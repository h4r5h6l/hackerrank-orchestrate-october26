# Identity Resolution Flowcharts (Mermaid)

Two diagrams, both derived from the implemented code (`code/identity.py`, wired in by
`code/main.py`):

1. **Pipeline view** - where identity resolution sits in the 518-case run, and what is
   still missing.
2. **Resolver view** - the actual control flow of `IdentityResolver` for one request.

Inputs are only `dataset/deletion_requests.csv`, `dataset/user_identities.csv` and
`dataset/user_audit_log.csv`.

---

## 1. Pipeline view

```mermaid
flowchart TD
    A["dataset/deletion_requests.csv<br/>518 requests<br/>case_id, email, requested_at,<br/>reported_status, reported_at, audit_at, request_text"]

    A --> B["Stage 1 - classify request_text<br/>code/main.py: classify_case()"]
    B --> C{"Text authorises<br/>deletion?"}
    C -->|"no<br/>access / correction / export /<br/>opt-out / other scope"| D(["NOT_APPLICABLE<br/>steps_json = []"])
    C -->|"yes"| E["Stage 2 - identity resolution<br/>code/identity.py: IdentityResolver"]

    E --> F{"Outcome"}
    F -->|"RESOLVED"| G["person_id<br/>+ every alias version<br/>with t_from &le; audit_at"]
    F -->|"UNRESOLVED / AMBIGUOUS"| H(["no subject<br/>cannot audit evidence"])

    G --> I["Stage 3 - evidence and activity join<br/>record_matches: person_id, emails,<br/>phones, email_hashes -> records at audit_at"]
    I --> J["Stage 4 - apply deletion_rules.csv<br/>DELETE / REDACT / ANONYMIZE /<br/>RETAIN / ACCOUNT_TOMBSTONE"]
    J --> K["Stage 5 - emit findings, remediation,<br/>verification as steps_json"]
    K --> L["output.csv<br/>case_id, deletion_status, steps_json"]

    D --> L
    H --> L

    classDef done fill:#e1f7e1,stroke:#2e7d32,stroke-width:2px;
    classDef current fill:#e3f2fd,stroke:#1565c0,stroke-width:3px;
    classDef planned fill:#f5f5f5,stroke:#9e9e9e,stroke-width:1px,stroke-dasharray: 5 5;
    classDef terminal fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;

    class B,D done;
    class E,G current;
    class I,J,K planned;
    class L terminal;
```

Stage status: stage 1 and identity resolution are implemented and tested; stages 3-5
are next. `output.csv` currently carries the stage-1 verdicts plus a provisional
`INCOMPLETE` for every authorised request.

---

## 2. Resolver view

### 2a. Construction - once per run

```mermaid
flowchart TD
    subgraph BUILD["Index build (once per run)"]
        direction TB
        S1["user_identities.csv<br/>850 rows"]
        S2["user_audit_log.csv<br/>306 rows"]

        S2 --> O1["sort per (user_id, field_name)<br/>by (event_time, natural audit_id)"]
        O1 --> I2["index old_value and new_value<br/>for field_name = email"]
        S1 --> I1["index current email"]
        S1 --> I3["snapshot row per user_id"]

        I1 --> M["email (normalized)<br/>to set of user_id"]
        I2 --> M
        M -.-> MC["owner collision is never merged:<br/>tie-break at requested_at,<br/>otherwise AMBIGUOUS"]

        I3 --> V["per user, per field:<br/>Version list<br/>[t_from, t_to), source"]
        O1 --> V
        V --> CHK["integrity gates<br/>hash = sha256(email)<br/>chain old = previous new<br/>snapshot = last new_value<br/>aliases distinct"]
        CHK --> Q{"violated?"}
        Q -->|"yes"| Q1["quarantine in failed_users<br/>other subjects unaffected"]
        Q -->|"no"| Q2["subject indexed<br/>total order, deterministic"]
    end
```

### 2b. Resolving one request

```mermaid
flowchart TD
    A(["request row<br/>case_id, email, requested_at, audit_at"])
    A --> B["normalize_email:<br/>NFKC, ASCII apostrophes,<br/>collapse whitespace, casefold"]
    B --> C{"empty?"}
    C -->|"yes"| U1(["UNRESOLVED<br/>'request has no email address'"])

    C -->|"no"| D["lookup owners in email index<br/>(snapshot + audit old/new)"]
    D --> E{"owners found"}

    E -->|"0"| U2(["UNRESOLVED<br/>appears in neither file"])
    E -->|"1"| F["resolved_by = snapshot<br/>if it equals the current email,<br/>otherwise history"]
    E -->|"more than 1"| T{"exactly one owner has a<br/>version of this email live at<br/>requested_at?"}

    T -->|"yes"| T1["resolved_by = tiebreak"]
    T -->|"no"| AMB(["AMBIGUOUS<br/>refuse to guess"])

    F --> H{"user in<br/>failed_users?"}
    T1 --> H
    H -->|"yes"| U3(["UNRESOLVED<br/>integrity failure"])

    H -->|"no"| I["subject = all Version records<br/>for email, phone, email_hash"]
    I --> J["alias_set at audit_at:<br/>keep versions with t_from &le; audit_at<br/>later versions excluded,<br/>superseded ones retained<br/>(old systems keep old identifiers)"]
    J --> R(["RESOLVED<br/>person_id + emails, phones,<br/>email_hashes"])
```

Key properties of the cutoff: `audit_at` bounds the alias set **from below only**
(`t_from <= audit_at`). A version created after `audit_at` is excluded because it did not
exist at decision time; a superseded version is never dropped, because the old address
may still sit in logs, exports, replicas or support attachments.

---

## 3. Why this is deterministic

- **No fuzzy matching, no name matching, no model call.** Three users share a display
  name in the dataset, so names are never a join key.
- **One value has one owner.** A colliding value is never silently merged: it either
  tie-breaks on validity at `requested_at` or returns `AMBIGUOUS`.
- **Total ordering.** `(event_time, audit_id)` gives the same version windows on every
  run, whatever order the CSV rows arrive in.
- **Integrity is checked, not assumed.** `email_hash == sha256(email)`, chain continuity
  and snapshot consistency are verified from the data at construction (all 850 subjects
  pass today); a failing subject is quarantined instead of corrupting an answer.
- **Explicit failure.** Resolution returns `UNRESOLVED` or `AMBIGUOUS` with a reason
  string rather than a low-confidence guess.

## 4. Reference run

| Metric | Value |
|---|---|
| Requests resolved | 518 / 518 |
| Distinct people | 517 (`case_33` and `case_52` share `user_18`) |
| Matched on current snapshot email | 418 |
| Matched only through history | 100 |
| Email versions recovered | 620 |
| Phone versions recovered | 607 |
| Alias contamination | 0 |
| Integrity failures | 0 |
| Versions lost at `audit_at` | 0 |
| Sample attribution vs naive baseline | 32/32 vs 29/32 (+9.4 pp) |
