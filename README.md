# HackerRank Orchestrate - October 2026

## Ghost Data Still Exists

Build an AI agent that audits whether a user's personal data was actually deleted.

A deletion workflow may report **Complete** while data still exists in databases, logs, support attachments, exports, search indexes, archives, or backups. Sync and restore processes may also bring deleted data back.

For each request, the agent must first determine whether deletion was actually requested. It then returns `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`, reports any remaining data or recreation risk, and produces the ordered remediation and verification steps required to finish an authorized deletion safely.

Read [`problem_statement.md`](./problem_statement.md) for the complete challenge contract.

---

## Quick Start

Clone the repository and move into the project directory:

```bash
git clone https://github.com/interviewstreet/hackerrank-orchestrate-october26.git
cd hackerrank-orchestrate-october26
```

Start your AI coding tool from the **repository root** so it automatically reads [`AGENTS.md`](./AGENTS.md) and logs your session turns to `log.txt` in the root directory.

Build your solution in `code/main.py`, or use another language and document its setup and run command clearly in your README.

Your solution must:

- Read the input files from `dataset/`
- Generate one prediction row for every request in `dataset/deletion_requests.csv`
- Write the final predictions to `output.csv` in the repository root

Run the starter Python entry point with:

```bash
python3 code/main.py
```

The blank template at `dataset/output.csv` is provided as a reference. Your final generated file for submission must be the root-level `output.csv`.

---

## Solution

The agent is a deterministic, offline pipeline in `code/`. No model calls, no
network: every row is derived from `dataset/` by rule, so repeated runs produce
byte-identical output.

```bash
python3 code/main.py                      # write output.csv (518 rows)
python3 code/main.py --dump-findings      # + discovered_findings.csv
python3 code/main.py --dump-identities    # + resolved_identities.csv
python3 code/main.py --verbose            # per-case findings
python3 -m unittest discover -s code -v   # 85 tests
```

| Stage | Module | Question it answers |
| --- | --- | --- |
| 0 wiring | `main.py` | contract-shaped output, dataset loading |
| 1 classify | `main.py` | does `request_text` actually authorise deletion? |
| 2 identify | `identity.py` | which person is this, with which historical emails/phones? |
| 3 discovery | `evidence.py`, `discovery.py` | what still exists at `audit_at`, and is that a policy violation? |
| 4 remedy | *(next)* | ordered remediation plus the verification that must follow |

Design rules that shape every row:

- **Evidence is the only proof.** `system_activity.csv` and `reported_status` are
  claims; a workflow row saying `DELETE_RECORD / SUCCESS` never removes a
  finding, and `CHECK_DATA_FLOW / SUCCESS` never creates one. Activity rows are
  used only to explain what was attempted.
- **The manifest capture time is the gate.** A file captured after a case's
  `audit_at` did not exist at decision time and is never read for that case, so
  a later snapshot cannot rewrite history.
- **Identifiers are exact, never fuzzy.** Current and historical emails/phones
  come from `user_identities.csv` plus `user_audit_log.csv`, bounded by
  `audit_at`. Names are never used to join: the corpus contains duplicate
  display names and near-miss addresses such as `g.silva76.jr@` next to
  `g.silva76@`.
- **Latest state wins per record.** For one `(system_id, resource_id)` the
  newest observation at or before `audit_at` decides, so a later `NOT_FOUND`
  clears an earlier `FOUND` and a later `PRESENT` reopens a record a writer
  recreated.
- **Policy decides, not intuition.** `deletion_rules.csv` maps a category to
  `DELETE` (the record must be gone → `REPORT_REMAINING_RECORD`), `REDACT` /
  `ANONYMIZE` (the record may stay but must not be attributable →
  `REPORT_EXPOSED_PII`), or `RETAIN` (the record must stay; only a restorable
  backup or an enabled connector is a finding).
- **Status follows findings.** `INCOMPLETE` iff at least one violation survives
  at `audit_at`, else `COMPLETE`; `NOT_APPLICABLE` iff the text does not
  authorise deletion.

Parsed formats: SQLite-compatible `.sql` snapshots (primary / read / regional /
reporting / failover replicas, including `record_json.document` payloads), JSON
snapshot bundles and per-service exports (`hits.documents[]`, `profile`),
`|`-separated ledgers, six different log layouts, and PDFs via `pdftotext`.

Current limitations, stated rather than hidden:

- 11 evidence files are PNG screenshots. There is no OCR in this environment, so
  they are reported as unreadable instead of being guessed at. Where a case has
  no timely textual evidence at all - 9 of 518 cases today - the audit finds no
  violation and therefore reports `COMPLETE` without proof; transcribing those
  screenshots is the next accuracy win.
- Steps are FINDING steps only. Stage 4 adds `REMEDIATION` and post-remediation
  `VERIFICATION`, so `COMPLETE` rows currently carry `steps_json = []`.

---

## Dataset

All participant-facing files are in `dataset/`:

| File | Contents |
| --- | --- |
| `deletion_requests.csv` | 518 requests |
| `sample_deletion_requests.csv` | 32 sample requests |
| `sample_output.csv` | Correct sample answers |
| `user_identities.csv` | Current user identities |
| `user_audit_log.csv` | Historical identity changes |
| `system_activity.csv` | Activity across services and data processes |
| `deletion_rules.csv` | Required treatment for each data category |
| `evidence_files.csv` | Manifest of supplied evidence files |
| `output.csv` | Blank output template |

Evidence is stored under `dataset/evidence/` and may include PDFs, images, logs, JSON, plain text, or SQL snapshot exports. SQL captures may contain a primary database, regional replicas, a reporting replica, or a failover replica so replication drift can be investigated directly. The `.sql` files are readable as text and executable with SQLite.

Only `deletion_requests.csv` requires answers. The other files provide evidence and context.

---

## Output

Create `output.csv` with these columns in this exact order:

```text
case_id,deletion_status,steps_json
```

Produce exactly one row per request. `deletion_status` is `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. `steps_json` is an ordered JSON array containing findings, remediation actions, and verification checks. Use an empty array (`[]`) for `NOT_APPLICABLE`. Evidence references may be a `file_id`, `activity_id`, or `audit_id`. Determine the resource state at `audit_at` from the available evidence; reported workflow statuses and operation results are claims. Use `dataset/sample_output.csv` as the format reference.

The final file must contain 518 data rows sorted by `case_id` (plus the header row). The grader parses `steps_json` as JSON, so object-key order and whitespace do not matter; array order does. Order findings, remediation, and verification in that phase order. Within a phase, follow the operation order in the problem statement, then sort by `system_id` and `resource_id`.

---

## Evaluation

`output.csv` will be compared with hidden canonical answers. Scoring considers:

- deletion assessment accuracy;
- current and historical identity resolution;
- discovery of remaining data and recreation risks;
- correct policy application and evidence references; and
- completeness and ordering of remediation and verification steps.

Your `code.zip` must include:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

- `evaluation_report.md` must cover case, row, field, and sequence accuracy, at least three additional evaluation cases created by you, failures found, and improvements made.
- `usage_report.md` must cover the final full-dataset run, including model providers and names, model calls, input and output tokens, total and average tokens per request, and estimated total and per-request cost. Include per-model and overall totals when using multiple models.

**Important:** Place `evaluation_report.md` and `usage_report.md` inside `code/evaluation/` (matching `code/evaluation/main.py` in this starter layout), write your complete evaluation metrics, custom evaluation test cases, and token/cost breakdowns directly inside those Markdown files, and keep prompts in source code or Markdown files. Automated code evaluation ignores raw data files (`.csv`, `.tsv`, `.json`, `.jsonl`, `.sql`, `.log`), so content stored only in those formats will not be visible to the code judge or AI interviewer.

---

## Chat Transcript

This repository includes [`AGENTS.md`](./AGENTS.md), which instructs compatible AI coding tools to append conversation summaries to `log.txt` in the repository root:

| Platform | Path |
| --- | --- |
| macOS / Linux | `<repo root>/log.txt` |
| Windows | `<repo root>\log.txt` |

- Always launch your AI coding agent from the repository root (or explicitly ask it to read `./AGENTS.md` first) so every turn is logged to `log.txt` with the required `User Prompt`, `Agent Response Summary`, `Actions`, and `Context` sections.
- Upload `log.txt` directly as your `chat_transcript` submission on HackerRank.
- Do not include API keys, tokens, credentials, or secrets in prompts, code, configuration, or `log.txt`.

---

## Packaging `code.zip` and Submission

| Item | Description |
| --- | --- |
| `code.zip` | Runnable solution, prompts, configuration, `README.md`, and `evaluation/` reports |
| `output.csv` | One answer row for each of the 518 requests in `dataset/deletion_requests.csv` |
| `chat_transcript` | The root `log.txt` file generated by your coding agent |
| AI interview | Live explanation of your architecture, approach, and evaluation |

You may use any programming language, model, framework, or retrieval approach. Include clear setup and execution instructions in `README.md` inside `code.zip`.

To package `code.zip` from the repository root without bundling the dataset:

**macOS / Linux:**

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.venv/*" "*/venv/*" "*/node_modules/*" "*/.git/*" "*/.DS_Store"
```

**Windows (PowerShell):**

```powershell
Compress-Archive -Path README.md, code -DestinationPath code.zip -Force
```

When packaging `code.zip`:

- Keep your evaluation reports in `code/evaluation/` so they are bundled automatically with `code` (or add `evaluation` to the archive command above if you placed them in a top-level `evaluation/` directory).
- Do **not** include `dataset/`, virtual environments (`.venv`, `venv`, `node_modules`), or build caches (`__pycache__`). On Windows, keep `.venv` at the repository root (outside `code/`) and remove any `code/__pycache__` folders before running `Compress-Archive`.
- Do **not** include nested archives (`.zip`, `.tar`, `.gz`, `.tgz`, `.7z`, `.rar`) inside `code.zip` — submissions containing nested archive files will be rejected.

Before submitting, confirm that:

- `output.csv` has the exact header `case_id,deletion_status,steps_json` and contains all 518 data rows sorted by `case_id`;
- every `steps_json` value is a valid JSON array with consecutive step numbers starting at `1`;
- findings cite valid evidence IDs, and `COMPLETE` verification steps cite evidence proving the current state;
- proposed remediation and future verification steps use an empty `evidence_id` (`""`);
- `code.zip` includes your runnable code, `README.md`, `code/evaluation/evaluation_report.md`, and `code/evaluation/usage_report.md`;
- `log.txt` follows the `AGENTS.md` turn format and is uploaded to the `chat_transcript` slot; and
- no API keys, credentials, real personal data, or sensitive configuration values are included.
