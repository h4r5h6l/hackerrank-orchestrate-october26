# Identity Resolution Flowchart

This Mermaid flowchart describes how to deterministically resolve "who is this deletion request about" from a request email, using `dataset/user_identities.csv` (current snapshot) and `dataset/user_audit_log.csv` (historical changes).

```mermaid
flowchart TD
    %% Start
    A([Start]) --> B[Deletion request arrives<br/>with request.email]

    %% Normalization
    B --> C[Normalize email<br/>lowercase + trim whitespace]
    C --> D{Email is empty?}

    %% Empty check
    D -- Yes --> Z1([UNRESOLVED<br/>→ NOT_APPLICABLE<br/>steps_json = []])
    D -- No --> E

    %% Build indexes (done once at startup)
    E --> F[Pre-build indexes:<br/>email_to_user from current snapshot<br/>email_to_user from audit_log old/new values<br/>user_identifiers per user_id]

    %% Current email lookup
    F --> G{Email matches<br/>current user_identities.email?}
    G -- Yes --> H[Return user_id<br/>RESOLVED]

    %% Historical email lookup
    G -- No --> I{Email matches<br/>audit_log.old_value or<br/>audit_log.new_value for<br/>some user_id?}
    I -- Yes --> J[Return that user_id<br/>RESOLVED]

    %% No match anywhere
    I -- No --> Z2([UNRESOLVED<br/>→ NOT_APPLICABLE<br/>steps_json = []])

    %% Resolved path continues to deletion audit
    H --> K[Proceed to deletion audit:<br/>reconstruct identifiers set<br/>from user_identifiers[user_id]<br/>(current + historical emails,<br/>phones, hashes)]
    J --> K
    K --> L[End: user_id resolved<br/>for evidence matching]

    %% Styling
    classDef resolved fill:#e1f7e1,stroke:#2e7d32,stroke-width:2px;
    classDef unresolved fill:#ffe1e1,stroke:#c62828,stroke-width:2px;
    classDef process fill:#e3f2fd,stroke:#1565c0,stroke-width:2px;
    classDef decision fill:#fff9e1,stroke:#f9a825,stroke-width:2px;

    class H,J resolved;
    class Z1,Z2 unresolved;
    class C,F,G,I decision;
    class B,E,K,L process;
```

## How to Read the Flowchart

| Node | Meaning |
|------|---------|
| **B** | The deletion request arrives with an `email` field (may be current or historical). |
| **C** | Normalize: lowercase + trim. This ensures case-insensitive, whitespace-tolerant matching. |
| **D** | Empty email → cannot resolve → `NOT_APPLICABLE`. |
| **F** | **One-time index build**: scan all 850 current identities + 306 audit rows to build `email → user_id` mappings covering both current and historical addresses. |
| **G** | Direct hit: request email equals a current user's email. Return that `user_id`. |
| **I** | Historical hit: request email appears as an `old_value` or `new_value` in `user_audit_log` for some `user_id`. Return that `user_id`. |
| **Z1 / Z2** | No match found in current or historical data → the person is not in the system → `NOT_APPLICABLE` with `steps_json = []`. |
| **K** | Resolved: expand the full identifier set (current + historical emails, phones, hashes) for evidence matching across all data sources. |

## Determinism Guarantees

- **No randomness**: Every step is a deterministic lookup.
- **No ties**: Emails are unique in `user_identities` (0 duplicates) and every audit `user_id` exists in `user_identities` (0 orphans), so each email maps to at most one `user_id`.
- **Same input → same output**: Running the flowchart twice on the same request always yields the same `user_id` or `UNRESOLVED`.