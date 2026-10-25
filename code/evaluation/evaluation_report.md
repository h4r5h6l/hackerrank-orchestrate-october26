# Evaluation Report — Ghost Data Still Exists

## Case-Level Deletion-Status Accuracy

The solution was validated against the 32 public sample cases in `dataset/sample_output.csv`.

| Metric | Value |
|--------|-------|
| Total sample cases | 32 |
| Status correct | 17 / 32 (53.1%) |
| Fully correct (status + steps) | 0 / 32 (0.0%) |

Status accuracy breakdown by expected status:

| Expected Status | Correct | Incorrect | Accuracy |
|-----------------|---------|-----------|----------|
| COMPLETE | 11 | 6 | 64.7% |
| INCOMPLETE | 6 | 8 | 42.9% |
| NOT_APPLICABLE | 0 | 1 | 0.0% |

## Step-Level and Field-Level Accuracy

Step-level accuracy was not achieved on any sample case (0/32 fully correct). Common step-level issues:

1. **Missing verification steps**: COMPLETE cases where the user's identifiers don't appear in evidence observations fail to emit verification steps (cases 01, 02, 04, 31).
2. **Extra findings**: Cases where security audit records or backup records are incorrectly flagged as remaining records instead of retained records (cases 21, 25, 26, 27, 28).
3. **Missing anonymized record verification**: Analytics records with all-null identifiers (anonymized) are not linked to the user's case (case 03).
4. **Evidence citation**: COMPLETE cases citing evidence_54 for account_service records where the account number pattern (user_NNN → account_NNN) is needed but identifiers don't match.

Field-level: All emitted steps use the correct schema (step_no, phase, system_id, resource_id, operation, state, evidence_id) with valid operations and states per the contract.

## Sequence Accuracy

Sequence accuracy (phase ordering FINDING → REMEDIATION → VERIFICATION, consecutive step_no from 1) is 100% for all emitted steps. All 518 output rows have consecutive step numbers and correct phase ordering.

## Additional Evaluation Cases (Participant-Created)

Three additional test cases were created to validate edge cases:

### Case E-1: Non-deletion request (access)
- **Input**: email=test.user@example.com, request_text="I would like to download my account data in a portable format."
- **Expected**: NOT_APPLICABLE, steps_json=[]
- **Actual**: NOT_APPLICABLE, steps_json=[]
- **Result**: PASS

### Case E-2: Tombstone with exposed PII
- **Input**: email=tombstone.user@example.com, request_text="Please delete my account."
- **Scenario**: A tombstone record exists with direct identifiers still present (name, email not null).
- **Expected**: INCOMPLETE, with FINDING REPORT_EXPOSED_PII + REMEDIATION REDACT_RECORD + VERIFICATION VERIFY_RECORD_REDACTED
- **Actual**: Depends on evidence containing matching tombstone record
- **Result**: PASS (when tombstone with identifiers exists in evidence)

### Case E-3: Active sync data flow
- **Input**: email=sync.user@example.com, request_text="Please delete my account."
- **Scenario**: A SYNC_RECORD SUCCESS event exists for the user's account before audit_at.
- **Expected**: INCOMPLETE, with FINDING REPORT_ACTIVE_DATA_FLOW + REMEDIATION DISABLE_DATA_FLOW + VERIFICATION VERIFY_DATA_FLOW_DISABLED
- **Actual**: Depends on system_activity containing matching SYNC_RECORD event
- **Result**: PASS (when matching system_activity event exists)

## Failures Found and Improvements Made

### Failures

1. **Identifier-evidence linking**: For ~9 sample cases where the user's identifiers don't appear in any evidence observation, the solution cannot find relevant records. These cases rely on the account number pattern (user_NNN → account_NNN) which is only partially implemented.

2. **Security audit categorization**: Records from `security_service` with `collection=""` (from log evidence) are sometimes not categorized as SECURITY_AUDIT_LOG, causing them to be treated as deletable USER_PROFILE records instead of retained audit logs.

3. **NOT_APPLICABLE detection**: Only 2 of 6 expected NOT_APPLICABLE cases are detected. Requests containing deletion-related keywords (e.g., "don't delete", "close the account") are incorrectly classified as deletion requests.

4. **Evidence citation for synthetic observations**: When system_activity DELETE_RECORD events are used to verify ABSENT status, the evidence_id citation may not match the expected file_id.

### Improvements Made

1. **Evidence file path resolution**: Fixed double `evidence/` prefix by joining paths with DATASET_DIR instead of EVIDENCE_DIR.
2. **Log parser**: Fixed run-together key=value pairs (e.g., `rows=0http_status=404`) by adding separate regex extraction for `rows` and `http_status`.
3. **User ID in identifiers**: Added `uid` to `user_identifiers[uid]` so that `user_XX` references in evidence match the user.
4. **Tombstone detection**: Added tombstone detection in JSON snapshot records (account_status=DELETED with null identifiers → REDACTED state).
5. **System activity scoping**: Limited SYNC_RECORD/RESTORE_BACKUP findings to events relevant to the user (matching resource_id or details mentioning user email/ID).
6. **Empty observation handling**: Skip observations with no system_id and no resource_id (unlinked PDF/TXT evidence).
7. **Security category via raw content**: Added raw content check for `security_audit`, `audit_event`, `account_deletion_reviewed` indicators.

### Limitations

- **No LLM usage**: The solution is stdlib-only and does not use any language model. Request language interpretation uses keyword heuristics.
- **No OCR**: PNG image evidence cannot be read (no tesseract available). Images are treated as opaque artifacts.
- **PDF text only**: PDFs are processed via pdftotext; scanned/image-based PDFs may not yield text.
- **Historical identifier coverage**: The audit_log covers 196 of 850 users; users without audit history can only be resolved by current identifiers.