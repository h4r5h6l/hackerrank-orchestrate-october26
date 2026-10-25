#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent (stage 1).

Pipeline stages:

  0. wiring    - CLI, dataset loading, contract-shaped output      [done]
  1. classify  - does request_text actually authorise deletion?    [this file]
  2. identify  - resolve current + historical identifiers, rebuild
                 the record state at ``audit_at`` from evidence    [TODO]
  3. policy    - apply deletion_rules.csv, emit FINDING /
                 REMEDIATION / VERIFICATION steps                  [TODO]

Stage 1 decision (AGENTS.md section 6.5, first bullet): a request that asks
for access, correction, portability, marketing opt-out, a login reset, a
profile update, or that explicitly refuses deletion is ``NOT_APPLICABLE`` and
carries ``steps_json = []``. Everything else authorises deletion and keeps
being audited in stage 2.

Interim output status: stage 1 can prove that a request authorises deletion
but not whether the required state holds, so those cases are written as
``INCOMPLETE`` with ``steps_json = []``. That is a *provisional* stand-in, not
a finding - stage 3 replaces it. Only ``NOT_APPLICABLE`` rows are final here.

Usage:
    python3 code/main.py
    python3 code/main.py --verbose
    python3 code/main.py --out /tmp/check.csv --limit 5
    python3 code/main.py --dataset-dir /path/to/dataset --dry-run

Exit codes:
    0   output written (or validated, with --dry-run)
    1   dataset or argument problem
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Sequence

CODE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CODE_DIR)
DEFAULT_DATASET_DIR = os.path.join(REPO_ROOT, "dataset")
DEFAULT_OUTPUT_PATH = os.path.join(REPO_ROOT, "output.csv")

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
STATUS_ORDER = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")

# Stage 1 cannot distinguish COMPLETE from INCOMPLETE, so every request that
# authorises deletion is written with this provisional status (see docstring).
PROVISIONAL_STATUS = "INCOMPLETE"
NOT_APPLICABLE_STEPS = "[]"

REQUEST_COLUMNS = ["case_id", "email", "requested_at", "reported_status",
                   "reported_at", "audit_at", "request_text"]

# Participant-facing files required before any work can start. Names are the
# documented ones; missing files are a hard error so a half-empty run cannot
# silently produce 518 wrong-looking rows.
REQUIRED_FILES = (
    "deletion_requests.csv",
    "user_identities.csv",
    "user_audit_log.csv",
    "system_activity.csv",
    "deletion_rules.csv",
    "evidence_files.csv",
)

# Loaded but not required for stage 0; the submission also ships a blank
# output template and the public sample pair.
OPTIONAL_FILES = (
    "sample_deletion_requests.csv",
    "sample_output.csv",
    "output.csv",
)


# --------------------------------------------------------------------------
# Dataset loading
# --------------------------------------------------------------------------

@dataclass
class Dataset:
    """Everything under dataset/ that the later stages will read."""

    dataset_dir: str
    deletion_requests: list[dict] = field(default_factory=list)
    user_identities: list[dict] = field(default_factory=list)
    user_audit_log: list[dict] = field(default_factory=list)
    system_activity: list[dict] = field(default_factory=list)
    deletion_rules: list[dict] = field(default_factory=list)
    evidence_files: list[dict] = field(default_factory=list)
    sample_deletion_requests: list[dict] = field(default_factory=list)
    sample_output: list[dict] = field(default_factory=list)
    evidence_dir: str = ""

    def counts(self) -> dict[str, int]:
        return {
            "deletion_requests": len(self.deletion_requests),
            "user_identities": len(self.user_identities),
            "user_audit_log": len(self.user_audit_log),
            "system_activity": len(self.system_activity),
            "deletion_rules": len(self.deletion_rules),
            "evidence_files": len(self.evidence_files),
            "sample_deletion_requests": len(self.sample_deletion_requests),
            "sample_output": len(self.sample_output),
        }


def load_csv(dataset_dir: str, name: str) -> list[dict]:
    """Read one CSV from dataset/ as a list of dict rows (utf-8, header row)."""
    path = os.path.join(dataset_dir, name)
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def load_dataset(dataset_dir: str, verbose: bool = False) -> Dataset:
    """Load every participant-facing file. Raises FileNotFoundError if required
    files are absent."""
    dataset_dir = os.path.abspath(dataset_dir)
    if not os.path.isdir(dataset_dir):
        raise FileNotFoundError(f"dataset directory not found: {dataset_dir}")

    absent = [n for n in REQUIRED_FILES
              if not os.path.isfile(os.path.join(dataset_dir, n))]
    if absent:
        raise FileNotFoundError(
            "missing required dataset file(s): " + ", ".join(absent))

    data = Dataset(dataset_dir=dataset_dir)
    data.deletion_requests = load_csv(dataset_dir, "deletion_requests.csv")
    data.user_identities = load_csv(dataset_dir, "user_identities.csv")
    data.user_audit_log = load_csv(dataset_dir, "user_audit_log.csv")
    data.system_activity = load_csv(dataset_dir, "system_activity.csv")
    data.deletion_rules = load_csv(dataset_dir, "deletion_rules.csv")
    data.evidence_files = load_csv(dataset_dir, "evidence_files.csv")

    for optional, attr in (
        ("sample_deletion_requests.csv", "sample_deletion_requests"),
        ("sample_output.csv", "sample_output"),
    ):
        if os.path.isfile(os.path.join(dataset_dir, optional)):
            setattr(data, attr, load_csv(dataset_dir, optional))

    data.evidence_dir = os.path.join(dataset_dir, "evidence")
    if verbose:
        for name, count in data.counts().items():
            print(f"  loaded {name:<26} {count:>5} rows")
    return data


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def validate_requests(requests: Sequence[dict]) -> None:
    """Fail fast on malformed request rows (skeleton-level checks only)."""
    if not requests:
        raise ValueError("deletion_requests.csv has no data rows")

    header = list(requests[0].keys())
    missing = [c for c in REQUEST_COLUMNS if c not in header]
    if missing:
        raise ValueError("deletion_requests.csv missing column(s): "
                         + ", ".join(missing))

    seen: dict[str, int] = {}
    for row in requests:
        case_id = (row.get("case_id") or "").strip()
        if not case_id:
            raise ValueError("deletion_requests.csv contains a row without case_id")
        seen[case_id] = seen.get(case_id, 0) + 1
    duplicates = sorted(k for k, v in seen.items() if v > 1)
    if duplicates:
        raise ValueError("duplicate case_id(s): " + ", ".join(duplicates[:5]))


def case_sort_key(case_id: str) -> tuple:
    """Natural order for case ids: case_9 < case_10 < case_550.

    Lexicographic order would put case_100 before case_33, so the numeric
    suffix is compared first and the raw string is kept as a tiebreaker.
    """
    _, _, suffix = case_id.partition("_")
    try:
        return (0, int(suffix), case_id)
    except ValueError:
        return (1, 0, case_id)


# --------------------------------------------------------------------------
# Stage 1: request classification - does the text authorise deletion?
# --------------------------------------------------------------------------
#
# Deterministic, evidence-free cue matching, consulted in this order:
#
#   REFUSAL   explicit refusal, exclusive scope, or a "keep it as it is" ask.
#             Decisive: a request that says "do not delete" cannot be read as
#             authorising deletion no matter how many deletion words it quotes.
#   DELETION  deletion vocabulary in any of the languages present in the
#             corpus (en/es/pt/fr/de/it/nl/pl/ja/ko/zh).
#   FOLLOWUP  chasing a deletion already requested ("confirm the profile is
#             gone"), which carries no deletion verb of its own.
#   OTHER     another data-subject right (access, portability, rectification,
#             login help, marketing opt-out). Only decisive when the text
#             contains no deletion vocabulary - "delete my account and fix my
#             name" is still a deletion request.
#
# Anything left over is UNCLASSIFIED and is surfaced loudly instead of being
# silently guessed.

INTENT_DELETION = "DELETION"
INTENT_NON_DELETION = "NON_DELETION"
INTENT_UNCLASSIFIED = "UNCLASSIFIED"
INTENT_ORDER = (INTENT_DELETION, INTENT_NON_DELETION, INTENT_UNCLASSIFIED)

_WHITESPACE = re.compile(r"\s+")
# NFKC leaves typographic apostrophes alone; fold them so "don’t" matches.
_APOSTROPHES = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'",
                              "\u00b4": "'"})


def normalize_text(text: str) -> str:
    """NFKC, casefold, ASCII apostrophes, collapsed whitespace."""
    folded = unicodedata.normalize("NFKC", text or "").translate(_APOSTROPHES)
    return _WHITESPACE.sub(" ", folded.casefold()).strip()


def _cue_table(pairs: Sequence[tuple[str, str]]) -> tuple[tuple[str, re.Pattern], ...]:
    return tuple((name, re.compile(pattern, re.UNICODE)) for name, pattern in pairs)


# (1) Decisive refusals: the text says the account survives, or narrows the ask
#     to something that is not deletion.
_REFUSAL_CUES = _cue_table([
    ("not_asking_for_deletion",
     r"\bnot (asking|requesting|seeking) (for |about )?(a )?(permanent )?"
     r"(deletion|erasure|removal|deleting)\b"),
    ("not_a_deletion_request",
     r"\bnot (a|an) (request|ask) (to|for) (erase|erasing|delete|deleting|remove|removing)\b"),
    ("information_request_only",
     r"\b(this|it) is an information request\b"),
    ("do_not_close_delete",
     r"\b(do not|don't|please don't) (close|delete|remove|erase|purge|wipe)\b"),
    ("without_removing_records",
     r"\bwithout (removing|deleting|erasing|dropping)\b"),
    ("leave_in_place",
     r"\bleave (my|the) (account|profile|order history|purchase history|records?|data)"
     r"(?: [a-z]+){0,6}? (in place|as (it|they) (is|are)|active|intact|untouched)\b"),
    ("keep_account_as_is",
     r"\bkeep (my|the) (account|profile)(?: [a-z]+){0,6}?"
     r" (in place|as (it|they) (is|are)|active|intact|untouched)\b"),
    ("keep_account", r"\bkeep (my|the) account\b"),
    ("still_need_the_account", r"\bstill (need|use|want) (the|this|my) account\b"),
    ("still_use_it", r"\bstill use (it|this)\b"),
    ("continue_using_service",
     r"\bcontinue (using|to use) (the|this) (service|account|site)\b"),
    ("marketing_scope_only", r"\b(marketing|promotional)\b[^.]{0,40}\bonly\b"),
    ("unsubscribe_only", r"\b(unsubscribe|opt (me )?out)\b"),
    # Refusals in the corpus languages other than English.
    ("es_no_solicito_eliminacion",
     r"\bno (solicito|pido|quiero) (la )?(eliminaci[oó]n|borrado|supresi[oó]n)\b"),
    ("pt_nao_solicito_exclusao",
     r"\bn[aã]o (solicito|pe[cç]o|quero) (a )?(exclus[aã]o|elimina[cç][aã]o)\b"),
    ("fr_pas_de_suppression",
     r"\bje ne (demande|souhaite) pas (la )?(suppression|effacement)\b"),
    ("de_keine_loeschung",
     r"\b(ich )?(beantrage|m[oö]chte) keine (l[oö]schung|entfernung)\b"),
])

# (2) Deletion vocabulary. Prefix-matched because these are inflected languages.
_DELETION_CUES = _cue_table([
    ("en_delete", r"\bdelet(?:e|ed|es|ing|ion|ions)\b"),
    ("en_erase", r"\beras(?:e|ed|es|ing|ure|ures)\b"),
    ("en_remove", r"\bremov(?:e|ed|es|ing|al|als)\b"),
    ("en_close", r"\bclos(?:e|ed|es|ing)\b"),
    ("en_purge", r"\b(?:purge|purged|purging|wipe|wiped|wiping)\b"),
    ("es_eliminar", r"\belimin\w*\b"),
    ("es_borrar", r"\bborr\w*\b"),
    ("es_suprimir", r"\bsuprim\w*\b|\bsupresi\w*\b"),
    ("pt_excluir", r"\bexclu\w*\b"),
    ("pt_apagar", r"\bapag\w*\b"),
    ("fr_supprimer", r"\bsupp(?:rim|ress)\w*\b"),
    ("fr_effacer", r"\beffac\w*\b"),
    ("de_loeschen", r"\bl[oö]sch\w*\b"),
    ("it_cancellare", r"\bcancell\w*\b"),
    ("nl_verwijderen", r"\bverwijder\w*\b"),
    ("pl_usunac", r"\busu(?:n|ń|nięc|nięcie|wanie)\w*\b"),
    ("ja_sakujo", r"削除"),
    ("ko_sakje", r"삭제"),
    ("zh_shanchu", r"删除|刪除"),
])

# (3) Deletion follow-ups: the customer is chasing a deletion already asked
#     for ("confirm the profile is gone"), so no deletion verb appears. Only
#     consulted after the refusal and deletion tiers miss.
_FOLLOWUP_CUES = _cue_table([
    ("confirm_target_state",
     r"\bconfirm (that |whether )?(the |my )?(profile|account|records?|data|copy|copies)"
     r"(?: [a-z]+){0,4}? (is|are|was|were) (gone|deleted|removed|erased|absent)\b"),
    ("account_gone_claim",
     r"\b(profile|account) (is|was) (gone|deleted|removed|erased)\b"),
    ("finish_deletion",
     r"\bfinish (the |my )?(deletion|erasure|removal)\b"
     r"|\bcomplete (the |my )?(deletion|erasure)\b"),
    ("deletion_audit_request", r"\baudit (the |my )?(deletion|erasure)\b"),
    ("residue_still_visible",
     r"\b(profile|account|records?|data)[^.]{0,20}\b(still|no longer) "
     r"(exists?|appears?|recognized|recognised|found|visible)\b"),
    ("intake_failure_report",
     r"\brequest (failed|was rejected|was denied|did not go through)\b"),
])

# (4) Other data-subject rights: they presuppose that the account survives.
_OTHER_RIGHT_CUES = _cue_table([
    ("data_access_request",
     r"\b(what|which) (personal )?(information|data)\b[^.]{0,40}"
     r"\b(hold|holds|have|has|store|stores|process|processes)\b"
     r"|\baccess (my|the) (personal )?(data|information)\b|\bsubject access\b"),
    ("data_portability",
     r"\bportable format\b|\bdownload (my|a copy of my)\b|\bexport (my|a copy)\b"
     r"|\bcopy of (the|my) (information|data|invoices?|records?)\b|\bsend me a copy\b"),
    ("record_correction",
     r"\bcorrect (it|my|the)\b|\bmisspell\w*\b|\bwrong (name|surname|address|phone)\b|\btypo\b"),
    ("profile_update",
     r"\b(replace|update|change) (it|my|the) "
     r"(mobile|phone|number|name|surname|address|email)\b"
     r"|\bchange the email address\b|\bnew (phone|mobile|number)\b"),
    ("login_help",
     r"\breset(?:ting)? (?:the |my )?(?:login|password)\b"
     r"|\bcan't (?:log ?in|access my profile)\b|\bpassword reset\b"),
    ("marketing_optout",
     r"\bstop the (promotional|marketing|advertising) emails?\b"),
])


@dataclass(frozen=True)
class Classification:
    """Stage 1 verdict for one request, with the cue that produced it."""

    case_id: str
    intent: str
    tier: str
    cue: str
    excerpt: str

    @property
    def authorizes_deletion(self) -> bool:
        # UNCLASSIFIED deliberately falls through to "keep auditing": dropping
        # a real deletion request is the expensive mistake, so the unresolved
        # tail is reported instead of being answered NOT_APPLICABLE.
        return self.intent != INTENT_NON_DELETION

    @property
    def status(self) -> str:
        return "NOT_APPLICABLE" if not self.authorizes_deletion else PROVISIONAL_STATUS


def _first_match(cues: Sequence[tuple[str, re.Pattern]],
                 text: str) -> tuple[str, str]:
    for name, pattern in cues:
        match = pattern.search(text)
        if match:
            return name, match.group(0)
    return "", ""


def classify_request_text(case_id: str, text: str) -> Classification:
    """Classify one request. Order matters:
    refusal > deletion vocabulary > deletion follow-up > other right."""
    normalized = normalize_text(text)

    cue, excerpt = _first_match(_REFUSAL_CUES, normalized)
    if cue:
        return Classification(case_id, INTENT_NON_DELETION,
                              "explicit_refusal_or_scope", cue, excerpt)

    cue, excerpt = _first_match(_DELETION_CUES, normalized)
    if cue:
        return Classification(case_id, INTENT_DELETION, "deletion_signal",
                              cue, excerpt)

    cue, excerpt = _first_match(_FOLLOWUP_CUES, normalized)
    if cue:
        return Classification(case_id, INTENT_DELETION, "deletion_followup",
                              cue, excerpt)

    cue, excerpt = _first_match(_OTHER_RIGHT_CUES, normalized)
    if cue:
        return Classification(case_id, INTENT_NON_DELETION,
                              "other_right_without_deletion_signal", cue, excerpt)

    return Classification(case_id, INTENT_UNCLASSIFIED, "no_signal", "", "")


def classify_case(case: dict) -> Classification:
    return classify_request_text(case["case_id"], case.get("request_text", ""))


# --------------------------------------------------------------------------
# Row construction
# --------------------------------------------------------------------------

def row_from_classification(classification: Classification) -> dict:
    """Shape one output row from a stage 1 verdict.

    TODO(stage 2): resolve identifiers and rebuild the state at audit_at.
    TODO(stage 3): apply deletion_rules.csv, then emit FINDING / REMEDIATION /
    VERIFICATION steps using the 7-field step contract.
    """
    row = {
        "case_id": classification.case_id,
        "deletion_status": classification.status,
        "steps_json": NOT_APPLICABLE_STEPS,
    }
    assert set(row) == set(OUTPUT_COLUMNS), "output row drifted from contract"
    assert row["deletion_status"] in STATUS_ORDER, row["deletion_status"]
    if row["deletion_status"] == "NOT_APPLICABLE":
        assert json.loads(row["steps_json"]) == [], "NOT_APPLICABLE needs []"
    return row


def build_rows(requests: Iterable[dict]) -> list[dict]:
    return [row_from_classification(classify_case(case)) for case in requests]


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def render_histogram(counts: Counter, order: Sequence[str], width: int = 40,
                     indent: str = "  ") -> list[str]:
    """Fixed-width ASCII histogram; the bar is scaled to the largest bucket."""
    total = sum(counts.values())
    peak = max(counts.values(), default=0)
    lines = []
    for key in order:
        n = counts.get(key, 0)
        share = (n / total * 100) if total else 0.0
        bar = "#" * (round(n / peak * width) if peak else 0)
        lines.append(f"{indent}{key:<16}{n:>5}  {share:5.1f}%  {bar}")
    lines.append(f"{indent}{'total':<16}{total:>5}  100.0%")
    return lines


def evaluate_samples(data: "Dataset") -> dict:
    """Run stage 1 over the public samples and score it against sample_output.

    Two metrics, because they measure different things:

      classification  - did we agree that the text authorises deletion?
                        This is the only thing stage 1 can get right.
      status          - full deletion_status agreement. Stage 1 has no record
                        evidence, so COMPLETE cases can only be reached by
                        accident; the number is capped and reported as such.
    """
    truth = {r["case_id"]: r["deletion_status"] for r in data.sample_output}
    samples = [s for s in data.sample_deletion_requests if s["case_id"] in truth]
    if not samples:
        return {}

    classification_hits = 0
    status_hits = 0
    expected = Counter()
    predicted = Counter()
    mismatches: list[tuple[str, str, str, str, str]] = []

    for sample in samples:
        case_id = sample["case_id"]
        want = truth[case_id]
        classification = classify_case(sample)
        predicted_na = not classification.authorizes_deletion
        expected["NOT_APPLICABLE" if want == "NOT_APPLICABLE" else "DELETION"] += 1
        predicted["NOT_APPLICABLE" if predicted_na else "DELETION"] += 1

        if predicted_na == (want == "NOT_APPLICABLE"):
            classification_hits += 1
        else:
            mismatches.append((case_id, want, "NOT_APPLICABLE" if predicted_na
                               else PROVISIONAL_STATUS, classification.intent,
                               classification.cue))
        if classification.status == want:
            status_hits += 1

    return {
        "total": len(samples),
        "classification_hits": classification_hits,
        "status_hits": status_hits,
        "expected": expected,
        "predicted": predicted,
        "mismatches": mismatches,
    }


def resolve_evidence_path(data: "Dataset", file_path: str) -> str:
    """Manifest paths are dataset-relative; absolute paths are left alone."""
    return file_path if os.path.isabs(file_path) else os.path.join(data.dataset_dir, file_path)


def cross_check_intake(data: "Dataset") -> dict:
    """Corroborate stage 1 against privacy-intake CLASSIFY_REQUEST activities.

    This is an independent signal, not an input: the intake service recorded
    its own non-deletion verdict for exactly the accounts we refuse. Two
    caveats keep it in the reporting layer:

      * the email -> account mapping lives in a ledger export whose capture
        time is after ``audit_at`` for most of these cases,
      * AGENTS.md section 6.2 forbids deciding from data captured after
        ``audit_at``.

    So ``corroborated`` counts verdicts backed by a timely intake activity,
    while ``timely_link`` counts how many of those links were themselves
    available at audit time.
    """
    ledger_rows = [r for r in data.evidence_files
                   if "security_audit_ledger" in r.get("file_path", "")]
    intake = {a["resource_id"]: a for a in data.system_activity
              if a.get("event_type") == "CLASSIFY_REQUEST"}
    result = {"available": False, "checked": 0, "corroborated": 0,
              "timely_link": 0, "unmatched": [], "captured_at": ""}
    if not ledger_rows or not intake:
        return result

    entry = ledger_rows[0]
    with open(resolve_evidence_path(data, entry["file_path"]), encoding="utf-8") as handle:
        ledger = json.load(handle)
    email_to_account = {
        rec["subject_reference"].lower(): rec["resource_id"]
        for rec in ledger.get("records", [])
        if rec.get("record_type") == "USER_PROFILE" and rec.get("subject_reference")
    }
    captured_at = entry.get("captured_at") or ledger.get("exported_at", "")
    result["available"] = True
    result["captured_at"] = captured_at

    for case in data.deletion_requests:
        if classify_case(case).intent != INTENT_NON_DELETION:
            continue
        result["checked"] += 1
        account = email_to_account.get((case.get("email") or "").lower())
        activity = intake.get(account) if account else None
        agrees = bool(activity) and "non-deletion" in activity.get("details", "").lower()
        timely = bool(activity) and activity["event_time"] <= case["audit_at"]
        if agrees and timely:
            result["corroborated"] += 1
        else:
            result["unmatched"].append(case["case_id"])
        if captured_at and captured_at <= case["audit_at"]:
            result["timely_link"] += 1
    return result


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_output(path: str, rows: Sequence[dict]) -> None:
    """Write output.csv with the exact contract header and one row per case."""
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS,
                                lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def verify_output(path: str, expected_ids: Sequence[str]) -> dict[str, int]:
    """Re-read the written file and assert the submission contract."""
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    if len(rows) != len(expected_ids):
        raise AssertionError(
            f"{path}: expected {len(expected_ids)} data rows, found {len(rows)}")
    if [r["case_id"] for r in rows] != list(expected_ids):
        raise AssertionError(f"{path}: case_id order/set does not match requests")

    errors = 0
    for row in rows:
        if row["deletion_status"] not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            errors += 1
            continue
        try:
            steps = json.loads(row["steps_json"])
        except json.JSONDecodeError:
            errors += 1
            continue
        if not isinstance(steps, list):
            errors += 1
    if errors:
        raise AssertionError(f"{path}: {errors} row(s) violate the output contract")

    return {"rows": len(rows), "errors": errors}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Ghost Data Still Exists - deletion audit agent (stage 1: "
                    "request classification).",
    )
    parser.add_argument("--dataset-dir", default=os.environ.get("DATASET_DIR", DEFAULT_DATASET_DIR),
                        help="dataset directory (default: <repo>/dataset)")
    parser.add_argument("--out", "--output", dest="output", default=DEFAULT_OUTPUT_PATH,
                        help="output CSV path (default: <repo>/output.csv)")
    parser.add_argument("--limit", type=int, default=0,
                        help="process only the first N requests (0 = all)")
    parser.add_argument("--dry-run", action="store_true",
                        help="load, classify and report only; write nothing")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="print per-stage detail")
    parser.add_argument("--show-cues", action="store_true",
                        help="list every NOT_APPLICABLE case with its matched cue")
    parser.add_argument("--cross-check-intake", action="store_true",
                        help="corroborate NOT_APPLICABLE verdicts against "
                             "privacy-intake CLASSIFY_REQUEST activities")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        data = load_dataset(args.dataset_dir, verbose=args.verbose)
        validate_requests(data.deletion_requests)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    requests = data.deletion_requests
    if args.limit and args.limit > 0:
        requests = requests[:args.limit]

    classifications = [classify_case(case) for case in requests]
    rows = [row_from_classification(c) for c in classifications]
    rows.sort(key=lambda r: case_sort_key(r["case_id"]))
    expected_ids = [r["case_id"] for r in rows]

    intent_counts = Counter(c.intent for c in classifications)
    status_counts = Counter(r["deletion_status"] for r in rows)
    tier_counts = Counter(c.tier for c in classifications if c.intent == INTENT_NON_DELETION)

    print(f"classified {len(classifications)} requests "
          f"from {os.path.basename(args.dataset_dir)}/deletion_requests.csv")
    print()
    print("intent histogram (stage 1 decision)")
    for line in render_histogram(intent_counts, INTENT_ORDER):
        print(line)
    print()
    print("deletion_status histogram (written to output.csv)")
    for line in render_histogram(status_counts, STATUS_ORDER):
        print(line)
    if tier_counts:
        print()
        print("NOT_APPLICABLE evidence tiers")
        for tier, n in sorted(tier_counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {tier:<36}{n:>5}")

    unclassified = [c for c in classifications if c.intent == INTENT_UNCLASSIFIED]
    if unclassified:
        print()
        print(f"WARNING: {len(unclassified)} request(s) matched no cue at all "
              f"and were left in the audit pipeline:")
        for c in unclassified[:10]:
            print(f"  {c.case_id}")

    if args.show_cues:
        print()
        print("NOT_APPLICABLE cases and their matched cue")
        for c in classifications:
            if c.intent == INTENT_NON_DELETION:
                print(f"  {c.case_id:<10}{c.tier:<34}{c.cue:<32}{c.excerpt[:44]!r}")

    print()
    print("sample check (sample_deletion_requests.csv vs sample_output.csv)")
    sample = evaluate_samples(data)
    if not sample:
        print("  skipped: no overlapping sample rows")
    else:
        total = sample["total"]
        print(f"  cases                    {total:>5}")
        print(f"  request classification   {sample['classification_hits']:>5}/{total}"
              f"  {sample['classification_hits'] / total * 100:5.1f}%"
              f"   authorised-deletion vs NOT_APPLICABLE")
        print(f"  full deletion_status     {sample['status_hits']:>5}/{total}"
              f"  {sample['status_hits'] / total * 100:5.1f}%"
              f"   capped: stage 1 cannot reach COMPLETE")
        print(f"  expected                 {dict(sample['expected'])}")
        print(f"  predicted                {dict(sample['predicted'])}")
        if sample["mismatches"]:
            print(f"  classification misses    {len(sample['mismatches'])}")
            for case_id, want, got, intent, cue in sample["mismatches"][:10]:
                print(f"    {case_id:<10} expected {want:<16} got {got:<16} "
                      f"({intent}/{cue})")
        if sample["expected"].get("NOT_APPLICABLE", 0) == 0:
            print("  caveat                   the sample set has no NOT_APPLICABLE "
                  "row, so it cannot validate the non-deletion branch")

    if args.cross_check_intake:
        print()
        print("intake cross-check (system_activity CLASSIFY_REQUEST, not a decision input)")
        intakes = cross_check_intake(data)
        if not intakes["available"]:
            print("  unavailable: no CLASSIFY_REQUEST activity or ledger in the dataset")
        else:
            print(f"  NOT_APPLICABLE checked      {intakes['checked']:>5}")
            print(f"  corroborated               {intakes['corroborated']:>5}"
                  f"   timely intake activity says non-deletion")
            print(f"  link available at audit_at {intakes['timely_link']:>5}"
                  f"   of {intakes['checked']} (ledger capture {intakes['captured_at']})")
            if intakes["unmatched"]:
                print(f"  uncorroborated             {intakes['unmatched']}")

    if args.dry_run:
        print()
        print(f"dry run: {len(rows)} row(s) prepared, nothing written")
        return 0

    write_output(args.output, rows)
    stats = verify_output(args.output, expected_ids)

    print()
    print(f"wrote {stats['rows']} rows -> {args.output}")
    print(f"  NOT_APPLICABLE : {status_counts.get('NOT_APPLICABLE', 0)} (decided)")
    print(f"  INCOMPLETE     : {status_counts.get('INCOMPLETE', 0)} "
          f"(provisional - no record audit yet, steps_json empty)")
    if args.verbose:
        print(f"  dataset  : {data.dataset_dir}")
        print(f"  contract : {','.join(OUTPUT_COLUMNS)}")
        print(f"  evidence : {len(data.evidence_files)} manifest entries "
              f"(unused until stage 2)")
        print(f"  rules    : {len(data.deletion_rules)} policy rows "
              f"(unused until stage 3)")
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
