#!/usr/bin/env python3
"""Ghost Data Still Exists - deletion audit agent.

Pipeline stages:

  0. wiring    - CLI, dataset loading, contract-shaped output      [done]
  1. classify  - does request_text actually authorise deletion?    [done]
  2. identify  - resolve current + historical identifiers, bounded
                 by audit_at                                         [done]
  3. discover  - rebuild the record state at audit_at from the
                 evidence corpus and apply deletion_rules.csv,
                 emitting one FINDING per violation                [done]
  4. remedy    - REMEDIATION + post-remediation VERIFICATION for
                 incomplete cases; VERIFICATION only for complete  [TODO]

Stage 1 decision (AGENTS.md section 6.5, first bullet): a request that asks
for access, correction, portability, marketing opt-out, a login reset, a
profile update, or that explicitly refuses deletion is ``NOT_APPLICABLE`` and
carries ``steps_json = []``. Everything else authorises deletion and keeps
being audited.

Stage 3 decides status from evidence, not from ``reported_status``: a case is
``INCOMPLETE`` when at least one policy violation survives at ``audit_at`` and
``COMPLETE`` when none does. Step lists currently hold FINDING steps only;
stage 4 fills in the remediation and verification tails.

Usage:
    python3 code/main.py
    python3 code/main.py --verbose
    python3 code/main.py --out /tmp/check.csv --limit 5
    python3 code/main.py --dump-findings
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

import discovery as discovery_module
import evidence as evidence_module
import identity as identity_module

CODE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(CODE_DIR)
DEFAULT_DATASET_DIR = os.path.join(REPO_ROOT, "dataset")
DEFAULT_OUTPUT_PATH = os.path.join(REPO_ROOT, "output.csv")

OUTPUT_COLUMNS = ["case_id", "deletion_status", "steps_json"]
STATUS_ORDER = ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")

# What stage 1 writes on its own: it can prove that a request authorises
# deletion but not whether the required state holds. Kept as the baseline that
# `evaluate_identity_samples` measures the record audit against.
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
    """Shape one output row from a stage 1 verdict alone.

    Only ``NOT_APPLICABLE`` rows are final: the request does not authorise
    deletion, so there is nothing to audit and ``steps_json`` is ``[]``. Rows
    that do authorise deletion are built by :func:`row_for_case` instead, from
    the record audit.
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
# Stage 3: record audit - what still exists at audit_at?
# --------------------------------------------------------------------------
#
# `system_activity.csv` is a stream of *claims*. A workflow row saying
# DELETE_RECORD / SUCCESS does not make the record absent, and CHECK_DATA_FLOW
# saying the connector is enabled is not proof either. So activity rows are
# read only to explain a finding, never to produce one.
#
# The only inputs to a finding are:
#
#   * the subject's identifiers, bounded by audit_at (stage 2),
#   * evidence files captured at or before audit_at (the manifest gate),
#   * deletion_rules.csv, which says what treatment each category needs.
#
# Findings are the FINDING phase of the step contract. Stage 4 turns each one
# into a remediation action plus the verification that must follow it.

FINDING_ORDER = (
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
)


def build_evidence_index(data: "Dataset") -> "evidence_module.EvidenceIndex":
    """Parse every evidence file in the manifest exactly once."""
    manifest = [{"file_id": row["file_id"], "file_path": row["file_path"],
                 "captured_at": row["captured_at"]}
                for row in data.evidence_files]
    return evidence_module.EvidenceIndex(data.dataset_dir, manifest)


def audit_cases(requests: Sequence[dict],
                resolutions: Sequence["identity_module.Resolution"],
                classifications: Sequence["Classification"],
                index: "evidence_module.EvidenceIndex",
                rules: dict[str, str]) -> dict[str, list]:
    """case_id -> ordered findings, for requests that authorise deletion."""
    findings_by_case: dict[str, list] = {}
    for case, resolution, classification in zip(requests, resolutions, classifications):
        case_id = case["case_id"]
        if not classification.authorizes_deletion:
            continue
        findings_by_case[case_id] = discovery_module.discover_case(
            case_id, resolution, index, rules)
    return findings_by_case


def steps_from_findings(findings: Sequence) -> list[dict]:
    """Number findings from 1 so they satisfy the step contract as-is."""
    return [finding.as_step(step_no) for step_no, finding in enumerate(findings, 1)]


def row_for_case(case_id: str, findings: Sequence) -> dict:
    """One output row: status from findings, FINDING steps numbered from 1."""
    steps = steps_from_findings(findings)
    row = {
        "case_id": case_id,
        "deletion_status": "INCOMPLETE" if steps else "COMPLETE",
        "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")),
    }
    assert set(row) == set(OUTPUT_COLUMNS), "output row drifted from contract"
    if not steps:
        assert row["deletion_status"] == "COMPLETE"
    return row


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


def evaluate_identity_samples(data: "Dataset", resolver: "identity_module.IdentityResolver",
                             status_by_case: dict[str, str] | None = None) -> dict:
    """Score identity resolution on the public samples, against sample_output.

    Three questions, kept separate so the delta cannot be inflated:

      coverage   - how many sample cases are attributed to a person at all?
                   The comparison arm is the naive resolver (current snapshot
                   email only), which is what the pipeline would do without the
                   audit log.
      aliases    - on the cases that need history, did we recover every email
                   version the person has, not just the one quoted?
      status     - does any of this move deletion_status? It cannot yet: status
                   still comes from the record audit that stage 2/3 will add.
                   The number is reported as-is rather than dressed up.
    """
    truth = {r["case_id"]: r["deletion_status"] for r in data.sample_output}
    samples = [s for s in data.sample_deletion_requests if s["case_id"] in truth]
    if not samples:
        return {}

    rows = []
    for sample in samples:
        resolution = resolver.resolve(sample)
        baseline = identity_module.baseline_resolve(sample, data.user_identities)
        aliases = resolution.alias_set(resolution.audit_at)
        verdict = classify_case(sample)
        predicted = (verdict.status if verdict.intent == INTENT_NON_DELETION
                     else PROVISIONAL_STATUS)
        rows.append({
            "case_id": resolution.case_id,
            "truth": truth[resolution.case_id],
            "predicted": predicted,
            "outcome": resolution.outcome,
            "person_id": resolution.person_id,
            "baseline_person": baseline,
            "resolved_by": resolution.subject.resolved_by if resolution.subject else "",
            "n_emails": len(aliases["email"]),
            "n_phones": len(aliases["phone"]),
            "needs_history": bool(resolution.subject and resolution.subject.resolved_by != "snapshot"),
        })

    total = len(rows)
    resolved = sum(1 for r in rows if r["person_id"])
    baseline_resolved = sum(1 for r in rows if r["baseline_person"])
    bad_person = [r["case_id"] for r in rows
                  if r["baseline_person"] and r["person_id"] and r["baseline_person"] != r["person_id"]]
    history_cases = [r for r in rows if r["needs_history"] or r["n_emails"] > 1]

    # Which expected sample statuses need history at all, and does status track it?
    multi = Counter(r["truth"] for r in rows if r["n_emails"] > 1)
    single = Counter(r["truth"] for r in rows if r["n_emails"] <= 1)

    # Status is decided downstream; `predicted` comes from the record audit when
    # it is supplied, and falls back to the stage-1 provisional status.
    predicted_by_case = status_by_case or {}
    status_hits = sum(1 for r in rows
                      if predicted_by_case.get(r["case_id"], r["predicted"]) == r["truth"])
    stage1_status_hits = sum(1 for r in rows if r["predicted"] == r["truth"])
    # How many INCOMPLETE cases can even be investigated by each arm?
    baseline_attributable_hits = sum(1 for r in rows
                                     if r["baseline_person"] and "INCOMPLETE" == r["truth"])
    current_attributable_hits = sum(1 for r in rows
                                    if r["person_id"] and "INCOMPLETE" == r["truth"])
    baseline_version_total = sum(1 for r in rows if r["baseline_person"])

    return {
        "total": total,
        "resolved": resolved,
        "baseline_resolved": baseline_resolved,
        "disagreements": bad_person,
        "history_cases": [r["case_id"] for r in history_cases],
        "baseline_misses": [r["case_id"] for r in rows if not r["baseline_person"]],
        "multi_status": multi,
        "single_status": single,
        "status_hits": status_hits,
        "stage1_status_hits": stage1_status_hits,
        "baseline_attributable_hits": baseline_attributable_hits,
        "current_attributable_hits": current_attributable_hits,
        "alias_total_current": sum(r["n_emails"] for r in rows),
        "alias_total_baseline": baseline_version_total,
    }


def evaluate_discovery_samples(data: "Dataset",
                               resolver: "identity_module.IdentityResolver",
                               index: "evidence_module.EvidenceIndex",
                               rules: dict[str, str]) -> dict:
    """Score the record audit against the FINDING steps in sample_output.csv.

    Two things are measured separately, because they can fail independently:

      findings - exact match on (operation, system_id, resource_id, state,
                 evidence_id). A finding with the right record but the wrong
                 citation is not a hit: the citation is the proof.
      status   - whether "has any finding" reproduces deletion_status. This is
                 the whole decision rule for stage 3, so a single extra or
                 missing finding flips a case.
    """
    truth_rows = {r["case_id"]: r for r in data.sample_output}
    samples = [s for s in data.sample_deletion_requests if s["case_id"] in truth_rows]
    if not samples:
        return {}

    matched = 0
    missing_total = 0
    extra_total = 0
    status_hits = 0
    per_case = []
    missing: list[tuple] = []
    extra: list[tuple] = []

    for sample in samples:
        case_id = sample["case_id"]
        resolution = resolver.resolve(sample)
        found = discovery_module.discover_case(case_id, resolution, index, rules)
        expected = [s for s in json.loads(truth_rows[case_id]["steps_json"])
                    if s.get("phase") == "FINDING"]

        got_keys = {(f.operation, f.system_id, f.resource_id, f.state, f.evidence_id)
                    for f in found}
        want_keys = {(s["operation"], s["system_id"], s["resource_id"],
                      s["state"], s["evidence_id"]) for s in expected}

        matched += len(got_keys & want_keys)
        for key in sorted(want_keys - got_keys):
            missing.append((case_id,) + key)
        for key in sorted(got_keys - want_keys):
            extra.append((case_id,) + key)
        missing_total += len(want_keys - got_keys)
        extra_total += len(got_keys - want_keys)

        predicted = "INCOMPLETE" if found else "COMPLETE"
        want_status = truth_rows[case_id]["deletion_status"]
        status_hits += predicted == want_status
        per_case.append((case_id, want_status, predicted, len(found), len(expected)))

    return {
        "total_cases": len(samples),
        "expected_findings": matched + missing_total,
        "matched": matched,
        "missing": missing_total,
        "extra": extra_total,
        "status_hits": status_hits,
        "per_case": per_case,
        "missing_detail": missing,
        "extra_detail": extra,
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
    parser.add_argument("--dump-identities", nargs="?", metavar="PATH",
                        const=os.path.join(REPO_ROOT, "resolved_identities.csv"),
                        default=None,
                        help="write case_id, person_id and every linked identity "
                             "(default path: <repo>/resolved_identities.csv)")
    parser.add_argument("--dump-findings", nargs="?", metavar="PATH",
                        const=os.path.join(REPO_ROOT, "discovered_findings.csv"),
                        default=None,
                        help="write every per-case finding with its data category, "
                             "location and citing evidence "
                             "(default path: <repo>/discovered_findings.csv)")
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

    resolver = identity_module.IdentityResolver(data.user_identities, data.user_audit_log)
    resolutions = [resolver.resolve(case) for case in requests]

    index = build_evidence_index(data)
    rules = discovery_module.load_rules(data.deletion_rules)
    findings_by_case = audit_cases(requests, resolutions, classifications, index, rules)

    rows = []
    for case, classification in zip(requests, classifications):
        case_id = case["case_id"]
        if classification.authorizes_deletion:
            rows.append(row_for_case(case_id, findings_by_case.get(case_id, [])))
        else:
            rows.append(row_from_classification(classification))
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

    outcome_counts = Counter(r.outcome for r in resolutions)
    resolved_by = Counter(r.subject.resolved_by for r in resolutions if r.subject)
    people = {r.person_id for r in resolutions if r.person_id}
    email_hist = Counter(len(r.alias_set(r.audit_at)["email"]) for r in resolutions if r.subject)
    phone_hist = Counter(len(r.alias_set(r.audit_at)["phone"]) for r in resolutions if r.subject)

    print()
    print("identity resolution (user_identities.csv + user_audit_log.csv)")
    print(f"  distinct people          {len(people):>5}")
    for line in render_histogram(outcome_counts,
                                 ("RESOLVED", "UNRESOLVED", "AMBIGUOUS")):
        print(line)
    print(f"  matched via              snapshot {resolved_by.get('snapshot', 0)}, "
          f"history {resolved_by.get('history', 0)}")
    print(f"  email versions/person    {dict(sorted(email_hist.items()))}")
    print(f"  phone versions/person    {dict(sorted(phone_hist.items()))}")
    if resolver.failed_users:
        print(f"  integrity failures       {len(resolver.failed_users)} "
              f"(those subjects resolve to UNRESOLVED)")

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

    print()
    print("identity check on the public samples "
          "(baseline = current-snapshot email match only)")
    status_by_case = {row["case_id"]: row["deletion_status"] for row in rows}
    id_report = evaluate_identity_samples(data, resolver, status_by_case)
    if not id_report:
        print("  skipped: no overlapping sample rows")
    else:
        n = id_report["total"]
        resolved = id_report["resolved"]
        base = id_report["baseline_resolved"]
        print(f"  cases attributed         {resolved:>5}/{n}"
              f"  {resolved / n * 100:5.1f}%   full resolver (snapshot + history)")
        print(f"  baseline attributable    {base:>5}/{n}"
              f"  {base / n * 100:5.1f}%   current-snapshot email only")
        print(f"  coverage delta           {resolved - base:>+5}"
              f"  {(resolved - base) / n * 100:+5.1f} pp")
        print(f"  needed history           {len(id_report['history_cases']):>5}"
              f"   {id_report['history_cases']}")
        print(f"  baseline misses          {len(id_report['baseline_misses']):>5}"
              f"   {id_report['baseline_misses']}")
        print(f"  person disagreements     {len(id_report['disagreements']):>5}"
              f"   {id_report['disagreements'] or 'none'}")
        print(f"  email versions recovered {id_report['alias_total_current']:>5}"
              f"   baseline would recover {id_report['alias_total_baseline']}")
        print(f"  status by email count    multi-version {dict(id_report['multi_status'])}"
              f" | single {dict(id_report['single_status'])}")
        print(f"  deletion_status accuracy {id_report['status_hits']:>5}/{n}"
              f"  {id_report['status_hits'] / n * 100:5.1f}%"
              f"   stage 1 alone: {id_report['stage1_status_hits']}/{n}"
              f" ({(id_report['status_hits'] - id_report['stage1_status_hits']) / n * 100:+.1f} pp)")

    print()
    print("record audit (evidence_files.csv + dataset/evidence + deletion_rules.csv)")
    print(f"  evidence files           {len(index.manifest):>5}"
          f"   parsed {len(index.manifest) - len(index.unparsed) - len(index.empty)},"
          f" empty {len(index.empty)}, unreadable {len(index.unparsed)}")
    print(f"  observations             {len(index.observations):>5}"
          f"   record states extracted from file contents")
    if index.unparsed:
        print(f"  unreadable               {index.unparsed}"
              f"   (binary images: no OCR in this environment)")
    finding_counts = Counter(f.operation for findings in findings_by_case.values()
                             for f in findings)
    cases_with_findings = sum(1 for findings in findings_by_case.values() if findings)
    print(f"  cases with findings      {cases_with_findings:>5}"
          f" / {len(findings_by_case)} audited")
    for operation in FINDING_ORDER:
        print(f"    {operation:<26}{finding_counts.get(operation, 0):>5}")
    if (args.verbose and findings_by_case):
        print()
        print("  every finding")
        for case_id in sorted(findings_by_case):
            for finding in findings_by_case[case_id]:
                print(f"    {case_id:<9}{finding.operation:<26}{finding.system_id:<20}"
                      f"{finding.resource_id:<20}{finding.category:<22}"
                      f"{finding.location:<12}{finding.evidence_id}")

    print()
    print("finding check on the public samples (FINDING steps of sample_output.csv)")
    discovery_report = evaluate_discovery_samples(data, resolver, index, rules)
    if not discovery_report:
        print("  skipped: no overlapping sample rows")
    else:
        expected = discovery_report["expected_findings"]
        matched = discovery_report["matched"]
        print(f"  findings matched         {matched:>5}/{expected}"
              f"  {(matched / expected * 100) if expected else 100:5.1f}%"
              f"   exact operation+system+resource+state+evidence")
        print(f"  missing / extra          {discovery_report['missing']:>5}"
              f" / {discovery_report['extra']}")
        print(f"  deletion_status          {discovery_report['status_hits']:>5}"
              f"/{discovery_report['total_cases']}"
              f"  {(discovery_report['status_hits'] / discovery_report['total_cases'] * 100):5.1f}%"
              f"   INCOMPLETE iff a finding survives")
        for case_id, key in discovery_report["missing_detail"][:10]:
            print(f"    missing {case_id:<9}{key}")
        for case_id, key in discovery_report["extra_detail"][:10]:
            print(f"    extra   {case_id:<9}{key}")

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

    if args.dump_identities:
        dump_rows = identity_module.resolution_rows(requests, resolver)
        identity_module.write_resolution_csv(args.dump_identities, dump_rows)
        print()
        print(f"wrote {len(dump_rows)} identity row(s) -> {args.dump_identities}")

    if args.dump_findings:
        finding_rows = []
        for case_id in sorted(findings_by_case, key=case_sort_key):
            finding_rows.extend(f.as_row() for f in findings_by_case[case_id])
        discovery_module.write_findings_csv(args.dump_findings, finding_rows)
        print()
        print(f"wrote {len(finding_rows)} finding row(s) -> {args.dump_findings}")

    print()
    print(f"wrote {stats['rows']} rows -> {args.output}")
    print(f"  NOT_APPLICABLE : {status_counts.get('NOT_APPLICABLE', 0)} (decided)")
    print(f"  INCOMPLETE     : {status_counts.get('INCOMPLETE', 0)} "
          f"(record audit found surviving violations)")
    print(f"  COMPLETE       : {status_counts.get('COMPLETE', 0)} "
          f"(no violation found at audit_at; verification steps land in stage 4)")
    if args.verbose:
        print(f"  dataset  : {data.dataset_dir}")
        print(f"  contract : {','.join(OUTPUT_COLUMNS)}")
        print(f"  evidence : {len(data.evidence_files)} manifest entries, "
              f"{len(index.observations)} observations")
        print(f"  rules    : {len(data.deletion_rules)} policy rows applied")
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
