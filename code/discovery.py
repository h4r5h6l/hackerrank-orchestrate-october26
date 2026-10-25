#!/usr/bin/env python3
"""Turn evidence observations into per-case findings.

`evidence.py` answers "what did each system say about each record". This module
answers the question the case actually asks:

    for this subject, at this audit_at, which records still exist in a state
    that `deletion_rules.csv` forbids?

The join is deliberately narrow:

  1. the subject's identifiers come from identity resolution, bounded by
     `audit_at`, so a historical email is still a match;
  2. an observation counts only if the file was captured at or before
     `audit_at` (a later snapshot did not exist at decision time);
  3. for the same (system, resource) the newest observation wins, so a later
     `NOT_FOUND` suppresses an earlier `FOUND`;
  4. the rule for the record's category decides whether the surviving state is
     a violation: DELETE needs absence, REDACT/ANONYMIZE need no direct
     identifier, RETAIN needs only that restore is blocked.

No activity result is trusted here. `system_activity.csv` says what the
workflow attempted; only evidence says what is still there.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence

import evidence
import identity

#: finding operations in the order the specification lists them
OPERATION_ORDER = (
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
)

STATE_BY_OPERATION = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
}

#: categories whose violation means "this should not exist at all"
DELETE_ACTIONS = ("DELETE",)
EXPOSURE_ACTIONS = ("REDACT", "ANONYMIZE")


@dataclass(frozen=True)
class Finding:
    case_id: str
    operation: str
    system_id: str
    resource_id: str
    state: str
    evidence_id: str
    category: str
    location: str
    observed_at: datetime
    detail: str = ""

    def order_key(self) -> tuple:
        return (OPERATION_ORDER.index(self.operation), self.resource_id, self.system_id)

    def as_step(self, step_no: int) -> dict:
        return {
            "step_no": step_no,
            "phase": "FINDING",
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }

    def as_row(self) -> dict:
        return {
            "case_id": self.case_id,
            "operation": self.operation,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "state": self.state,
            "evidence_id": self.evidence_id,
            "data_category": self.category,
            "location": self.location,
            "observed_at": self.observed_at.isoformat().replace("+00:00", "Z"),
            "detail": self.detail,
        }


def load_rules(rows: Sequence[dict]) -> dict[str, str]:
    """data_category -> required_action, straight from deletion_rules.csv."""
    return {row["data_category"].strip().upper(): row["required_action"].strip().upper()
            for row in rows}


def _violation(observation: evidence.Observation, action: str) -> str:
    """Which finding operation (if any) this surviving state justifies."""
    if observation.category == "DATA_FLOW":
        return "REPORT_ACTIVE_DATA_FLOW" if observation.state == "ACTIVE" else ""

    if action in DELETE_ACTIONS:
        if observation.state in ("PRESENT", "ACTIVE"):
            return "REPORT_REMAINING_RECORD"
        return ""

    if action in EXPOSURE_ACTIONS:
        if observation.state == "PRESENT" and observation.exposure:
            return "REPORT_EXPOSED_PII"
        return ""

    if action == "RETAIN":
        # A retained backup is only a violation while it can still be restored.
        if observation.category == "BACKUP_ARCHIVE" and observation.state == "ACTIVE":
            return "REPORT_RESTORE_RISK"
        return ""

    return ""


def latest_states(observations: Iterable[evidence.Observation]) -> dict[tuple[str, str],
                                                                      evidence.Observation]:
    """Newest observation per (system, resource); ties break deterministically."""
    latest: dict[tuple[str, str], evidence.Observation] = {}
    for observation in observations:
        current = latest.get(observation.key)
        if current is None or observation.sort_key() > current.sort_key():
            latest[observation.key] = observation
    return latest


def discover_case(case_id: str, resolution: identity.Resolution,
                  index: evidence.EvidenceIndex, rules: dict[str, str]) -> list[Finding]:
    """All findings for one case, ordered by operation then resource."""
    if not resolution.subject or resolution.audit_at is None:
        return []
    cutoff = resolution.audit_at
    aliases = resolution.alias_set(cutoff)
    observations = index.subject_observations(
        aliases["email"], aliases["phone"], aliases["email_hash"],
        [resolution.person_id], cutoff)
    if not observations:
        return []

    findings = []
    for observation in latest_states(observations).values():
        action = rules.get(observation.category, "")
        operation = _violation(observation, action)
        if not operation:
            continue
        findings.append(Finding(
            case_id=case_id, operation=operation, system_id=observation.system_id,
            resource_id=observation.resource_id,
            state=STATE_BY_OPERATION[operation], evidence_id=observation.evidence_id,
            category=observation.category, location=observation.location,
            observed_at=observation.observed_at,
            detail=f"{observation.category} {observation.state}"
                   + (" with direct identifiers" if observation.exposure else "")))
    findings.sort(key=Finding.order_key)
    return findings


def discovery_rows(cases: Sequence[dict], resolutions: dict[str, identity.Resolution],
                   index: evidence.EvidenceIndex, rules: dict[str, str]) -> list[dict]:
    rows = []
    for case in cases:
        case_id = case["case_id"]
        for finding in discover_case(case_id, resolutions[case_id], index, rules):
            rows.append(finding.as_row())
    return rows


def write_findings_csv(path: str, rows: Sequence[dict]) -> None:
    columns = ["case_id", "operation", "system_id", "resource_id", "state",
               "evidence_id", "data_category", "location", "observed_at", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
