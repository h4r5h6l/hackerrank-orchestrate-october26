#!/usr/bin/env python3
"""Deterministic identity resolution for the deletion audit.

Implements the algorithm proposed during the design step: resolve the request
email to exactly one stable ``user_id``, then expand that subject to every
identifier version they have ever had, with the validity window and the audit
record that introduced each version.

Invariants this module depends on, all verified at construction time from the
dataset itself (never hardcoded):

  * ``email_hash`` is ``sha256(email)``;
  * the audit log is a chain - each ``old_value`` equals the previous
    ``new_value``, and the snapshot equals the last ``new_value``;
  * a subject's aliases are distinct;
  * one identifier value has one owner (a shared value is reported, not
    silently merged).

No fuzzy matching, no name matching, no model call. Every ordered step uses
``(event_time, audit_id)`` as a total order, so the same input always produces
the same subject and the same alias list.
"""

from __future__ import annotations

import csv
import hashlib
import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

FIELDS = ("email", "phone", "email_hash")

MIN_TIME = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAX_TIME = datetime(9999, 12, 31, tzinfo=timezone.utc)

_EPSILON = re.compile(r"\s+")
_APOSTROPHES = str.maketrans({"\u2019": "'", "\u2018": "'", "\u02bc": "'"})


class IdentityIntegrityError(RuntimeError):
    """Raised when the dataset violates an invariant the resolver relies on."""


def parse_time(value: str) -> datetime:
    """Parse an ISO-8601 timestamp; ``Z`` is normalised to ``+00:00``."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def normalize_email(value: str) -> str:
    """NFKC, ASCII apostrophes, collapsed whitespace, casefold."""
    folded = unicodedata.normalize("NFKC", value or "").translate(_APOSTROPHES)
    return _EPSILON.sub(" ", folded).strip().casefold()


def normalize_phone(value: str) -> str:
    """Keep digits only, so '+1 (202) 555-0103' and '+12025550103' agree."""
    return re.sub(r"\D", "", value or "")


def normalize_hash(value: str) -> str:
    return (value or "").strip().lower()


def normalize_field(field_name: str, value: str) -> str:
    if field_name == "email":
        return normalize_email(value)
    if field_name == "phone":
        return normalize_phone(value)
    if field_name == "email_hash":
        return normalize_hash(value)
    raise ValueError(f"unknown identity field: {field_name}")


def email_hash(email: str) -> str:
    return hashlib.sha256((email or "").encode("utf-8")).hexdigest()


def natural_audit_key(audit_id: str) -> tuple:
    suffix = audit_id.rsplit("_", 1)[-1]
    try:
        return (0, int(suffix), audit_id)
    except ValueError:
        return (1, 0, audit_id)


@dataclass(frozen=True)
class Version:
    """One value of one field, and the half-open window it was current for."""

    field: str
    value: str
    t_from: datetime
    t_to: datetime
    source: str          # "snapshot" or "audit:<audit_id>"

    @property
    def audit_id(self) -> str:
        return self.source.split(":", 1)[1] if self.source.startswith("audit:") else ""

    def live_at(self, moment: datetime) -> bool:
        return self.t_from <= moment < self.t_to


@dataclass(frozen=True)
class Subject:
    """A resolved person and every identifier version known for them."""

    user_id: str
    resolved_by: str                 # "snapshot" | "history"
    matched_value: str
    versions: tuple[Version, ...]

    def _values(self, field_name: str, cutoff: datetime | None = None) -> tuple[str, ...]:
        values = [v.value for v in self.versions
                  if v.field == field_name and (cutoff is None or v.t_from <= cutoff)]
        return tuple(sorted(set(values)))

    def emails(self, cutoff: datetime | None = None) -> tuple[str, ...]:
        return self._values("email", cutoff)

    def phones(self, cutoff: datetime | None = None) -> tuple[str, ...]:
        return self._values("phone", cutoff)

    def hashes(self, cutoff: datetime | None = None) -> tuple[str, ...]:
        return self._values("email_hash", cutoff)

    def provenance(self, field_name: str) -> tuple[tuple[str, datetime, datetime, str], ...]:
        return tuple((v.value, v.t_from, v.t_to, v.source)
                     for v in self.versions if v.field == field_name)

    def counts(self) -> dict[str, int]:
        return {f"n_{name}": len(self._values(name)) for name in FIELDS}


@dataclass(frozen=True)
class Resolution:
    """Outcome of resolving one case's request email to a person."""

    case_id: str
    outcome: str                     # "RESOLVED" | "UNRESOLVED" | "AMBIGUOUS"
    subject: Subject | None
    reason: str
    requested_at: datetime | None
    audit_at: datetime | None

    @property
    def person_id(self) -> str:
        return self.subject.user_id if self.subject else ""

    @property
    def matched_value(self) -> str:
        return self.subject.matched_value if self.subject else ""

    def alias_set(self, cutoff: datetime | None = None) -> dict[str, tuple[str, ...]]:
        if not self.subject:
            return {name: () for name in FIELDS}
        return {
            "email": self.subject.emails(cutoff),
            "phone": self.subject.phones(cutoff),
            "email_hash": self.subject.hashes(cutoff),
        }


class IdentityResolver:
    """Index once, resolve many. Deterministic and side-effect free."""

    def __init__(self, identities: Sequence[dict], audit_log: Sequence[dict]):
        self.snapshot: dict[str, dict] = {}
        self._events: dict[tuple[str, str], list[dict]] = defaultdict(list)
        self._email_owners: dict[str, set[str]] = defaultdict(set)
        self._failed_users: dict[str, str] = {}
        self._versions: dict[tuple[str, str], tuple[Version, ...]] = {}

        for row in identities:
            user_id = (row.get("user_id") or "").strip()
            if not user_id:
                raise IdentityIntegrityError("identity row without user_id")
            if user_id in self.snapshot:
                raise IdentityIntegrityError(f"duplicate snapshot row for {user_id}")
            self.snapshot[user_id] = row
            email_value = normalize_email(row.get("email", ""))
            if email_value:
                self._email_owners[email_value].add(user_id)

        for row in audit_log:
            user_id = (row.get("user_id") or "").strip()
            field_name = (row.get("field_name") or "").strip()
            if field_name not in FIELDS:
                raise IdentityIntegrityError(f"unknown audit field {field_name!r}")
            self._events[(user_id, field_name)].append(row)
            if field_name == "email":
                for value in (row.get("old_value", ""), row.get("new_value", "")):
                    normalized = normalize_email(value)
                    if normalized:
                        self._email_owners[normalized].add(user_id)

        for events in self._events.values():
            events.sort(key=lambda r: (parse_time(r["event_time"]),
                                       natural_audit_key(r["audit_id"])))

        for user_id in self.snapshot:
            try:
                self._versions[user_id] = self._build_versions(user_id)
                self._check_user_invariants(user_id)
            except IdentityIntegrityError as exc:
                self._failed_users[user_id] = str(exc)

    # -- construction -----------------------------------------------------

    def _build_versions(self, user_id: str) -> tuple[Version, ...]:
        versions: list[Version] = []
        for field_name in FIELDS:
            events = self._events.get((user_id, field_name), [])
            if not events:
                versions.append(Version(field_name, self.snapshot[user_id][field_name],
                                        MIN_TIME, MAX_TIME, "snapshot"))
                continue
            first = events[0]
            versions.append(Version(field_name, first["old_value"], MIN_TIME,
                                    parse_time(first["event_time"]),
                                    f"audit:{first['audit_id']}"))
            for index, event in enumerate(events):
                following = events[index + 1] if index + 1 < len(events) else None
                versions.append(Version(field_name, event["new_value"],
                                        parse_time(event["event_time"]),
                                        parse_time(following["event_time"]) if following else MAX_TIME,
                                        f"audit:{event['audit_id']}"))
        return tuple(versions)

    def _check_user_invariants(self, user_id: str) -> None:
        snapshot = self.snapshot[user_id]
        for field_name in FIELDS:
            events = self._events.get((user_id, field_name), [])
            for previous, current in zip(events, events[1:]):
                if (normalize_field(field_name, previous["new_value"])
                        != normalize_field(field_name, current["old_value"])):
                    raise IdentityIntegrityError(
                        f"{user_id}/{field_name}: chain break between "
                        f"{previous['audit_id']} and {current['audit_id']}")
            if events and (normalize_field(field_name, events[-1]["new_value"])
                           != normalize_field(field_name, snapshot[field_name])):
                raise IdentityIntegrityError(
                    f"{user_id}/{field_name}: snapshot differs from the last "
                    f"audit new_value ({events[-1]['audit_id']})")

        emails = [v.value for v in self._versions[user_id] if v.field == "email"]
        if len({normalize_email(e) for e in emails}) != len(emails):
            raise IdentityIntegrityError(f"{user_id}/email: duplicate alias version")

        if email_hash(snapshot["email"]) != normalize_hash(snapshot["email_hash"]):
            raise IdentityIntegrityError(f"{user_id}: snapshot hash is not sha256(email)")

        by_time = {parse_time(e["event_time"]): e["new_value"]
                   for e in self._events.get((user_id, "email"), [])}
        hash_by_time = {parse_time(e["event_time"]): e["new_value"]
                        for e in self._events.get((user_id, "email_hash"), [])}
        for moment, email_value in by_time.items():
            stored = hash_by_time.get(moment)
            if stored is not None and email_hash(email_value) != normalize_hash(stored):
                raise IdentityIntegrityError(
                    f"{user_id}: hash change at {moment.isoformat()} is not sha256(email)")

    # -- queries ----------------------------------------------------------

    @property
    def failed_users(self) -> dict[str, str]:
        return dict(self._failed_users)

    def owners_of(self, email_value: str) -> set[str]:
        return set(self._email_owners.get(normalize_email(email_value), set()))

    def _subject(self, user_id: str, resolved_by: str, matched: str) -> Subject:
        return Subject(user_id=user_id, resolved_by=resolved_by, matched_value=matched,
                       versions=self._versions[user_id])

    def _break_tie(self, case_id: str, owners: set[str], value: str,
                   requested_at: datetime | None) -> Resolution:
        """Tie-break on version validity at requested_at; refuse if still tied."""
        if requested_at is not None:
            live = [uid for uid in sorted(owners)
                    if uid in self._versions
                    and any(v.field == "email" and normalize_email(v.value) == normalize_email(value)
                            and v.live_at(requested_at)
                            for v in self._versions[uid])]
            if len(live) == 1:
                return Resolution(case_id, "RESOLVED",
                                  self._subject(live[0], "tiebreak", value),
                                  f"email shared by {sorted(owners)}; unique owner at requested_at",
                                  requested_at, None)
        return Resolution(case_id, "AMBIGUOUS", None,
                          f"email {value!r} is claimed by {sorted(owners)}",
                          requested_at, None)

    def resolve(self, case: dict) -> Resolution:
        """Resolve one request row (case_id, email, requested_at, audit_at)."""
        case_id = case.get("case_id", "")
        raw_email = case.get("email", "")
        value = normalize_email(raw_email)
        requested_at = parse_time(case["requested_at"]) if case.get("requested_at") else None
        audit_at = parse_time(case["audit_at"]) if case.get("audit_at") else None

        def unresolved(reason: str, outcome: str = "UNRESOLVED") -> Resolution:
            return Resolution(case_id, outcome, None, reason, requested_at, audit_at)

        if not value:
            return unresolved("request has no email address")

        owners = self._email_owners.get(value, set())
        if not owners:
            return unresolved(f"{raw_email!r} appears in neither the snapshot nor the audit log")

        if len(owners) > 1:
            tie = self._break_tie(case_id, owners, raw_email, requested_at)
            if tie.outcome != "RESOLVED":
                return Resolution(case_id, "AMBIGUOUS", None, tie.reason,
                                  requested_at, audit_at)
            user_id, resolved_by = tie.subject.user_id, "tiebreak"
        else:
            user_id = next(iter(owners))
            resolved_by = "snapshot" if normalize_email(
                self.snapshot[user_id]["email"]) == value else "history"

        if user_id in self._failed_users:
            return unresolved(f"{user_id} failed integrity checks: {self._failed_users[user_id]}")

        return Resolution(case_id, "RESOLVED", self._subject(user_id, resolved_by, raw_email),
                          "", requested_at, audit_at)


# --------------------------------------------------------------------------
# Reporting helpers
# --------------------------------------------------------------------------

def resolution_rows(cases: Iterable[dict], resolver: IdentityResolver,
                    cutoff_field: str = "audit_at") -> list[dict]:
    """One flat row per case: person_id plus the alias set at the case cutoff."""
    rows = []
    for case in cases:
        resolution = resolver.resolve(case)
        cutoff = resolution.audit_at
        aliases = resolution.alias_set(cutoff)
        rows.append({
            "case_id": resolution.case_id,
            "outcome": resolution.outcome,
            "person_id": resolution.person_id,
            "resolved_by": resolution.subject.resolved_by if resolution.subject else "",
            "matched_value": resolution.matched_value if resolution.subject else "",
            "n_emails": len(aliases["email"]),
            "n_phones": len(aliases["phone"]),
            "n_hashes": len(aliases["email_hash"]),
            "emails": "|".join(aliases["email"]),
            "phones": "|".join(aliases["phone"]),
            "email_hashes": "|".join(aliases["email_hash"]),
            "sources": "|".join(sorted({v.source for v in resolution.subject.versions})) if resolution.subject else "",
            "reason": resolution.reason,
        })
    return rows


def write_resolution_csv(path: str, rows: Sequence[dict]) -> None:
    columns = ["case_id", "outcome", "person_id", "resolved_by", "matched_value",
               "n_emails", "n_phones", "n_hashes", "emails", "phones",
               "email_hashes", "sources", "reason"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def baseline_resolve(case: dict, identities: Sequence[dict]) -> str:
    """The naive resolver: exact current-snapshot email match only.

    Kept as the comparison arm for the accuracy delta - it is what the
    pipeline would do without the audit log.
    """
    value = normalize_email(case.get("email", ""))
    for row in identities:
        if normalize_email(row.get("email", "")) == value:
            return row["user_id"]
    return ""
