#!/usr/bin/env python3
"""Normalise the evidence corpus into observations about records.

Every file under ``dataset/evidence/`` is one system's point-in-time view. The
formats differ (SQLite snapshots, JSON exports, ledger text, three log
syntaxes, PDFs) but they all answer the same question:

    does record <resource_id> in <system> still exist at <time>,
    and if so, which of the subject's identifiers does it still expose?

This module answers that question in isolation: it parses, it does not judge.
Judging happens in ``discovery.py``, which applies ``deletion_rules.csv``.

Design rules:

  * the manifest is the only index of files; a file is identified by its
    ``file_id`` so findings can cite it;
  * the *file* capture time gates eligibility (a file captured after a case's
    ``audit_at`` did not exist at decision time and is never read);
  * per-record timestamps (``observed_at`` / ``recorded_at``) order competing
    observations of the same resource;
  * no name matching, no fuzzy matching - identifiers are exact after the
    normalisation in ``identity.py``;
  * an unparseable file is recorded as unparsed rather than silently skipped.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator, Sequence

import identity

# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------

#: States an observation can report. `ACTIVE`/`BLOCKED`/`DISABLED` describe a
#: process or a restore path; the others describe a record.
STATES = ("PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "BLOCKED", "DISABLED")

#: raw tokens seen in the corpus -> canonical state
_STATE_BY_TOKEN = {
    "FOUND": "PRESENT",
    "PRESENT": "PRESENT",
    "IDENTIFIABLE": "PRESENT",
    "EXISTS": "PRESENT",
    "HIT": "PRESENT",
    "NOT_FOUND": "ABSENT",
    "MISSING": "ABSENT",
    "ABSENT": "ABSENT",
    "DELETED": "ABSENT",
    "REDACTED": "REDACTED",
    "ANONYMIZED": "ANONYMIZED",
    "ACTIVE": "ACTIVE",
    "ENABLED": "ACTIVE",
    "RESTORABLE": "ACTIVE",
    "BLOCKED": "BLOCKED",
    "DISABLED": "DISABLED",
    "STOPPED": "DISABLED",
}

#: table or collection -> data category
_CATEGORY_BY_SOURCE = {
    "customer_profiles": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "profile_lookups": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "index_queries": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "support_conversations": "SUPPORT_MESSAGE",
    "tickets": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "customer_exports": "USER_EXPORT",
    "customer_export_jobs": "USER_EXPORT",
    "exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "connector_configurations": "DATA_FLOW",
    "connectors": "DATA_FLOW",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "backup_catalog": "BACKUP_ARCHIVE",
    "restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "audit_records": "SECURITY_AUDIT_LOG",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "retained_order_records": "LEGAL_HOLD_RECORD",
    "customer_profiles_tombstone": "ACCOUNT_TOMBSTONE",
}

#: names that look like a system but are really a store or a team alias
SYSTEM_ALIASES = {
    "support_replica": "support_platform",
    "search_index_service": "search_service",
    "attachment_preview": "support_platform",
    "profile_service": "account_service",
    "user_export_store": "export_service",
    "support_storage_service": "support_platform",
    "backup_restore_service": "backup_service",
    "customer_account_service": "account_service",
    "downstream_delivery_service": "email_delivery_service",
    "privacy_treatment_service": "",
    "records_assurance_service": "",
    "customer_data_read_replica_capture": "",
}

KNOWN_SYSTEMS = frozenset({
    "account_service", "search_service", "analytics_platform", "support_platform",
    "integration_service", "backup_service", "security_service", "export_service",
    "identity_service", "legal_service", "marketing_platform", "cache_service",
    "email_delivery_service", "object_store",
})

#: data category -> the system that owns it (only used when the row is silent)
SYSTEM_BY_CATEGORY = {
    "USER_PROFILE": "account_service",
    "SECONDARY_IDENTIFIER": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "ANALYTICS_PROFILE": "analytics_platform",
    "PRODUCT_TELEMETRY": "analytics_platform",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "USER_EXPORT": "export_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "BACKUP_ARCHIVE": "backup_service",
    "CACHE_ENTRY": "cache_service",
    "DATA_FLOW": "integration_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
}

#: data category -> where the copy physically lives
LOCATION_BY_CATEGORY = {
    "USER_PROFILE": "primary",
    "SECONDARY_IDENTIFIER": "primary",
    "SEARCH_INDEX_ENTRY": "index",
    "ANALYTICS_PROFILE": "analytics",
    "PRODUCT_TELEMETRY": "analytics",
    "SUPPORT_MESSAGE": "support",
    "SUPPORT_ATTACHMENT": "support",
    "USER_EXPORT": "export",
    "MARKETING_PROFILE": "marketing",
    "EMAIL_DELIVERY_LOG": "log",
    "SECURITY_AUDIT_LOG": "log",
    "LEGAL_HOLD_RECORD": "archive",
    "BACKUP_ARCHIVE": "backup",
    "CACHE_ENTRY": "cache",
    "DATA_FLOW": "integration",
    "ACCOUNT_TOMBSTONE": "identity",
}

#: columns that carry a direct identifier, by category of exposure
_EMAIL_COLUMNS = ("email", "customer_email", "requester_email", "owner_email",
                  "subject_reference_email", "matched_value", "lookup_value")
_PHONE_COLUMNS = ("phone", "requester_phone", "owner_phone", "customer_phone")
_HASH_COLUMNS = ("email_hash", "subject_hash", "lookup_hash")
_NAME_COLUMNS = ("full_name", "display_name", "requester_name", "name", "uploaded_by")
_REF_COLUMNS = ("user_id", "customer_reference", "subject_reference", "owner_reference")

#: columns that prove a *stored* direct identifier (not a lookup key)
_STORED_EMAIL = ("email", "customer_email", "requester_email", "owner_email")
_STORED_PHONE = ("phone", "requester_phone", "owner_phone", "customer_phone")
_STORED_HASH = ("email_hash",)
_STORED_NAME = ("full_name", "display_name", "requester_name", "name", "uploaded_by")

_DIRECT_ID_COLUMNS = _EMAIL_COLUMNS + _PHONE_COLUMNS + _HASH_COLUMNS + _NAME_COLUMNS
_STORED_ID_COLUMNS = _STORED_EMAIL + _STORED_PHONE + _STORED_HASH + _STORED_NAME

_TOKEN_SPLIT = re.compile(r"\s*\|\s*")
_KV_PAIR = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|\S+)')
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\+\d[\d ()\-]{7,}\d")
_USER_RE = re.compile(r"\buser_(\d+)\b")
_HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
_RESOURCE_RE = re.compile(r"\b(account|search|analytics|support|audit_record|export|"
                          r"backup|data_flow|tombstone|object|legal_hold|marketing)_(\d+)\b")
_TOPOLOGY_RE = re.compile(r"Database topology:\s*([A-Za-z_]+)")


@dataclass(frozen=True)
class Observation:
    """One statement by one system about one resource at one time."""

    evidence_id: str
    captured_at: datetime
    observed_at: datetime
    system_id: str
    resource_id: str
    category: str
    state: str
    exposure: bool
    identifiers: frozenset[str] = frozenset()
    user_refs: frozenset[str] = frozenset()
    location: str = ""
    detail: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.system_id, self.resource_id)

    def sort_key(self) -> tuple:
        return (self.observed_at, self.captured_at, self.evidence_id)


@dataclass
class ParsedFile:
    evidence_id: str
    captured_at: datetime
    observations: list[Observation] = field(default_factory=list)
    unparsed: bool = False
    note: str = ""


# --------------------------------------------------------------------------
# Value normalisation
# --------------------------------------------------------------------------

def _add_identifier(bucket: set[str], raw: object) -> None:
    """Collect one raw value into the identifier set, guessing its kind."""
    if raw is None:
        return
    text = str(raw).strip()
    if not text or text.lower() in ("null", "none", "n/a"):
        return
    user = _USER_RE.search(text)
    if user:
        bucket.add(f"user_{user.group(1)}")
    for candidate in _EMAIL_RE.findall(text):
        bucket.add(identity.normalize_email(candidate))
    digits = identity.normalize_phone(text)
    if len(digits) >= 8 and not _EMAIL_RE.search(text):
        bucket.add("phone:" + digits)
    for digest in _HASH_RE.findall(text.lower()):
        bucket.add("hash:" + digest)


def _split_identifiers(values: Iterable[object]) -> tuple[set[str], set[str]]:
    """Split raw identifiers into (direct identifiers, user references)."""
    direct: set[str] = set()
    refs: set[str] = set()
    for value in values:
        found: set[str] = set()
        _add_identifier(found, value)
        for item in found:
            (refs if item.startswith("user_") else direct).add(item)
    return direct, refs


def _state(token: str) -> str:
    return _STATE_BY_TOKEN.get((token or "").strip().upper(), "PRESENT")


#: resource-id namespace -> data category, used when the row names no category
_CATEGORY_BY_RESOURCE = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "support": "SUPPORT_MESSAGE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "export": "USER_EXPORT",
    "backup": "BACKUP_ARCHIVE",
    "data_flow": "DATA_FLOW",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "marketing": "MARKETING_PROFILE",
}


def _category_by_resource(resource_id: str) -> str:
    match = _RESOURCE_RE.search(resource_id or "")
    if not match:
        return ""
    return _CATEGORY_BY_RESOURCE.get(match.group(1), "")


def _category(*candidates: object) -> str:
    for candidate in candidates:
        text = (str(candidate or "")).strip().upper()
        if not text:
            continue
        if text in SYSTEM_BY_CATEGORY:
            return text
        if text.lower() in _CATEGORY_BY_SOURCE:
            return _CATEGORY_BY_SOURCE[text.lower()]
    return ""


def _system(system_hint: object, category: str, source: str = "") -> str:
    for candidate in (system_hint, source):
        text = str(candidate or "").strip()
        if not text or text.lower() in ("null", "none"):
            continue
        if text in SYSTEM_ALIASES:
            # an alias may still resolve to nothing; fall back to the category
            return SYSTEM_ALIASES[text] or SYSTEM_BY_CATEGORY.get(category, "")
        if text in KNOWN_SYSTEMS:
            return text
    return SYSTEM_BY_CATEGORY.get(category, "")


def _location(category: str, topology: str = "") -> str:
    base = LOCATION_BY_CATEGORY.get(category, "")
    if topology and base in ("primary", "index"):
        if "replica" in topology or "failover" in topology:
            return "replica"
    return base


def _exposure_for(category: str, row: dict) -> bool:
    """Would this record still be linkable to the subject?"""
    def present(columns: Sequence[str]) -> bool:
        for column in columns:
            value = row.get(column)
            if value in (None, "", "null", "None"):
                continue
            if isinstance(value, str) and not value.strip():
                continue
            return True
        return False

    if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        return present(_STORED_ID_COLUMNS + _REF_COLUMNS)
    if category in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE",
                    "USER_PROFILE", "SECONDARY_IDENTIFIER"):
        return present(_STORED_ID_COLUMNS)
    # DELETE-style categories do not become compliant by dropping a field
    return False


# --------------------------------------------------------------------------
# SQL snapshots
# --------------------------------------------------------------------------

_IDENTITY_COLUMNS = tuple(dict.fromkeys(
    _EMAIL_COLUMNS + _PHONE_COLUMNS + _HASH_COLUMNS + _DIRECT_ID_COLUMNS + _REF_COLUMNS))


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _parse_sql(path: str, evidence_id: str, captured_at: datetime) -> list[Observation]:
    text = _read_text(path)
    topology_match = _TOPOLOGY_RE.search(text)
    topology = topology_match.group(1) if topology_match else ""

    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(text)
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        observations = []
        for table in tables:
            if table in ("snapshot_scope",):
                continue
            cursor = connection.execute(f'SELECT * FROM "{table}"')
            columns = [d[0] for d in cursor.description]
            for values in cursor.fetchall():
                row = dict(zip(columns, values))
                record_json = row.get("record_json")
                if record_json:
                    try:
                        embedded = json.loads(record_json)
                    except (TypeError, ValueError):
                        embedded = {}
                    if isinstance(embedded, dict):
                        nested = embedded.get("document")
                        row = {**row, **embedded}
                        if isinstance(nested, dict):
                            row = {**row, **nested}
                category = _category(row.get("collection_name"), row.get("record_type"),
                                     table)
                if not category:
                    continue
                system = _system(row.get("origin_system") or row.get("system"),
                                 category, table)
                resource = str(row.get("resource_id") or row.get("id") or "")
                if not resource:
                    continue
                observations.append(_row_observation(
                    row, evidence_id, captured_at, system, resource, category,
                    _location(category, topology), detail=table))
        return observations
    finally:
        connection.close()


def _row_observation(row: dict, evidence_id: str, captured_at: datetime,
                     system: str, resource: str, category: str, location: str,
                     detail: str = "") -> Observation:
    observed_raw = (row.get("observed_at") or row.get("recorded_at")
                    or row.get("created_at") or row.get("updated_at"))
    observed_at = identity.parse_time(observed_raw) if observed_raw else captured_at

    identifiers, refs = _split_identifiers(
        row.get(column) for column in _IDENTITY_COLUMNS if column in row)

    status = str(row.get("account_status") or "").strip().upper()
    if category == "USER_PROFILE" and status in ("DELETED", "TOMBSTONE", "DELETION_COMPLETE"):
        category = "ACCOUNT_TOMBSTONE"

    if category == "BACKUP_ARCHIVE":
        allowed = row.get("restore_allowed")
        state = "ACTIVE" if str(allowed).strip().lower() in ("1", "true") else "BLOCKED"
    elif category == "DATA_FLOW":
        enabled = row.get("enabled")
        state = "ACTIVE" if str(enabled).strip().lower() in ("1", "true") else "DISABLED"
    elif "result" in row and str(row.get("result", "")).strip():
        state = _state(str(row["result"]))
    else:
        state = "PRESENT"

    exposure = _exposure_for(category, row) if state == "PRESENT" else False
    return Observation(
        evidence_id=evidence_id, captured_at=captured_at, observed_at=observed_at,
        system_id=system, resource_id=resource, category=category, state=state,
        exposure=exposure, identifiers=frozenset(identifiers),
        user_refs=frozenset(refs), location=location, detail=detail)


# --------------------------------------------------------------------------
# JSON exports and bundles
# --------------------------------------------------------------------------

def _json_records(document: dict) -> Iterator[tuple[dict, dict]]:
    """Yield (context, record) for every record shape the corpus uses.

    Context keys: `data_store`, `collection`, `captured_at`. The three container
    shapes are a snapshot bundle, a per-service export, and a flat collection.
    """
    if "snapshots" in document:
        for snapshot in document.get("snapshots") or []:
            context = {
                "data_store": snapshot.get("data_store") or "",
                "collection": snapshot.get("collection") or "",
                "captured_at": snapshot.get("captured_at") or "",
            }
            for record in snapshot.get("records") or []:
                yield context, record
        return
    if "service_exports" in document:
        for service, collections in (document.get("service_exports") or {}).items():
            for collection, records in (collections or {}).items():
                context = {"data_store": service, "collection": collection,
                           "captured_at": document.get("exported_at") or ""}
                for record in records or []:
                    yield context, record
        return
    context = {
        "data_store": document.get("source") or document.get("origin") or "",
        "collection": document.get("collection") or "",
        "captured_at": document.get("captured_at") or document.get("exported_at") or "",
    }
    for record in document.get("records") or []:
        yield context, record


def _parse_json(path: str, evidence_id: str, captured_at: datetime) -> list[Observation]:
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    observations = []
    for context, original in _json_records(document):
        record = dict(original)
        category = _category(record.get("record_type"), context.get("collection"),
                             context.get("data_store"))
        if not category:
            continue
        system = _system(record.get("system") or context.get("data_store"), category,
                         context.get("data_store", ""))
        resource = str(record.get("resource_id") or "")
        if not resource:
            continue

        if "profile" in record and category == "USER_PROFILE":
            profile = record.get("profile")
            code = str(record.get("status_code") or "")
            if profile in (None, {}, "null") or code not in ("", "200"):
                observations.append(Observation(
                    evidence_id, captured_at, captured_at, system, resource, category,
                    "ABSENT", False, location=_location(category),
                    detail=context.get("collection", "")))
                continue
            if isinstance(profile, dict):
                record = {**record, **profile}
        document_body = record.get("document")
        if isinstance(document_body, dict):
            record = {**record, **document_body}

        hits = record.get("hits")
        if isinstance(hits, dict):
            documents = hits.get("documents") or []
            total = hits.get("total")
            total = int(total) if isinstance(total, (int, float)) else len(documents)
            if total > 0 and documents and isinstance(documents[0], dict):
                record = {**documents[0], **record}
            state = "PRESENT" if total > 0 else "ABSENT"
        elif isinstance(hits, str) and hits.strip().isdigit():
            state = "PRESENT" if int(hits) > 0 else "ABSENT"
        else:
            state = "PRESENT"

        if state == "PRESENT":
            if category == "BACKUP_ARCHIVE":
                state = ("ACTIVE" if str(record.get("restore_allowed")).lower() in ("1", "true")
                         else "BLOCKED")
            elif category == "DATA_FLOW":
                state = ("ACTIVE" if str(record.get("enabled")).lower() in ("1", "true")
                         else "DISABLED")
            elif str(record.get("result", "")).strip():
                state = _state(str(record["result"]))

        observed_raw = (record.get("observed_at") or record.get("recorded_at")
                        or record.get("created_at") or context.get("captured_at"))
        observed_at = identity.parse_time(observed_raw) if observed_raw else captured_at
        identifiers, refs = _split_identifiers(
            record.get(column) for column in _IDENTITY_COLUMNS)
        exposure = _exposure_for(category, record) if state == "PRESENT" else False
        observations.append(Observation(
            evidence_id=evidence_id, captured_at=captured_at, observed_at=observed_at,
            system_id=system, resource_id=resource, category=category, state=state,
            exposure=exposure, identifiers=frozenset(identifiers),
            user_refs=frozenset(refs), location=_location(category),
            detail=context.get("collection", "")))
    return observations


# --------------------------------------------------------------------------
# Ledger text (handover sheets, delivery ledgers)
# --------------------------------------------------------------------------

def _parse_ledger(path: str, evidence_id: str, captured_at: datetime) -> list[Observation] | None:
    """`time | system | resource | category | state | identity` rows."""
    text = _read_text(path)
    observations = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- ") and " | " not in stripped:
            continue
        parts = [p.strip() for p in _TOKEN_SPLIT.split(stripped.lstrip("- ").strip())]
        if len(parts) < 6:
            continue
        stamp, system, resource, category, state, subject = parts[:6]
        category = _category(category)
        if not category or not _RESOURCE_RE.search(resource):
            continue
        observed_at = identity.parse_time(stamp) if stamp else captured_at
        identifiers, refs = _split_identifiers([subject])
        token = state.strip().upper()
        canonical = _state(state)
        exposure = False
        if canonical == "PRESENT":
            if token == "IDENTIFIABLE":
                exposure = True
            elif category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                exposure = bool(identifiers or refs)
            elif category in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG"):
                exposure = bool(identifiers)
            elif category == "ACCOUNT_TOMBSTONE":
                exposure = bool(identifiers)
        observations.append(Observation(
            evidence_id, captured_at, observed_at, system, resource, category,
            canonical, exposure, frozenset(identifiers), frozenset(refs),
            _location(category), detail="ledger"))
    return observations or None


# --------------------------------------------------------------------------
# Logs: three syntaxes, one event vocabulary
# --------------------------------------------------------------------------

_SERVICE_CATEGORY = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "support_replica": "SUPPORT_MESSAGE",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "export_service": "USER_EXPORT",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "downstream_delivery_service": "EMAIL_DELIVERY_LOG",
    "marketing_platform": "MARKETING_PROFILE",
    "cache_service": "CACHE_ENTRY",
}


def _collect_pairs(text: str, target: dict[str, str]) -> None:
    for key, value, inner in _KV_PAIR.findall(text):
        target[key] = inner if value.startswith('"') else value


#: `2026-09-30T11:51:03Z requestId=tr-2263120 level=DEBUG function=profile_service message="..."`
_RUNTIME_LINE = re.compile(
    r"^(?:requestId=(?P<request>\S+)\s+)?level=(?P<level>\S+)\s+"
    r"(?:function=(?P<function>\S+)\s+)?message=\"(?P<body>.*)\"$")
_RUNTIME_INNER = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)="((?:[^"\\]|\\.)*)"')
#: `<15>1 node-1 account_service tr-7458912 - - level=DEBUG ...`
_SYSLOG_LINE = re.compile(
    r"^<\d+>\d+\s+(?P<node>\S+)\s+(?P<service>\S+)\s+(?P<trace>\S+)\s+-\s+-\s+(?P<body>.*)$")
#: `[DEBUG] [account_service] [tr-6074163] profile_lookup_completed: instance="..." ...`
_BRACKET_LINE = re.compile(
    r"^\[(?P<level>[A-Z]+)\]\s+\[(?P<service>[A-Za-z0-9_]+)\]\s+"
    r"(?:\[(?P<trace>[A-Za-z0-9_\-]+)\]\s+)?(?P<event>[a-z_]+):\s*(?P<body>.*)$")
#: `2026-07-03T07:51:32Z | DEBUG | security_service | tr-5156005 | event | k=v ...`
_PIPE_LINE = re.compile(r"^\|\s*(?P<level>[A-Z]+)\s*\|")


def _parse_log_line(line: str) -> dict | None:
    """Parse one log line in any of the six syntaxes the corpus uses."""
    line = line.strip()
    if not line:
        return None
    stamp_match = re.match(r"^(\S+?)Z?\s", line)
    if not stamp_match:
        return None
    stamp = stamp_match.group(1)
    rest = line[len(stamp_match.group(0)):].strip()

    record: dict[str, str] = {}

    if rest.startswith("{"):
        try:
            payload = json.loads(rest)
        except ValueError:
            return None
        record = {str(k): str(v) for k, v in payload.items()}
    elif _PIPE_LINE.match(rest):
        parts = [p.strip() for p in _TOKEN_SPLIT.split(rest.lstrip("|").strip())]
        if len(parts) < 5:
            return None
        record = {"level": parts[0], "service": parts[1], "trace_id": parts[2],
                  "event": parts[3].split(":")[0]}
        _collect_pairs(" ".join(parts[4:]), record)
    elif _BRACKET_LINE.match(rest):
        match = _BRACKET_LINE.match(rest)
        record = {"level": match.group("level"), "service": match.group("service"),
                  "event": match.group("event")}
        if match.group("trace"):
            record["trace_id"] = match.group("trace")
        _collect_pairs(match.group("body"), record)
    elif _SYSLOG_LINE.match(rest):
        match = _SYSLOG_LINE.match(rest)
        record = {"service": match.group("service"), "trace_id": match.group("trace")}
        _collect_pairs(match.group("body"), record)
    elif _RUNTIME_LINE.match(rest):
        # the message body is itself an escaped key=value payload
        match = _RUNTIME_LINE.match(rest)
        record = {"level": match.group("level")}
        if match.group("function"):
            record["function"] = match.group("function")
        if match.group("request"):
            record["trace_id"] = match.group("request")
        for key, value in _RUNTIME_INNER.findall(match.group("body").replace('\\"', '"')):
            record.setdefault(key, value.replace('\\"', '"'))
    else:
        _collect_pairs(rest, record)
        colon = re.match(r"([a-z_]+):", rest)
        if colon and "event" not in record:
            record["event"] = colon.group(1)

    if "event" not in record:
        return None
    try:
        record["_time"] = identity.parse_time(stamp).isoformat()
    except ValueError:
        return None
    return record


def _log_state(record: dict) -> str:
    if "result" in record and record["result"].lower() in ("hit", "miss"):
        return "PRESENT" if record["result"].lower() == "hit" else "ABSENT"
    if "rows" in record and record["rows"].isdigit():
        return "PRESENT" if int(record["rows"]) > 0 else "ABSENT"
    if "http_status" in record and record["http_status"].isdigit():
        return "PRESENT" if int(record["http_status"]) == 200 else "ABSENT"
    if "marker_found" in record:
        return "PRESENT" if record["marker_found"].lower() == "true" else "ABSENT"
    if "archive_present" in record:
        return "PRESENT" if record["archive_present"].lower() == "true" else "ABSENT"
    if "result" in record and record["result"].upper() in _STATE_BY_TOKEN:
        return _state(record["result"])
    return "PRESENT"


#: events that request work or describe infrastructure, not record state
_NOISE_EVENTS = frozenset({
    "connection_acquired", "dependency_retry", "dependency_recovered", "cache_lookup",
    "lease_extended", "consumer_lag", "flag_snapshot_loaded", "slow_call_rate",
    "batch_started", "checkpoint_saved", "thumbnail_failed", "delivery_abandoned",
    "export_started", "cache_refresh", "deletion_marker_check",
})


def _emit_log_observation(record: dict, context: dict, evidence_id: str,
                          captured_at: datetime) -> Observation | None:
    event = record.get("event", "")
    if event.endswith("_started") or event in _NOISE_EVENTS:
        return None
    resource = record.get("resource_id") or record.get("lookup_value")
    if not resource:
        return None
    service = record.get("service") or context.get("service", "")

    category = _category(record.get("record_type"))
    if not category:
        if event.startswith(("contact_lookup", "contact_query")):
            # a legacy contact index keyed by hash or secondary address: the whole
            # row is a secondary identifier, not a message or a profile
            category = "SECONDARY_IDENTIFIER"
        elif "restore" in event or "backup" in service:
            category = "BACKUP_ARCHIVE"
        elif "connector" in event or "flow" in event or service == "integration_service":
            category = "DATA_FLOW"
        elif "export" in event:
            category = "USER_EXPORT"
        elif "attachment" in event:
            category = "SUPPORT_ATTACHMENT"
        else:
            category = (_SERVICE_CATEGORY.get(service, "")
                        or _category_by_resource(str(resource)))
    if not category:
        category = _category_by_resource(str(resource))

    ref_system = record.get("system") if record.get("record_type") else None
    system = _system(ref_system, category, service)

    state = _log_state(record)
    if category == "BACKUP_ARCHIVE":
        if "restore_allowed" in record:
            state = ("ACTIVE" if record["restore_allowed"].lower() == "true" else "BLOCKED")
        elif "eligible" in record:
            state = ("ACTIVE" if record["eligible"].lower() == "true"
                     and record.get("deletion_block", "false").lower() != "true"
                     else "BLOCKED")
        elif state == "PRESENT":
            state = "BLOCKED"
    elif category == "DATA_FLOW":
        if "enabled" in record:
            state = "ACTIVE" if record["enabled"].lower() == "true" else "DISABLED"
    elif category == "USER_EXPORT" and "download_available" in record:
        state = ("PRESENT" if record["download_available"].lower() == "true" else "ABSENT")

    merged = {**context, **record}
    identifiers, refs = _split_identifiers(
        merged.get(column) for column in _IDENTITY_COLUMNS + ("lookup_key", "subject_key",
                                                              "correlation_key", "matched_value"))
    if record.get("detector") == "direct_identifier" and record.get("matched_value"):
        exposure = True
    else:
        exposure = _exposure_for(category, merged) if state == "PRESENT" else False
    # a stored email hash is still an attributable identifier for analytics
    if (not exposure and state == "PRESENT"
            and category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY")
            and _HASH_RE.fullmatch((record.get("correlation_key") or "").strip().lower())):
        exposure = True
    if not category:
        return None
    if "message_pii_scan" in event or "attachment_pii_scan" in event:
        exposure = True

    observed_at = identity.parse_time(record["_time"]) if record.get("_time") else captured_at
    return Observation(
        evidence_id=evidence_id, captured_at=captured_at, observed_at=observed_at,
        system_id=system, resource_id=str(resource), category=category, state=state,
        exposure=exposure, identifiers=frozenset(identifiers), user_refs=frozenset(refs),
        location=_location(category), detail=event)


def _parse_log(path: str, evidence_id: str, captured_at: datetime) -> list[Observation]:
    records = [r for r in (_parse_log_line(line) for line in
                           _read_text(path).splitlines()) if r]
    observations = []
    context_by_trace: dict[str, dict] = defaultdict(dict)
    for record in records:
        trace = record.get("trace_id") or record.get("trace") or ""
        if trace:
            for key, value in record.items():
                if key in ("lookup_key", "subject_key", "matched_value", "correlation_key",
                           "service", "email", "phone", "email_hash", "customer_email",
                           "requester_email", "subject_reference", "customer_reference"):
                    context_by_trace[trace].setdefault(key, value)
    for record in records:
        trace = record.get("trace_id") or record.get("trace") or ""
        observation = _emit_log_observation(record, context_by_trace.get(trace, {}),
                                            evidence_id, captured_at)
        if observation:
            observations.append(observation)
    return observations


# --------------------------------------------------------------------------
# PDF business documents
# --------------------------------------------------------------------------

_PDF_CATEGORY = (
    ("delivery address correction", "SUPPORT_ATTACHMENT"),
    ("support reference", "SUPPORT_ATTACHMENT"),
    ("disputed orders and tax records", "LEGAL_HOLD_RECORD"),
    ("compliance journal", "SECURITY_AUDIT_LOG"),
    ("customer statement", "USER_EXPORT"),
)


def _parse_pdf(path: str, evidence_id: str, captured_at: datetime) -> list[Observation]:
    if not shutil.which("pdftotext"):
        return []
    result = subprocess.run(["pdftotext", "-layout", path, "-"],
                            capture_output=True, text=True, check=False)
    text = result.stdout or ""
    lowered = text.lower()
    category = next((cat for needle, cat in _PDF_CATEGORY if needle in lowered), "")
    if not category:
        return []

    resources = []
    for line in text.splitlines():
        if "|" in line:
            for match in _RESOURCE_RE.finditer(line):
                resources.append(match.group(0))
    if not resources:
        resources = list(dict.fromkeys(m.group(0) for m in _RESOURCE_RE.finditer(text)))
    if not resources:
        return []

    identifiers, refs = _split_identifiers(
        _EMAIL_RE.findall(text) + _PHONE_RE.findall(text) + _USER_RE.findall(text)
        + _HASH_RE.findall(text.lower()))
    # user_NN regex returns bare digits through findall, add the full token
    for number in _USER_RE.findall(text):
        refs.add(f"user_{number}")

    observations = []
    for resource in dict.fromkeys(resources):
        system = _system(None, category)
        observations.append(Observation(
            evidence_id, captured_at, captured_at, system, resource, category,
            "PRESENT", bool(identifiers or refs), frozenset(identifiers),
            frozenset(refs), _location(category), detail="pdf"))
    return observations


# --------------------------------------------------------------------------
# Index
# --------------------------------------------------------------------------

_ADAPTERS = {
    ".sql": _parse_sql,
    ".json": _parse_json,
    ".log": _parse_log,
    ".txt": _parse_ledger,
    ".pdf": _parse_pdf,
}


class EvidenceIndex:
    """Parse the whole manifest once, then answer per-case questions."""

    def __init__(self, dataset_dir: str, manifest: Sequence[dict]):
        self.dataset_dir = dataset_dir
        self.manifest = {row["file_id"]: row for row in manifest}
        self.captured_at = {fid: identity.parse_time(row["captured_at"])
                            for fid, row in self.manifest.items()}
        self.observations: list[Observation] = []
        self.unparsed: list[str] = []      # could not be read at all
        self.empty: list[str] = []         # read fine, held no record state
        self.files_by_kind: dict[str, int] = defaultdict(int)

        for file_id in sorted(self.manifest):
            row = self.manifest[file_id]
            path = os.path.join(dataset_dir, row["file_path"])
            extension = os.path.splitext(path)[1].lower()
            adapter = _ADAPTERS.get(extension)
            self.files_by_kind[extension or "?"] += 1
            if adapter is None:
                self.unparsed.append(file_id)
                continue
            try:
                found = adapter(path, file_id, self.captured_at[file_id])
            except Exception:                      # a malformed file must not abort the run
                self.unparsed.append(file_id)
                continue
            if not found:
                # e.g. an inventory snapshot that lists tables but no rows
                self.empty.append(file_id)
                continue
            self.observations.extend(found)

        self.observations.sort(key=lambda o: (o.captured_at, o.evidence_id,
                                              o.system_id, o.resource_id))

    # -- queries ---------------------------------------------------------

    def subject_observations(self, emails: Iterable[str], phones: Iterable[str],
                             hashes: Iterable[str], user_refs: Iterable[str],
                             cutoff: datetime) -> list[Observation]:
        """Observations that mention the subject and were captured by `cutoff`."""
        wanted: set[str] = set()
        for email in emails:
            wanted.add(identity.normalize_email(email))
        for phone in phones:
            wanted.add("phone:" + identity.normalize_phone(phone))
        for digest in hashes:
            wanted.add("hash:" + identity.normalize_hash(digest))
        refs = {ref for ref in user_refs if ref}

        matched = []
        for observation in self.observations:
            if observation.captured_at > cutoff:
                continue
            if observation.identifiers & wanted or observation.user_refs & refs:
                matched.append(observation)
        return matched

    def stats(self) -> dict:
        by_state: dict[str, int] = defaultdict(int)
        by_category: dict[str, int] = defaultdict(int)
        for observation in self.observations:
            by_state[observation.state] += 1
            by_category[observation.category] += 1
        return {
            "files": len(self.manifest),
            "files_by_kind": dict(sorted(self.files_by_kind.items())),
            "observations": len(self.observations),
            "unparsed": len(self.unparsed),
            "by_state": dict(sorted(by_state.items())),
            "by_category": dict(sorted(by_category.items())),
        }
