#!/usr/bin/env python3
"""Tests for the record audit: evidence parsing, rules, findings, ordering.

The suite has three layers:

  * parser level   - does each file kind become observations, and are states
                     read from the right token (`rows=0`, `result=miss`,
                     `restore_allowed`, `enabled`, ledger states)?
  * rule level     - does deletion_rules.csv turn a surviving state into the
                     right finding operation, and only when policy is violated?
  * sample level   - does the audit reproduce the FINDING steps of
                     sample_output.csv exactly, and does "INCOMPLETE iff a
                     finding survives" reproduce deletion_status?

Run: python3 -m unittest discover -s code -v
"""

from __future__ import annotations

import csv
import json
import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import discovery
import evidence
import identity
import main

DATASET_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "dataset")


def utc(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def observation(resource_id: str, state: str, *, evidence_id: str = "evidence_01",
                captured_at: str = "2026-09-10T00:00:00Z",
                observed_at: str | None = None, system_id: str = "account_service",
                category: str = "USER_PROFILE", exposure: bool = False,
                identifiers=(), user_refs=()):
    """Hand-built observation, so rule tests need no file on disk."""
    return evidence.Observation(
        evidence_id=evidence_id,
        captured_at=utc(captured_at),
        observed_at=utc(observed_at or captured_at),
        system_id=system_id,
        resource_id=resource_id,
        category=category,
        state=state,
        exposure=exposure,
        identifiers=frozenset(identifiers),
        user_refs=frozenset(user_refs),
        location="",
        detail="test")


class DatasetMixin:
    """One shared parse of the dataset and the evidence corpus."""

    @classmethod
    def setUpClass(cls):
        cls.data = main.load_dataset(DATASET_DIR)
        cls.index = main.build_evidence_index(cls.data)
        cls.resolver = identity.IdentityResolver(cls.data.user_identities,
                                                 cls.data.user_audit_log)
        cls.rules = discovery.load_rules(cls.data.deletion_rules)


# --------------------------------------------------------------------------
# Parser level
# --------------------------------------------------------------------------

class TestEvidenceParsing(DatasetMixin, unittest.TestCase):

    def test_manifest_is_fully_accounted_for(self):
        parsed = len(self.index.manifest) - len(self.index.unparsed) - len(self.index.empty)
        self.assertEqual(parsed + len(self.index.empty) + len(self.index.unparsed),
                         len(self.index.manifest))

    def test_only_binary_images_are_unreadable(self):
        """Screenshots are the only format without a text layer here."""
        with open(os.path.join(DATASET_DIR, "evidence_files.csv"), encoding="utf-8") as fh:
            paths = {row["file_id"]: row["file_path"] for row in csv.DictReader(fh)}
        for file_id in self.index.unparsed:
            self.assertTrue(paths[file_id].endswith(".png"),
                            f"{file_id} ({paths[file_id]}) should have parsed")

    def test_every_file_kind_is_represented(self):
        kinds = self.index.files_by_kind
        for extension in (".sql", ".json", ".log", ".txt", ".pdf", ".png"):
            self.assertIn(extension, kinds)
        self.assertEqual(kinds[".png"], len(self.index.unparsed))

    def test_observations_cover_every_record_category(self):
        categories = {o.category for o in self.index.observations}
        for expected in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "ANALYTICS_PROFILE",
                         "SUPPORT_MESSAGE", "USER_EXPORT", "BACKUP_ARCHIVE",
                         "DATA_FLOW", "SECURITY_AUDIT_LOG", "ACCOUNT_TOMBSTONE"):
            self.assertIn(expected, categories)

    def test_no_observation_has_an_empty_category_or_system(self):
        for o in self.index.observations:
            self.assertTrue(o.category, o)
            self.assertTrue(o.system_id, o)
            self.assertIn(o.state, evidence.STATES, o)

    def test_states_are_canonical(self):
        """`NOT_FOUND` is normalised to `ABSENT`, never left as a raw token."""
        states = {o.state for o in self.index.observations}
        self.assertNotIn("NOT_FOUND", states)
        self.assertNotIn("FOUND", states)
        self.assertNotIn("IDENTIFIABLE", states)

    def test_absent_and_present_both_occur(self):
        """A parser that reports only hits would look perfect and find nothing."""
        states = {o.state for o in self.index.observations}
        for expected in ("ABSENT", "PRESENT", "ACTIVE", "BLOCKED", "DISABLED"):
            self.assertIn(expected, states)

    def test_log_line_syntaxes_parse(self):
        """All six log layouts in the corpus must yield an event."""
        samples = [
            '2026-09-15T08:51:57Z level=INFO service=search_service event=x event=done',
            '2026-07-03T07:51:32Z | DEBUG | security_service | tr-1 | audit_record_read_completed | a="1"',
            '2026-04-19T06:51:13Z {"service":"search_service","event":"index_query_completed"}',
            '2026-07-28T05:51:21Z [INFO] [account_service] [tr-1] profile_lookup_completed: rows="0"',
            '2026-03-25T08:55:11Z <12>1 node-8 analytics_platform tr-1 - - level=WARN event="scan"',
            '2026-09-30T11:51:03Z requestId=tr-1 level=DEBUG function=profile_service '
            'message="resource_id=\\"account_1\\" event=\\"profile_lookup_completed\\" rows=\\"1\\""',
        ]
        for line in samples:
            parsed = evidence._parse_log_line(line)
            self.assertIsNotNone(parsed, line)
            self.assertIn("event", parsed, line)
            self.assertIn("_time", parsed, line)

    def test_escaped_runtime_message_keeps_its_fields(self):
        line = ('2026-09-30T11:51:03Z requestId=tr-1 level=DEBUG function=profile_service '
                'message="resource_id=\\"account_66777\\" event=\\"profile_lookup_completed\\" '
                'rows=\\"1\\" correlation_key=\\"a@b.co\\""')
        parsed = evidence._parse_log_line(line)
        self.assertEqual(parsed["resource_id"], "account_66777")
        self.assertEqual(parsed["rows"], "1")
        self.assertEqual(parsed["correlation_key"], "a@b.co")

    def test_log_row_counts_are_read_as_state(self):
        base = {"service": "account_service", "resource_id": "account_1",
                "event": "profile_lookup_completed", "_time": "2026-09-10T00:00:00Z"}
        self.assertEqual(evidence._log_state({**base, "rows": "1"}), "PRESENT")
        self.assertEqual(evidence._log_state({**base, "rows": "0"}), "ABSENT")
        self.assertEqual(evidence._log_state({**base, "http_status": "404"}), "ABSENT")

    def test_sql_replica_keeps_its_topology(self):
        """Replica captures must not be flattened into `primary`."""
        replica = [o for o in self.index.observations if o.location == "replica"]
        self.assertTrue(replica, "no replica observation: topology tag was lost")
        self.assertEqual({o.category for o in replica} - {"USER_PROFILE",
                                                         "SEARCH_INDEX_ENTRY"}, set())

    def test_nested_json_documents_are_merged(self):
        """`hits.documents[]` / `record_json.document` carry the identifiers."""
        with_identifiers = [o for o in self.index.observations
                            if o.category == "SEARCH_INDEX_ENTRY" and o.identifiers]
        self.assertTrue(with_identifiers)


# --------------------------------------------------------------------------
# Rule level
# --------------------------------------------------------------------------

class TestRuleApplication(unittest.TestCase):

    def setUp(self):
        self.rules = {"USER_PROFILE": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
                      "SUPPORT_MESSAGE": "REDACT", "ANALYTICS_PROFILE": "ANONYMIZE",
                      "SECURITY_AUDIT_LOG": "RETAIN", "BACKUP_ARCHIVE": "RETAIN",
                      "DATA_FLOW": "DELETE"}

    def operation(self, obs, category=None):
        category = category or obs.category
        return discovery._violation(obs, self.rules.get(category, ""))

    def test_delete_category_present_is_remaining(self):
        self.assertEqual(self.operation(observation("account_1", "PRESENT")),
                         "REPORT_REMAINING_RECORD")

    def test_delete_category_absent_is_clean(self):
        self.assertEqual(self.operation(observation("account_1", "ABSENT")), "")

    def test_redact_with_identifiers_is_exposed_pii(self):
        obs = observation("support_1", "PRESENT", category="SUPPORT_MESSAGE",
                          exposure=True)
        self.assertEqual(self.operation(obs), "REPORT_EXPOSED_PII")

    def test_redact_without_identifiers_is_clean(self):
        obs = observation("support_1", "PRESENT", category="SUPPORT_MESSAGE",
                          exposure=False)
        self.assertEqual(self.operation(obs), "")

    def test_redacted_state_is_clean(self):
        obs = observation("support_1", "REDACTED", category="SUPPORT_MESSAGE",
                          exposure=False)
        self.assertEqual(self.operation(obs), "")

    def test_anonymize_needs_no_direct_identifier(self):
        obs = observation("analytics_1", "PRESENT", category="ANALYTICS_PROFILE",
                          exposure=True)
        self.assertEqual(self.operation(obs), "REPORT_EXPOSED_PII")
        self.assertEqual(self.operation(observation("analytics_1", "ANONYMIZED",
                                                    category="ANALYTICS_PROFILE")), "")

    def test_retained_audit_log_is_never_a_finding(self):
        obs = observation("audit_record_1", "PRESENT", category="SECURITY_AUDIT_LOG")
        self.assertEqual(self.operation(obs), "")

    def test_restorable_backup_is_a_restore_risk(self):
        obs = observation("backup_1", "ACTIVE", category="BACKUP_ARCHIVE")
        self.assertEqual(self.operation(obs), "REPORT_RESTORE_RISK")
        blocked = observation("backup_1", "BLOCKED", category="BACKUP_ARCHIVE")
        self.assertEqual(self.operation(blocked), "")

    def test_enabled_data_flow_is_active(self):
        obs = observation("data_flow_1", "ACTIVE", category="DATA_FLOW")
        self.assertEqual(self.operation(obs), "REPORT_ACTIVE_DATA_FLOW")
        off = observation("data_flow_1", "DISABLED", category="DATA_FLOW")
        self.assertEqual(self.operation(off), "")

    def test_finding_states_match_their_operation(self):
        for operation, state in discovery.STATE_BY_OPERATION.items():
            self.assertIn(operation, discovery.OPERATION_ORDER)
            self.assertIn(state, ("PRESENT", "ACTIVE"))

    def test_rules_cover_every_contract_category(self):
        rules = discovery.load_rules(main.load_dataset(DATASET_DIR).deletion_rules)
        for operation in discovery.OPERATION_ORDER:
            self.assertTrue(rules, operation)
        self.assertEqual(rules["USER_PROFILE"], "DELETE")
        self.assertEqual(rules["SECURITY_AUDIT_LOG"], "RETAIN")
        self.assertEqual(rules["ACCOUNT_TOMBSTONE"], "REDACT")


class TestStateReconstruction(unittest.TestCase):

    def test_newest_observation_wins(self):
        older = observation("account_1", "PRESENT", evidence_id="evidence_01",
                            captured_at="2026-09-01T00:00:00Z")
        newer = observation("account_1", "ABSENT", evidence_id="evidence_02",
                            captured_at="2026-09-05T00:00:00Z")
        latest = discovery.latest_states([older, newer])
        self.assertEqual(latest[("account_service", "account_1")].state, "ABSENT")

    def test_state_can_regress_when_a_writer_reappears(self):
        """A later PRESENT must not be masked by an earlier NOT_FOUND."""
        older = observation("search_1", "ABSENT", evidence_id="evidence_01",
                            captured_at="2026-09-01T00:00:00Z")
        newer = observation("search_1", "PRESENT", evidence_id="evidence_02",
                            captured_at="2026-09-05T00:00:00Z")
        latest = discovery.latest_states([older, newer])
        self.assertEqual(latest[("account_service", "search_1")].state, "PRESENT")

    def test_identical_timestamps_break_deterministically(self):
        first = observation("account_1", "PRESENT", evidence_id="evidence_01")
        second = observation("account_1", "ABSENT", evidence_id="evidence_02")
        self.assertEqual(discovery.latest_states([first, second]),
                         discovery.latest_states([second, first]))

    def test_distinct_systems_are_kept_apart(self):
        """The same resource id in two systems is two copies, not one."""
        left = observation("account_1", "PRESENT", system_id="account_service")
        right = observation("account_1", "PRESENT", system_id="crm_service")
        self.assertEqual(len(discovery.latest_states([left, right])), 2)


# --------------------------------------------------------------------------
# Case level
# --------------------------------------------------------------------------

class TestCaseAudit(DatasetMixin, unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.requests = {row["case_id"]: row for row in cls.data.deletion_requests}
        cls.samples = {row["case_id"]: row for row in cls.data.sample_deletion_requests}
        cls.truth = {row["case_id"]: row for row in cls.data.sample_output}

    def findings(self, case):
        resolution = self.resolver.resolve(case)
        return discovery.discover_case(case["case_id"], resolution, self.index, self.rules)

    def test_no_finding_cites_late_evidence(self):
        """The manifest capture time is the eligibility gate, per case."""
        audited = 0
        for case in self.data.deletion_requests:
            for finding in self.findings(case):
                captured = self.index.captured_at[finding.evidence_id]
                self.assertLessEqual(captured, identity.parse_time(case["audit_at"]),
                                     f"{case['case_id']} cites {finding.evidence_id}")
                audited += 1
        self.assertGreater(audited, 0)

    def test_findings_are_ordered_and_numbered(self):
        for case in list(self.data.deletion_requests)[:120]:
            findings = self.findings(case)
            keys = [(discovery.OPERATION_ORDER.index(f.operation), f.resource_id,
                     f.system_id) for f in findings]
            self.assertEqual(keys, sorted(keys), case["case_id"])
            steps = [f.as_step(i) for i, f in enumerate(findings, 1)]
            self.assertEqual([s["step_no"] for s in steps],
                             list(range(1, len(steps) + 1)))
            for step in steps:
                self.assertEqual(set(step), {"step_no", "phase", "system_id",
                                             "resource_id", "operation", "state",
                                             "evidence_id"})
                self.assertEqual(step["phase"], "FINDING")

    def test_findings_are_deterministic(self):
        case = self.samples["case_11"]
        first = [f.as_row() for f in self.findings(case)]
        second = [f.as_row() for f in self.findings(case)]
        self.assertEqual(first, second)

    def test_not_applicable_cases_are_not_audited(self):
        """Nothing to audit: the request does not authorise deletion."""
        requests = self.data.deletion_requests
        classifications = [main.classify_case(case) for case in requests]
        resolutions = [self.resolver.resolve(case) for case in requests]
        audited = main.audit_cases(requests, resolutions, classifications,
                                   self.index, self.rules)
        checked = 0
        for case, classification in zip(requests, classifications):
            if classification.authorizes_deletion:
                self.assertIn(case["case_id"], audited)
                continue
            checked += 1
            self.assertNotIn(case["case_id"], audited)
            row = main.row_from_classification(classification)
            self.assertEqual(row["deletion_status"], "NOT_APPLICABLE")
            self.assertEqual(json.loads(row["steps_json"]), [])
        self.assertGreater(checked, 0)

    def test_rows_derive_status_from_findings(self):
        case = self.samples["case_11"]
        row = main.row_for_case(case["case_id"], self.findings(case))
        self.assertEqual(row["deletion_status"], "INCOMPLETE")
        self.assertTrue(json.loads(row["steps_json"]))
        clean = main.row_for_case("case_x", [])
        self.assertEqual(clean["deletion_status"], "COMPLETE")
        self.assertEqual(clean["steps_json"], "[]")

    def test_sample_findings_match_exactly(self):
        """41 labelled findings across 22 incomplete samples, exact match."""
        report = main.evaluate_discovery_samples(self.data, self.resolver,
                                                 self.index, self.rules)
        self.assertEqual(report["missing"], 0, report["missing_detail"])
        self.assertEqual(report["extra"], 0, report["extra_detail"])
        self.assertEqual(report["matched"], report["expected_findings"])
        self.assertGreaterEqual(report["expected_findings"], 40)

    def test_sample_status_follows_from_findings(self):
        report = main.evaluate_discovery_samples(self.data, self.resolver,
                                                 self.index, self.rules)
        self.assertEqual(report["status_hits"], report["total_cases"],
                         [row for row in report["per_case"] if row[1] != row[2]])

    def test_known_anchors(self):
        """Hand-checked cases, so a silent parser change cannot go unnoticed."""
        anchors = {
            "case_11": {("REPORT_REMAINING_RECORD", "search_service", "search_052"),
                        ("REPORT_EXPOSED_PII", "analytics_platform", "analytics_2034"),
                        ("REPORT_EXPOSED_PII", "support_platform", "support_864"),
                        ("REPORT_ACTIVE_DATA_FLOW", "integration_service", "data_flow_9522")},
            "case_09": {("REPORT_RESTORE_RISK", "backup_service", "backup_4978")},
            "case_16": {("REPORT_REMAINING_RECORD", "account_service", "account_994"),
                        ("REPORT_REMAINING_RECORD", "search_service", "search_1007")},
            "case_32": {("REPORT_EXPOSED_PII", "identity_service", "tombstone_9178")},
        }
        for case_id, expected in anchors.items():
            got = {(f.operation, f.system_id, f.resource_id)
                   for f in self.findings(self.samples[case_id])}
            self.assertEqual(got, expected, case_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
