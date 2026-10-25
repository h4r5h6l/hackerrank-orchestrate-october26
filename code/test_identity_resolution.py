#!/usr/bin/env python3
"""Tests for deterministic identity resolution (code/identity.py).

Run with either:
    python3 code/test_identity_resolution.py
    python3 -m unittest discover -s code -p 'test_*.py'

Everything asserted here is derived from participant-visible data in
``dataset/`` (the snapshot, the audit log, the requests and the public
samples). The synthetic cases at the bottom build tiny in-memory tables to
exercise the tie-break and time-window paths that the real dataset never
reaches, so a failure there is a logic bug rather than dataset drift.
"""

from __future__ import annotations

import csv
import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import identity  # noqa: E402  (path set above)
import main  # noqa: E402


def _load() -> main.Dataset:
    return main.load_dataset(main.DEFAULT_DATASET_DIR)


def _identity(user_id: str, email: str, phone: str = "+1 202 555 0100") -> dict:
    return {
        "user_id": user_id,
        "name": f"Person {user_id}",
        "email": email,
        "phone": phone,
        "email_hash": identity.email_hash(email),
        "updated_at": "2026-01-01T00:00:00Z",
    }


def _change(user_id: str, audit_id: str, field: str, old: str, new: str,
            when: str) -> dict:
    """One audit row with the same six columns as user_audit_log.csv."""
    return {
        "audit_id": audit_id,
        "user_id": user_id,
        "event_time": when,
        "field_name": field,
        "old_value": old,
        "new_value": new,
    }


def _case(case_id: str, email: str, requested_at: str, audit_at: str) -> dict:
    return {
        "case_id": case_id,
        "email": email,
        "requested_at": requested_at,
        "audit_at": audit_at,
        "reported_status": "COMPLETE",
        "reported_at": audit_at,
        "request_text": "please delete my data",
    }


class ResolverFixture(unittest.TestCase):
    """One resolver over the real dataset, shared by every read-only test."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.data = _load()
        cls.resolver = identity.IdentityResolver(
            cls.data.user_identities, cls.data.user_audit_log)
        cls.by_case = {c["case_id"]: c for c in cls.data.deletion_requests}
        cls.by_case.update({c["case_id"]: c for c in cls.data.sample_deletion_requests})


class TestDatasetInvariants(ResolverFixture):
    """The invariants the algorithm relies on must actually hold on load."""

    def test_no_subject_fails_integrity_checks(self) -> None:
        self.assertEqual(self.resolver.failed_users, {})

    def test_snapshot_hash_is_sha256_of_email(self) -> None:
        for row in self.data.user_identities:
            with self.subTest(user_id=row["user_id"]):
                self.assertEqual(row["email_hash"], identity.email_hash(row["email"]))

    def test_audit_chain_is_continuous(self) -> None:
        """Each old_value equals the previous new_value, per user and field."""
        events: dict[tuple[str, str], list[dict]] = {}
        for row in self.data.user_audit_log:
            events.setdefault((row["user_id"], row["field_name"]), []).append(row)
        for key, rows in events.items():
            rows.sort(key=lambda r: (identity.parse_time(r["event_time"]),
                                     identity.natural_audit_key(r["audit_id"])))
            field = key[1]
            for previous, current in zip(rows, rows[1:]):
                self.assertEqual(
                    identity.normalize_field(field, previous["new_value"]),
                    identity.normalize_field(field, current["old_value"]),
                    f"{key}")

    def test_one_identifier_has_one_owner(self) -> None:
        """Cross-user sharing would make the link ambiguous; report, don't merge."""
        owners: dict[str, set[str]] = {}
        for row in self.data.user_identities:
            owners.setdefault(identity.normalize_email(row["email"]), set()).add(row["user_id"])
        for row in self.data.user_audit_log:
            if row["field_name"] != "email":
                continue
            for value in (row["old_value"], row["new_value"]):
                owners.setdefault(identity.normalize_email(value), set()).add(row["user_id"])
        shared = sorted((value, sorted(uids)) for value, uids in owners.items()
                        if value and len(uids) > 1)
        self.assertEqual(shared, [])


class TestResolutionOnDataset(ResolverFixture):
    """Every request must land on exactly one person and their full alias set."""

    EXPECTED_CASES = 518

    def test_every_request_resolves(self) -> None:
        resolutions = [self.resolver.resolve(c) for c in self.data.deletion_requests]
        self.assertEqual(len(resolutions), self.EXPECTED_CASES)
        self.assertEqual({r.outcome for r in resolutions}, {"RESOLVED"})
        self.assertEqual(sum(1 for r in resolutions if r.person_id),
                         self.EXPECTED_CASES)

    def test_distinct_people_count(self) -> None:
        people = {self.resolver.resolve(c).person_id for c in self.data.deletion_requests}
        self.assertEqual(len(people), 517)

    def test_snapshot_and_history_are_both_used(self) -> None:
        routes = [self.resolver.resolve(c).subject.resolved_by
                  for c in self.data.deletion_requests]
        self.assertEqual(routes.count("snapshot"), 418)
        self.assertEqual(routes.count("history"), 100)

    def test_no_alias_is_owned_by_two_people(self) -> None:
        for case in self.data.deletion_requests:
            resolution = self.resolver.resolve(case)
            aliases = resolution.alias_set(resolution.audit_at)
            for email in aliases["email"]:
                with self.subTest(case_id=case["case_id"], email=email):
                    self.assertEqual(self.resolver.owners_of(email),
                                     {resolution.person_id})

    def test_audit_at_never_drops_a_known_version(self) -> None:
        """A cutoff may exclude later versions, never earlier ones."""
        for case in self.data.deletion_requests:
            resolution = self.resolver.resolve(case)
            full = resolution.alias_set(None)
            cutoff = resolution.alias_set(resolution.audit_at)
            for field in identity.FIELDS:
                with self.subTest(case_id=case["case_id"], field=field):
                    self.assertLessEqual(set(cutoff[field]), set(full[field]))

    def test_request_email_is_always_in_the_alias_set(self) -> None:
        for case in self.data.deletion_requests:
            resolution = self.resolver.resolve(case)
            quoted = identity.normalize_email(case["email"])
            known = {identity.normalize_email(e)
                     for e in resolution.alias_set(None)["email"]}
            with self.subTest(case_id=case["case_id"]):
                self.assertIn(quoted, known)


class TestAliasWindows(unittest.TestCase):
    """Explicit examples: multi-hop history, superseded values, casefolding."""

    @classmethod
    def setUpClass(cls) -> None:
        data = _load()
        cls.data = data
        cls.resolver = identity.IdentityResolver(data.user_identities, data.user_audit_log)
        cls.by_case = {c["case_id"]: c for c in data.deletion_requests}
        cls.by_case.update({c["case_id"]: c for c in data.sample_deletion_requests})

    def test_two_hop_history_recovers_three_emails(self) -> None:
        resolution = self.resolver.resolve(self.by_case["case_37"])
        self.assertEqual(resolution.person_id, "user_35")
        self.assertEqual(resolution.subject.resolved_by, "history")
        self.assertEqual(len(resolution.alias_set(resolution.audit_at)["email"]), 3)

    def test_superseded_values_stay_in_scope(self) -> None:
        """Old systems keep old identifiers, so older versions are never dropped."""
        resolution = self.resolver.resolve(self.by_case["case_10"])
        emails = resolution.alias_set(resolution.audit_at)["email"]
        self.assertEqual(len(emails), 3)
        quoted = identity.normalize_email(self.by_case["case_10"]["email"])
        self.assertIn(quoted, emails)

    def test_two_phones_are_both_recovered(self) -> None:
        resolution = self.resolver.resolve(self.by_case["case_34"])
        self.assertEqual(resolution.person_id, "user_11")
        self.assertEqual(len(resolution.alias_set(resolution.audit_at)["phone"]), 2)

    def test_request_email_is_casefolded(self) -> None:
        raw = self.by_case["case_40"]["email"]
        resolution = self.resolver.resolve(self.by_case["case_40"])
        self.assertNotEqual(raw, raw.casefold())  # the sample really is mixed case
        self.assertEqual(resolution.person_id, "user_38")

    def test_same_email_two_audit_times_shares_one_person(self) -> None:
        first = self.resolver.resolve(self.by_case["case_33"])
        second = self.resolver.resolve(self.by_case["case_52"])
        self.assertEqual(first.person_id, second.person_id)
        self.assertTrue(first.person_id)


class TestSyntheticEdgeCases(unittest.TestCase):
    """Shapes the real dataset does not contain, so the guard rails get tested."""

    def _resolver(self) -> tuple[identity.IdentityResolver, dict]:
        identities = [
            _identity("user_a", "shared@example.com"),
            _identity("user_b", "shared@example.com"),
        ]
        audit = [_change("user_b", "aud_1", "email",
                         "before@example.com", "shared@example.com",
                         "2026-05-01T00:00:00Z")]
        return identity.IdentityResolver(identities, audit), {
            "early": _case("c_early", "Shared@Example.com",
                           "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
            "late": _case("c_late", "shared@example.com",
                          "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"),
        }

    def test_shared_value_tie_breaks_on_request_time(self) -> None:
        resolver, cases = self._resolver()
        early = resolver.resolve(cases["early"])
        self.assertEqual(early.outcome, "RESOLVED")
        self.assertEqual(early.person_id, "user_a")
        self.assertEqual(early.subject.resolved_by, "tiebreak")

    def test_shared_value_stays_ambiguous_when_both_are_live(self) -> None:
        resolver, cases = self._resolver()
        late = resolver.resolve(cases["late"])
        self.assertEqual(late.outcome, "AMBIGUOUS")
        self.assertIsNone(late.subject)
        self.assertEqual(late.person_id, "")

    def test_unknown_email_is_unresolved_not_guessed(self) -> None:
        resolver, _ = self._resolver()
        resolution = resolver.resolve(
            _case("c_unknown", "nobody@example.com",
                  "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"))
        self.assertEqual(resolution.outcome, "UNRESOLVED")
        self.assertEqual(resolution.reason, "'nobody@example.com' appears in "
                                            "neither the snapshot nor the audit log")

    def test_empty_email_is_unresolved(self) -> None:
        resolver, _ = self._resolver()
        resolution = resolver.resolve(
            _case("c_blank", "   ", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"))
        self.assertEqual(resolution.outcome, "UNRESOLVED")

    def test_missing_cutoff_keeps_every_version(self) -> None:
        """audit_at is optional; absent means 'no upper bound' on the alias set."""
        resolver, cases = self._resolver()
        historic = _case("c_old", "before@example.com",
                         "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
        with_cutoff = resolver.resolve(historic)
        self.assertEqual(with_cutoff.person_id, "user_b")
        self.assertEqual(len(with_cutoff.alias_set(with_cutoff.audit_at)["email"]), 1)

        no_cutoff = dict(historic)
        no_cutoff.pop("audit_at")
        uncapped = resolver.resolve(no_cutoff)
        self.assertIsNone(uncapped.audit_at)
        self.assertEqual(len(uncapped.alias_set(None)["email"]), 2)

    def test_failed_user_does_not_abort_construction(self) -> None:
        identities = [_identity("user_ok", "ok@example.com"),
                      _identity("user_bad", "bad@example.com")]
        # Snapshot hash deliberately mismatches sha256(email).
        identities[1]["email_hash"] = "0" * 64
        resolver = identity.IdentityResolver(identities, [])
        self.assertIn("user_bad", resolver.failed_users)
        resolution = resolver.resolve(
            _case("c_bad", "bad@example.com", "2026-09-01T00:00:00Z",
                  "2026-09-01T00:00:00Z"))
        self.assertEqual(resolution.outcome, "UNRESOLVED")
        self.assertIn("failed integrity checks", resolution.reason)


class TestDeterminism(ResolverFixture):
    """Same input, same bytes - the submission must be reproducible."""

    def test_two_resolvers_produce_identical_rows(self) -> None:
        other = identity.IdentityResolver(self.data.user_identities,
                                          self.data.user_audit_log)
        first = identity.resolution_rows(self.data.deletion_requests, self.resolver)
        second = identity.resolution_rows(self.data.deletion_requests, other)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 518)

    def test_csv_serialisation_is_byte_identical(self) -> None:
        rows = identity.resolution_rows(self.data.deletion_requests, self.resolver)
        with tempfile.TemporaryDirectory() as tmp:
            paths = [os.path.join(tmp, "one.csv"), os.path.join(tmp, "two.csv")]
            identity.write_resolution_csv(paths[0], rows)
            identity.write_resolution_csv(paths[1], rows)
            with open(paths[0], "rb") as handle:
                first = hashlib.sha256(handle.read()).hexdigest()
            with open(paths[1], "rb") as handle:
                second = hashlib.sha256(handle.read()).hexdigest()
            with open(paths[0], encoding="utf-8", newline="") as handle:
                header = next(csv.reader(handle))
        self.assertEqual(first, second)
        self.assertEqual(header, ["case_id", "outcome", "person_id", "resolved_by",
                                  "matched_value", "n_emails", "n_phones",
                                  "n_hashes", "emails", "phones", "email_hashes",
                                  "sources", "reason"])

    def test_audit_rows_are_ordered_before_use(self) -> None:
        """Shuffling the audit CSV must not change any resolution."""
        shuffled = list(reversed(self.data.user_audit_log))
        other = identity.IdentityResolver(self.data.user_identities, shuffled)
        for case in self.data.deletion_requests:
            with self.subTest(case_id=case["case_id"]):
                self.assertEqual(self.resolver.resolve(case).person_id,
                                 other.resolve(case).person_id)


class TestSampleAccuracy(ResolverFixture):
    """The public samples, scored against sample_output.csv."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.report = main.evaluate_identity_samples(cls.data, cls.resolver)
        cls.truth = {r["case_id"]: r["deletion_status"] for r in cls.data.sample_output}

    def test_full_resolver_attributes_every_sample(self) -> None:
        self.assertEqual(self.report["resolved"], 32)
        self.assertEqual(self.report["resolved"], self.report["total"])

    def test_baseline_needs_history_for_three_samples(self) -> None:
        self.assertEqual(self.report["baseline_resolved"], 29)
        self.assertEqual(len(self.report["baseline_misses"]), 3)

    def test_resolver_never_contradicts_the_baseline(self) -> None:
        self.assertEqual(self.report["disagreements"], [])

    def test_history_cases_are_the_multi_version_ones(self) -> None:
        self.assertEqual(sorted(self.report["history_cases"]),
                         ["case_10", "case_12", "case_29", "case_30"])

    def test_status_accuracy_is_unchanged_by_identity(self) -> None:
        """Identity alone cannot separate COMPLETE from INCOMPLETE.

        Every deletion case still gets the provisional INCOMPLETE status, so the
        pipeline agrees with exactly the 22 INCOMPLETE labels. Recovering old
        emails does not change that: multi-version subjects are all INCOMPLETE,
        while single-version subjects are both COMPLETE and INCOMPLETE.
        """
        self.assertEqual(self.report["status_hits"], 22)
        self.assertEqual(sum(1 for s in self.truth.values() if s == "INCOMPLETE"), 22)
        self.assertEqual(dict(self.report["multi_status"]), {"INCOMPLETE": 4})
        self.assertEqual(dict(self.report["single_status"]),
                         {"COMPLETE": 10, "INCOMPLETE": 18})
        # Three more INCOMPLETE cases are now investigable, but status is not
        # derived from attribution, so the label agreement does not move.
        self.assertEqual(self.report["current_attributable_hits"],
                         self.report["baseline_attributable_hits"] + 3)


class TestBaselineComparison(ResolverFixture):
    """The naive arm must be exactly 'current snapshot email, casefolded'."""

    def test_baseline_matches_snapshot_only(self) -> None:
        for row in self.data.user_identities[:50]:
            case = _case("c", row["email"].upper(), "2026-09-01T00:00:00Z",
                         "2026-09-01T00:00:00Z")
            self.assertEqual(identity.baseline_resolve(case, self.data.user_identities),
                             row["user_id"])

    def test_baseline_returns_empty_for_history_only_email(self) -> None:
        case = self.by_case["case_37"]
        self.assertEqual(identity.baseline_resolve(case, self.data.user_identities), "")
        self.assertTrue(self.resolver.resolve(case).person_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
