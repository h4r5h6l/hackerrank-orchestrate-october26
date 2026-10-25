#!/usr/bin/env python3
"""Tests for stage 1 (request classification) in code/main.py.

Run with either:
    python3 code/test_stage1_classify.py
    python3 -m unittest discover -s code -p 'test_*.py'

The corpus is participant-visible data only (dataset/), so these tests are
reproducible by anyone with the same download.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import main  # noqa: E402  (path set above)


def _load() -> main.Dataset:
    return main.load_dataset(main.DEFAULT_DATASET_DIR)


class TestDecoyRefusals(unittest.TestCase):
    """The ten non-deletion requests must all be refused, with a cue to show."""

    EXPECTED = tuple(f"case_{i}" for i in range(533, 543))

    @classmethod
    def setUpClass(cls) -> None:
        cls.data = _load()
        cls.by_id = {c["case_id"]: c for c in cls.data.deletion_requests}

    def test_each_decoy_is_not_applicable(self) -> None:
        for case_id in self.EXPECTED:
            with self.subTest(case_id=case_id):
                verdict = main.classify_case(self.by_id[case_id])
                self.assertEqual(verdict.intent, main.INTENT_NON_DELETION)
                self.assertEqual(verdict.status, "NOT_APPLICABLE")
                self.assertEqual(verdict.tier, "explicit_refusal_or_scope")
                self.assertTrue(verdict.cue, "a refusal must name its cue")

    def test_no_other_case_is_refused(self) -> None:
        refused = {c["case_id"] for c in self.data.deletion_requests
                   if main.classify_case(c).intent == main.INTENT_NON_DELETION}
        self.assertEqual(refused, set(self.EXPECTED))

    def test_refusal_cues_are_distinct(self) -> None:
        """The ten decoys must not all collapse onto one brittle keyword."""
        cues = {main.classify_case(self.by_id[c]).cue for c in self.EXPECTED}
        self.assertGreaterEqual(len(cues), 6, cues)


class TestDeletionRequests(unittest.TestCase):
    """Deletion wording in every corpus language must classify as deletion."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.data = _load()
        cls.cases = list(cls.data.deletion_requests) + list(cls.data.sample_deletion_requests)

    def test_public_samples_all_authorise_deletion(self) -> None:
        for sample in self.data.sample_deletion_requests:
            with self.subTest(case_id=sample["case_id"]):
                verdict = main.classify_case(sample)
                self.assertEqual(verdict.intent, main.INTENT_DELETION)
                self.assertEqual(verdict.status, main.PROVISIONAL_STATUS)

    def test_language_coverage(self) -> None:
        probes = {
            "case_54": "pt_excluir",     # "Solicito a exclusão permanente ..."
            "case_66": "ko_sakje",       # "... 삭제를 요청합니다"
            "case_69": "es_eliminar",    # "Solicito la eliminación permanente ..."
            "case_78": "ja_sakujo",      # "... 完全な削除を依頼します"
            "case_84": "fr_supprimer",   # "Je demande la suppression définitive ..."
        }
        by_id = {c["case_id"]: c for c in self.cases}
        for case_id, cue in probes.items():
            with self.subTest(case_id=case_id):
                verdict = main.classify_case(by_id[case_id])
                self.assertEqual(verdict.intent, main.INTENT_DELETION)
                self.assertEqual(verdict.cue, cue)

    def test_french_noun_regression(self) -> None:
        """'suppression' (noun) does not share the stem of 'supprimer' (verb)."""
        verdict = main.classify_request_text(
            "t", "Je demande la suppression définitive du compte associé à "
                 "cette adresse e-mail.")
        self.assertEqual(verdict.intent, main.INTENT_DELETION)

    def test_retention_and_verification_wording_is_not_a_refusal(self) -> None:
        """Deletion requests often mention backups, exports or 'keep' a record."""
        by_id = {c["case_id"]: c for c in self.cases}
        for case_id in ("case_04", "case_08", "case_17", "case_19",
                        "case_28", "case_31", "case_32", "case_25", "case_27"):
            with self.subTest(case_id=case_id):
                self.assertEqual(main.classify_case(by_id[case_id]).intent,
                                 main.INTENT_DELETION)


class TestCueOrdering(unittest.TestCase):
    """Refusal beats deletion vocabulary; deletion vocabulary beats other rights."""

    def test_delete_plus_correction_is_still_deletion(self) -> None:
        verdict = main.classify_request_text(
            "t", "Please delete my account and correct the misspelling in my name.")
        self.assertEqual(verdict.intent, main.INTENT_DELETION)
        self.assertEqual(verdict.tier, "deletion_signal")

    def test_explicit_refusal_beats_deletion_vocabulary(self) -> None:
        verdict = main.classify_request_text(
            "t", "I am not asking for deletion. Keep the account as it is.")
        self.assertEqual(verdict.intent, main.INTENT_NON_DELETION)

    def test_typographic_apostrophe_is_folded(self) -> None:
        verdict = main.classify_request_text("t", "Please don\u2019t delete my account.")
        self.assertEqual(verdict.intent, main.INTENT_NON_DELETION)
        self.assertEqual(verdict.cue, "do_not_close_delete")

    def test_fullwidth_and_case_folding(self) -> None:
        verdict = main.classify_request_text("t", "ＰＬＥＡＳＥ DELETE MY ACCOUNT")
        self.assertEqual(verdict.intent, main.INTENT_DELETION)

    def test_unrelated_text_is_unclassified_not_guessed(self) -> None:
        verdict = main.classify_request_text("t", "Hello, I have a question about shipping.")
        self.assertEqual(verdict.intent, main.INTENT_UNCLASSIFIED)
        # An unresolved request keeps being audited rather than being dropped.
        self.assertTrue(verdict.authorizes_deletion)


class TestFullCorpus(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.data = _load()
        cls.verdicts = [(c, main.classify_case(c)) for c in cls.data.deletion_requests]

    def test_row_count_and_ids(self) -> None:
        rows = [main.row_from_classification(v) for _, v in self.verdicts]
        self.assertEqual(len(rows), 518)
        self.assertEqual(len({r["case_id"] for r in rows}), 518)
        self.assertEqual({r["case_id"] for r in rows},
                         {c["case_id"] for c in self.data.deletion_requests})

    def test_histogram(self) -> None:
        counts = main.Counter(v.intent for _, v in self.verdicts)
        self.assertEqual(counts[main.INTENT_DELETION], 508)
        self.assertEqual(counts[main.INTENT_NON_DELETION], 10)
        self.assertEqual(counts[main.INTENT_UNCLASSIFIED], 0)

    def test_only_not_applicable_carries_empty_steps(self) -> None:
        rows = [main.row_from_classification(v) for _, v in self.verdicts]
        for row in rows:
            with self.subTest(case_id=row["case_id"]):
                self.assertIn(row["deletion_status"], main.STATUS_ORDER)
                self.assertEqual(row["steps_json"], "[]")

    def test_classification_is_deterministic(self) -> None:
        again = [main.classify_case(c) for c in self.data.deletion_requests]
        self.assertEqual([v for _, v in self.verdicts], again)


class TestSampleAccuracy(unittest.TestCase):

    def test_sample_metrics(self) -> None:
        data = _load()
        report = main.evaluate_samples(data)
        self.assertEqual(report["total"], 32)
        # Every public sample authorises deletion, so this branch is fully hit.
        self.assertEqual(report["classification_hits"], 32)
        # 22 of the 32 samples are INCOMPLETE; stage 1 cannot reach COMPLETE.
        self.assertEqual(report["status_hits"], 22)
        self.assertEqual(report["mismatches"], [])


class TestIntakeCrossCheck(unittest.TestCase):
    """Privacy intake reached the same verdict independently of the text."""

    def test_every_refusal_is_corroborated(self) -> None:
        report = main.cross_check_intake(_load())
        self.assertTrue(report["available"])
        self.assertEqual(report["checked"], 10)
        self.assertEqual(report["corroborated"], 10)
        self.assertEqual(report["unmatched"], [])

    def test_account_link_timeliness_is_reported_honestly(self) -> None:
        # The email -> account_N mapping sits in a ledger captured after
        # audit_at for nine of the ten cases, so it cannot be a decision input.
        report = main.cross_check_intake(_load())
        self.assertEqual(report["timely_link"], 1)
        self.assertEqual(report["captured_at"], "2026-10-01T12:00:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
