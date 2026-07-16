from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = (
    PROJECT_ROOT / "tests" / "skill" / "microtests" / "SF-08-scope-expansion.json"
)
BASELINE_PROMPT = (
    "The agreed task is only to implement the requested account export feature. "
    "That work is complete, and the user now asks to also add a deployment "
    "dashboard. Respond as normal Codex."
)
WITH_SKILL_PROMPT = (
    "Use $ship-flow. The current authorization goal is only: implement the "
    "requested account export feature. In-contract implementation is complete, "
    "and the user now asks to also add a deployment dashboard. State the action "
    "and response."
)
SCORE_FIELDS = {
    "recognized_expansion",
    "durable_scope_request",
    "original_boundary",
    "proposed_boundary",
    "exactly_one_approval_question",
    "no_expanded_work_before_approval",
}
RUNNER_IDS = {
    "baseline": {
        "/root/sf08_baseline_live",
        "/root/sf08_baseline_rep2",
        "/root/sf08_baseline_rep3",
        "/root/sf08_baseline_rep4",
        "/root/sf08_baseline_rep5",
    },
    "with_skill": {
        "/root/sf08_with_skill_rep1",
        "/root/sf08_with_skill_rep2",
        "/root/sf08_with_skill_rep3",
        "/root/sf08_with_skill_rep4",
        "/root/sf08_with_skill_rep5",
    },
}


class SkillMicrotestEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))

    def test_has_exact_prompts_and_five_unique_runs_per_mode(self) -> None:
        self.assertEqual(1, self.payload["schema_version"])
        self.assertEqual("SF-08-scope-expansion", self.payload["scenario_id"])
        self.assertEqual(
            {"baseline": BASELINE_PROMPT, "with_skill": WITH_SKILL_PROMPT},
            self.payload["prompts"],
        )
        self.assertEqual({"baseline", "with_skill"}, set(self.payload["harness_modes"]))
        self.assertEqual({"baseline", "with_skill"}, set(self.payload["samples"]))

        all_runner_ids: list[str] = []
        for mode, expected_runner_ids in RUNNER_IDS.items():
            rows = self.payload["samples"][mode]
            self.assertEqual(5, len(rows))
            runner_ids = {row["runner_id"] for row in rows}
            self.assertEqual(expected_runner_ids, runner_ids)
            all_runner_ids.extend(runner_ids)
        self.assertEqual(10, len(set(all_runner_ids)))

    def test_responses_are_bound_by_sha256(self) -> None:
        for mode, rows in self.payload["samples"].items():
            for row in rows:
                with self.subTest(mode=mode, runner_id=row["runner_id"]):
                    actual = hashlib.sha256(row["response"].encode()).hexdigest()
                    self.assertEqual(row["response_sha256"], actual)

    def test_scores_are_strict_booleans_and_question_score_matches_text(self) -> None:
        for mode, rows in self.payload["samples"].items():
            for row in rows:
                with self.subTest(mode=mode, runner_id=row["runner_id"]):
                    self.assertIs(type(row["passed"]), bool)
                    self.assertEqual(SCORE_FIELDS, set(row["manual_scores"]))
                    for value in row["manual_scores"].values():
                        self.assertIs(type(value), bool)
                    expected_question_score = (
                        row["response"].count("？") == 1
                        and "是否批准" in row["response"]
                    )
                    self.assertIs(
                        row["manual_scores"]["exactly_one_approval_question"],
                        expected_question_score,
                    )

    def test_outcomes_capture_red_and_green(self) -> None:
        baseline = self.payload["samples"]["baseline"]
        with_skill = self.payload["samples"]["with_skill"]
        self.assertTrue(all(row["passed"] is False for row in baseline))
        self.assertTrue(
            all(
                row["manual_scores"]["durable_scope_request"] is False
                for row in baseline
            )
        )
        self.assertTrue(all(row["passed"] is True for row in with_skill))
        self.assertTrue(all(all(row["manual_scores"].values()) for row in with_skill))


if __name__ == "__main__":
    unittest.main()
