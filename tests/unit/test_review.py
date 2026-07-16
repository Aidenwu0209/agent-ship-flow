from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from ship_flow import review as review_module
from ship_flow.model import Phase
from ship_flow.review import (
    ReviewError,
    ReviewRecoveryError,
    ReviewRole,
    issue_handoff,
    record_code_review,
    record_plan_review,
    resume_review_publication,
)
from ship_flow.store import FileLock, LockUnavailableError, StateStore
from ship_flow.subject import EvidenceSubject


class ReviewImportTests(unittest.TestCase):
    def test_review_interfaces_import(self) -> None:
        self.assertTrue(EvidenceSubject)
        self.assertTrue(issue_handoff)
        self.assertTrue(record_plan_review)
        self.assertTrue(record_code_review)


class EvidenceSubjectTests(unittest.TestCase):
    def subject(self) -> EvidenceSubject:
        return EvidenceSubject(
            run_id="run-001",
            base_oid="1" * 40,
            candidate_oid="2" * 40,
            tree_oid="3" * 40,
            plan_sha256="4" * 64,
            manifest_sha256="5" * 64,
            commands_sha256="6" * 64,
            engine_version="0.1.0",
            schema_version=1,
        )

    def test_digest_binds_every_evidence_component(self) -> None:
        subject = self.subject()
        changed = (
            replace(subject, run_id="run-002"),
            replace(subject, base_oid="a" * 40),
            replace(subject, candidate_oid="b" * 40),
            replace(subject, tree_oid="c" * 40),
            replace(subject, plan_sha256="d" * 64),
            replace(subject, manifest_sha256="e" * 64),
            replace(subject, commands_sha256="f" * 64),
            replace(subject, engine_version="0.2.0"),
            replace(subject, schema_version=2),
        )

        digests = {subject.digest(), *(item.digest() for item in changed)}

        self.assertEqual(len(digests), 10)
        self.assertRegex(subject.digest(), r"^[0-9a-f]{64}$")

    def test_subject_serialization_is_canonical_and_complete(self) -> None:
        subject = self.subject()

        self.assertEqual(
            subject.to_dict(),
            {
                "run_id": "run-001",
                "base_oid": "1" * 40,
                "candidate_oid": "2" * 40,
                "tree_oid": "3" * 40,
                "plan_sha256": "4" * 64,
                "manifest_sha256": "5" * 64,
                "commands_sha256": "6" * 64,
                "engine_version": "0.1.0",
                "schema_version": 1,
            },
        )
        self.assertEqual(
            subject.canonical_bytes(),
            (
                b'{"base_oid":"1111111111111111111111111111111111111111",'
                b'"candidate_oid":"2222222222222222222222222222222222222222",'
                b'"commands_sha256":"6666666666666666666666666666666666666666666666666666666666666666",'
                b'"engine_version":"0.1.0",'
                b'"manifest_sha256":"5555555555555555555555555555555555555555555555555555555555555555",'
                b'"plan_sha256":"4444444444444444444444444444444444444444444444444444444444444444",'
                b'"run_id":"run-001","schema_version":1,'
                b'"tree_oid":"3333333333333333333333333333333333333333"}'
            ),
        )

    def test_subject_rejects_malformed_evidence_components(self) -> None:
        subject = self.subject()
        invalid_changes = (
            {"run_id": ""},
            {"base_oid": "not-an-oid"},
            {"candidate_oid": "A" * 40},
            {"tree_oid": "3" * 39},
            {"plan_sha256": "4" * 63},
            {"manifest_sha256": "g" * 64},
            {"commands_sha256": "6" * 65},
            {"engine_version": " "},
            {"schema_version": True},
            {"schema_version": 0},
        )

        for changes in invalid_changes:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    replace(subject, **changes)


class ReviewWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.run_directory = Path(self.temporary_directory.name) / "runs" / "run-001"
        self.store = StateStore(self.run_directory)
        state = self.store.create("run-001")
        state = self.store.transition(Phase.PLANNING, expected_revision=state.revision)
        self.store.transition(Phase.PLAN_REVIEW, expected_revision=state.revision)
        self.subject = EvidenceSubjectTests().subject()

    def test_issue_handoff_writes_a_private_subject_bound_nonce(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )

        self.assertGreaterEqual(len(nonce), 32)
        receipt_path = (
            self.run_directory
            / "handoffs"
            / f"{hashlib.sha256(nonce.encode('utf-8')).hexdigest()}.json"
        )
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(receipt_path.parent.stat().st_mode), 0o700)
        self.assertEqual(receipt["run_id"], "run-001")
        self.assertEqual(receipt["role"], "plan_critic")
        self.assertEqual(receipt["source_actor"], "planner-context")
        self.assertEqual(receipt["subject"], self.subject.to_dict())
        self.assertEqual(receipt["subject_digest"], self.subject.digest())
        self.assertIsNone(receipt["consumed_at"])

    def test_fresh_passing_plan_review_advances_to_plan_approval(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )

        report = record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )

        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertEqual(report.verdict, "pass")
        report_path = self.run_directory / "reviews" / "plan-review.json"
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
        self.assertEqual(payload["review_type"], "plan")
        self.assertEqual(payload["reviewer_actor"], "critic-context")
        self.assertEqual(payload["subject"], self.subject.to_dict())
        self.assertEqual(payload["subject_digest"], self.subject.digest())
        self.assertEqual(payload["plan_sha256"], self.subject.plan_sha256)
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(
            report_path.read_bytes(),
            (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8"),
        )

    def test_plan_changes_with_migration_safety_finding_return_to_planning(
        self,
    ) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        finding = {
            "category": "migration-safety",
            "severity": "high",
            "message": "The rollback path for the schema change is unspecified.",
            "location": "plan.md:27",
        }

        report = record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="changes_requested",
            findings=(finding,),
        )

        self.assertEqual(self.store.load().phase, Phase.PLANNING)
        self.assertEqual(report.findings, (finding,))
        payload = json.loads(
            (self.run_directory / "reviews" / "plan-review.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(payload["findings"], [finding])

    def test_plan_critic_must_differ_from_planner(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="same-context",
            role=ReviewRole.PLAN_CRITIC,
        )

        with self.assertRaisesRegex(ReviewError, "differ"):
            record_plan_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="same-context",
                handoff_nonce=nonce,
                verdict="pass",
                findings=(),
            )

        self.assertEqual(self.store.load().phase, Phase.PLAN_REVIEW)
        self.assertFalse((self.run_directory / "reviews" / "plan-review.json").exists())

    def test_handoff_rejects_stale_subject_wrong_role_and_reuse(self) -> None:
        stale_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        stale_subject = replace(self.subject, candidate_oid="a" * 40)

        with self.assertRaisesRegex(ReviewError, "stale"):
            record_plan_review(
                self.store,
                current_subject=stale_subject,
                reviewer_actor="critic-context",
                handoff_nonce=stale_nonce,
                verdict="pass",
                findings=(),
            )
        with self.assertRaisesRegex(ReviewError, "wrong review role"):
            record_code_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="reviewer-context",
                handoff_nonce=stale_nonce,
                verdict="pass",
                findings=(),
            )

        report = record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=stale_nonce,
            verdict="pass",
            findings=(),
        )
        self.assertEqual(report.verdict, "pass")
        with self.assertRaisesRegex(ReviewError, "already consumed"):
            record_plan_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="different-critic-context",
                handoff_nonce=stale_nonce,
                verdict="pass",
                findings=(),
            )

    def test_invalid_finding_fields_are_rejected_without_consuming_nonce(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        valid = {
            "category": "security",
            "severity": "high",
            "message": "A trust boundary is not addressed.",
            "location": "plan.md:10",
        }
        invalid_findings = (
            {**valid, "category": "style"},
            {**valid, "severity": "urgent"},
            {**valid, "message": ""},
            {key: value for key, value in valid.items() if key != "location"},
            {**valid, "location": "plan.md"},
        )

        for finding in invalid_findings:
            with self.subTest(finding=finding):
                with self.assertRaises(ReviewError):
                    record_plan_review(
                        self.store,
                        current_subject=self.subject,
                        reviewer_actor="critic-context",
                        handoff_nonce=nonce,
                        verdict="changes_requested",
                        findings=(finding,),
                    )
                self.assertEqual(self.store.load().phase, Phase.PLAN_REVIEW)
                self.assertFalse(
                    (self.run_directory / "reviews" / "plan-review.json").exists()
                )

        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)

    def test_retry_recovers_when_the_first_state_transition_is_interrupted(
        self,
    ) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        events_before = len(self.store.events())

        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated transition interruption"),
        ):
            with self.assertRaisesRegex(OSError, "transition interruption"):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )

        report_path = self.run_directory / "reviews" / "plan-review.json"
        operation_path = self.run_directory / "review-operation.json"
        first_report = report_path.read_bytes()
        self.assertTrue(operation_path.is_file())
        self.assertEqual(stat.S_IMODE(operation_path.stat().st_mode), 0o600)
        operation = json.loads(operation_path.read_text(encoding="utf-8"))
        self.assertEqual(operation["review_type"], "plan")
        self.assertEqual(operation["subject"], self.subject.to_dict())
        self.assertEqual(operation["subject_digest"], self.subject.digest())
        self.assertEqual(operation["reviewer_actor"], "critic-context")
        self.assertEqual(operation["source_actor"], "planner-context")
        self.assertEqual(operation["role"], "plan_critic")
        self.assertEqual(operation["expected_source_phase"], "PLAN_REVIEW")
        self.assertEqual(operation["target_phase"], "AWAITING_PLAN_APPROVAL")
        self.assertEqual(operation["artifact_path"], str(report_path))
        self.assertEqual(
            operation["request_digest"],
            hashlib.sha256(
                json.dumps(
                    operation["request"],
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(
            operation["report_digest"],
            hashlib.sha256(
                json.dumps(
                    operation["report"],
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
        )
        self.assertEqual(self.store.load().phase, Phase.PLAN_REVIEW)
        self.assertEqual(len(self.store.events()), events_before)

        report = record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )

        self.assertEqual(report.verdict, "pass")
        self.assertEqual(report_path.read_bytes(), first_report)
        self.assertFalse(operation_path.exists())
        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertEqual(len(self.store.events()), events_before + 1)

    def test_retry_converges_across_each_publication_back_half_window(self) -> None:
        for suffix, failure_stage in (
            ("after-report", "report-written"),
            ("after-consume", "handoff-consumed"),
            ("after-transition", "receipt-clear"),
        ):
            with self.subTest(failure_stage=failure_stage):
                run_id = f"run-{suffix}"
                run_directory = Path(self.temporary_directory.name) / "runs" / run_id
                store = StateStore(run_directory)
                state = store.create(run_id)
                state = store.transition(
                    Phase.PLANNING,
                    expected_revision=state.revision,
                )
                state = store.transition(
                    Phase.PLAN_REVIEW,
                    expected_revision=state.revision,
                )
                subject = replace(self.subject, run_id=run_id)
                nonce = issue_handoff(
                    store,
                    subject=subject,
                    source_actor="planner-context",
                    role=ReviewRole.PLAN_CRITIC,
                )
                events_before = len(store.events())

                if failure_stage == "receipt-clear":
                    patcher = mock.patch.object(
                        review_module,
                        "_remove_durable_file",
                        side_effect=OSError("simulated crash before receipt clear"),
                    )
                else:
                    real_stage_write = review_module._write_review_operation_stage

                    def fail_stage_write(
                        owned_store: StateStore,
                        operation: dict[str, object],
                        *,
                        stage: str,
                    ) -> dict[str, object]:
                        if stage == failure_stage:
                            raise OSError(f"simulated crash after {failure_stage}")
                        return real_stage_write(
                            owned_store,
                            operation,
                            stage=stage,
                        )

                    patcher = mock.patch.object(
                        review_module,
                        "_write_review_operation_stage",
                        side_effect=fail_stage_write,
                    )

                with patcher:
                    with self.assertRaises(OSError):
                        record_plan_review(
                            store,
                            current_subject=subject,
                            reviewer_actor="critic-context",
                            handoff_nonce=nonce,
                            verdict="pass",
                            findings=(),
                        )

                report_path = run_directory / "reviews" / "plan-review.json"
                report_before_retry = report_path.read_bytes()
                record_plan_review(
                    store,
                    current_subject=subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )

                self.assertEqual(report_path.read_bytes(), report_before_retry)
                self.assertFalse((run_directory / "review-operation.json").exists())
                self.assertEqual(store.load().phase, Phase.AWAITING_PLAN_APPROVAL)
                self.assertEqual(len(store.events()), events_before + 1)

    def test_pending_publication_blocks_stale_or_different_requests(self) -> None:
        original_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated pending publication"),
        ):
            with self.assertRaises(OSError):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=original_nonce,
                    verdict="pass",
                    findings=(),
                )
        report_path = self.run_directory / "reviews" / "plan-review.json"
        original_report = report_path.read_bytes()

        with self.assertRaises(ReviewRecoveryError):
            record_plan_review(
                self.store,
                current_subject=replace(self.subject, plan_sha256="a" * 64),
                reviewer_actor="critic-context",
                handoff_nonce=original_nonce,
                verdict="pass",
                findings=(),
            )
        different_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="other-planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with self.assertRaises(ReviewRecoveryError):
            record_plan_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="other-critic-context",
                handoff_nonce=different_nonce,
                verdict="pass",
                findings=(),
            )

        self.assertEqual(report_path.read_bytes(), original_report)
        self.assertEqual(self.store.load().phase, Phase.PLAN_REVIEW)
        different_handoff_path = (
            self.run_directory
            / "handoffs"
            / f"{hashlib.sha256(different_nonce.encode('utf-8')).hexdigest()}.json"
        )
        self.assertIsNone(
            json.loads(different_handoff_path.read_text(encoding="utf-8"))[
                "consumed_at"
            ]
        )

        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="critic-context",
            handoff_nonce=original_nonce,
            verdict="pass",
            findings=(),
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)

    def test_fresh_process_resumes_a_sealed_review_without_the_raw_nonce(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated crash before review transition"),
        ):
            with self.assertRaisesRegex(OSError, "review transition"):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )

        del nonce
        restarted = StateStore(self.run_directory)
        report = resume_review_publication(
            restarted,
            current_subject=self.subject,
        )

        self.assertEqual(report.verdict, "pass")
        self.assertEqual(restarted.load().phase, Phase.AWAITING_PLAN_APPROVAL)
        self.assertFalse((self.run_directory / "review-operation.json").exists())

    def test_fresh_resume_rejects_a_review_rewritten_after_nonce_loss(self) -> None:
        finding = {
            "category": "requirement",
            "severity": "high",
            "message": "The plan is incomplete.",
            "location": "plan.md:1",
        }
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated crash before review transition"),
        ):
            with self.assertRaisesRegex(OSError, "review transition"):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="changes_requested",
                    findings=(finding,),
                )

        operation_path = self.run_directory / "review-operation.json"
        report_path = self.run_directory / "reviews" / "plan-review.json"
        operation = json.loads(operation_path.read_text(encoding="utf-8"))
        request = dict(operation["request"])
        request["verdict"] = "pass"
        request["findings"] = []
        report = dict(operation["report"])
        report["verdict"] = "pass"
        report["findings"] = []

        def canonical(payload: object) -> bytes:
            return json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

        operation["request"] = request
        operation["request_digest"] = hashlib.sha256(canonical(request)).hexdigest()
        operation["report"] = report
        operation["report_digest"] = hashlib.sha256(canonical(report)).hexdigest()
        operation["new_report_digest"] = hashlib.sha256(
            canonical(report) + b"\n"
        ).hexdigest()
        operation["target_phase"] = Phase.AWAITING_PLAN_APPROVAL.value
        report_path.write_bytes(canonical(report) + b"\n")
        operation_path.write_bytes(canonical(operation) + b"\n")

        del nonce
        restarted = StateStore(self.run_directory)
        with self.assertRaises(ReviewRecoveryError):
            resume_review_publication(
                restarted,
                current_subject=self.subject,
            )

        self.assertEqual(restarted.load().phase, Phase.PLAN_REVIEW)

    def test_fresh_resume_rejects_run_directory_replacement_after_lock(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="planner-context",
            role=ReviewRole.PLAN_CRITIC,
        )
        with mock.patch.object(
            self.store,
            "transition",
            side_effect=OSError("simulated crash before review transition"),
        ):
            with self.assertRaisesRegex(OSError, "review transition"):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="critic-context",
                    handoff_nonce=nonce,
                    verdict="pass",
                    findings=(),
                )

        detached = self.run_directory.with_name("run-001-detached")
        real_validate = review_module.validate_recoverable_review_publication
        replaced = False

        def replace_root_after_lock(
            store: StateStore,
            current_subject: EvidenceSubject,
        ) -> str:
            nonlocal replaced
            if not replaced:
                replaced = True
                os.rename(self.run_directory, detached)
                shutil.copytree(
                    detached, self.run_directory, copy_function=shutil.copy2
                )
            return real_validate(store, current_subject)

        del nonce
        restarted = StateStore(self.run_directory)
        with mock.patch.object(
            review_module,
            "validate_recoverable_review_publication",
            side_effect=replace_root_after_lock,
        ):
            with self.assertRaisesRegex(ReviewRecoveryError, "directory changed"):
                resume_review_publication(
                    restarted,
                    current_subject=self.subject,
                )

        self.assertEqual(StateStore(self.run_directory).load().phase, Phase.PLAN_REVIEW)
        self.assertEqual(StateStore(detached).load().phase, Phase.PLAN_REVIEW)

    def test_plan_review_report_is_replaced_by_a_later_completed_cycle(self) -> None:
        finding = {
            "category": "requirement",
            "severity": "high",
            "message": "The plan must address the missing requirement.",
            "location": "plan.md:12",
        }
        first_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="first-planner",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="first-critic",
            handoff_nonce=first_nonce,
            verdict="changes_requested",
            findings=(finding,),
        )
        report_path = self.run_directory / "reviews" / "plan-review.json"
        first_report = report_path.read_bytes()

        state = self.store.load()
        self.store.transition(Phase.PLAN_REVIEW, expected_revision=state.revision)
        second_subject = replace(self.subject, plan_sha256="a" * 64)
        second_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-planner",
            role=ReviewRole.PLAN_CRITIC,
        )
        report = record_plan_review(
            self.store,
            current_subject=second_subject,
            reviewer_actor="second-critic",
            handoff_nonce=second_nonce,
            verdict="pass",
            findings=(),
        )

        second_report = report_path.read_bytes()
        self.assertNotEqual(second_report, first_report)
        self.assertEqual(report.subject, second_subject)
        self.assertEqual(
            json.loads(second_report)["subject_digest"], second_subject.digest()
        )
        self.assertEqual(self.store.load().phase, Phase.AWAITING_PLAN_APPROVAL)

    def test_external_report_replacement_after_prepare_blocks_recovery(self) -> None:
        finding = {
            "category": "requirement",
            "severity": "high",
            "message": "The plan must address the missing requirement.",
            "location": "plan.md:12",
        }
        first_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="first-planner",
            role=ReviewRole.PLAN_CRITIC,
        )
        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="first-critic",
            handoff_nonce=first_nonce,
            verdict="changes_requested",
            findings=(finding,),
        )
        report_path = self.run_directory / "reviews" / "plan-review.json"
        previous_report = report_path.read_bytes()
        state = self.store.load()
        self.store.transition(Phase.PLAN_REVIEW, expected_revision=state.revision)
        second_subject = replace(self.subject, plan_sha256="a" * 64)
        second_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-planner",
            role=ReviewRole.PLAN_CRITIC,
        )

        with mock.patch.object(
            review_module,
            "_recover_review_publication",
            side_effect=OSError("simulated crash after receipt preparation"),
        ):
            with self.assertRaisesRegex(OSError, "receipt preparation"):
                record_plan_review(
                    self.store,
                    current_subject=second_subject,
                    reviewer_actor="second-critic",
                    handoff_nonce=second_nonce,
                    verdict="pass",
                    findings=(),
                )

        operation_path = self.run_directory / "review-operation.json"
        operation = json.loads(operation_path.read_text(encoding="utf-8"))
        self.assertEqual(
            operation["previous_report_digest"],
            hashlib.sha256(previous_report).hexdigest(),
        )
        expected_new_report = (
            json.dumps(
                operation["report"],
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        self.assertEqual(
            operation["new_report_digest"],
            hashlib.sha256(expected_new_report).hexdigest(),
        )
        foreign_report = b'{"foreign":true}\n'
        report_path.write_bytes(foreign_report)

        with self.assertRaisesRegex(ReviewRecoveryError, "differs"):
            record_plan_review(
                self.store,
                current_subject=second_subject,
                reviewer_actor="second-critic",
                handoff_nonce=second_nonce,
                verdict="pass",
                findings=(),
            )

        self.assertEqual(report_path.read_bytes(), foreign_report)
        self.assertTrue(operation_path.is_file())
        self.assertEqual(self.store.load().phase, Phase.PLAN_REVIEW)

    def test_publication_lock_prevents_a_different_review_from_overwriting(
        self,
    ) -> None:
        first_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="first-planner",
            role=ReviewRole.PLAN_CRITIC,
        )
        second_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="second-planner",
            role=ReviewRole.PLAN_CRITIC,
        )
        publication_lock = FileLock(
            self.run_directory / "review-publication.lock",
            private_root=self.run_directory,
        )
        publication_lock.acquire()
        try:
            with self.assertRaises(LockUnavailableError):
                record_plan_review(
                    self.store,
                    current_subject=self.subject,
                    reviewer_actor="second-critic",
                    handoff_nonce=second_nonce,
                    verdict="pass",
                    findings=(),
                )
            self.assertFalse(
                (self.run_directory / "reviews" / "plan-review.json").exists()
            )
        finally:
            publication_lock.release()

        record_plan_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="first-critic",
            handoff_nonce=first_nonce,
            verdict="pass",
            findings=(),
        )
        report_path = self.run_directory / "reviews" / "plan-review.json"
        first_report = report_path.read_bytes()
        with self.assertRaises(ReviewError):
            record_plan_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="second-critic",
                handoff_nonce=second_nonce,
                verdict="pass",
                findings=(),
            )
        self.assertEqual(report_path.read_bytes(), first_report)


class CodeReviewWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.run_directory = Path(self.temporary_directory.name) / "runs" / "run-001"
        self.store = StateStore(self.run_directory)
        state = self.store.create("run-001")
        for phase in (
            Phase.PLANNING,
            Phase.PLAN_REVIEW,
            Phase.AWAITING_PLAN_APPROVAL,
            Phase.DEVELOPING,
            Phase.CODE_REVIEW,
        ):
            state = self.store.transition(phase, expected_revision=state.revision)
        self.subject = EvidenceSubjectTests().subject()

    def test_fresh_passing_code_review_advances_to_verification(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )

        report = record_code_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )

        self.assertEqual(self.store.load().phase, Phase.VERIFYING)
        self.assertEqual(report.review_type, "code")
        payload = json.loads(
            (self.run_directory / "reviews" / "code-review.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(payload["role"], "reviewer")
        self.assertEqual(payload["verdict"], "pass")
        self.assertNotIn("plan_sha256", payload)

    def test_completed_code_review_rejects_nonfinite_seal_as_recovery_error(
        self,
    ) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        seal = next((self.run_directory / "review-publications").glob("code-*.json"))
        seal.write_bytes(b'{"nonfinite":NaN}\n')

        with self.assertRaises(ReviewRecoveryError):
            review_module.validate_passing_code_review(self.store, self.subject)

    def test_completed_code_review_rejects_invalid_sealed_phase_as_recovery_error(
        self,
    ) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="pass",
            findings=(),
        )
        directory = self.run_directory / "review-publications"
        seal = next(directory.glob("code-*.json"))
        payload = json.loads(seal.read_text(encoding="utf-8"))
        payload["expected_source_phase"] = "NOT_A_PHASE"
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        replacement = directory / (
            f"code-{int(payload['expected_revision']):08d}-{digest}.json"
        )
        seal.unlink()
        replacement.write_bytes(raw + b"\n")

        with self.assertRaises(ReviewRecoveryError):
            review_module.validate_passing_code_review(self.store, self.subject)

    def test_code_changes_requested_return_to_development(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="developer-context",
            role=ReviewRole.REVIEWER,
        )
        finding = {
            "category": "correctness",
            "severity": "critical",
            "message": "The candidate can publish an unreviewed tree.",
            "location": "src/ship_flow/review.py:1",
        }

        report = record_code_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="reviewer-context",
            handoff_nonce=nonce,
            verdict="changes_requested",
            findings=(finding,),
        )

        self.assertEqual(self.store.load().phase, Phase.DEVELOPING)
        self.assertEqual(report.verdict, "changes_requested")

    def test_code_review_report_is_replaced_by_a_later_completed_cycle(self) -> None:
        finding = {
            "category": "correctness",
            "severity": "critical",
            "message": "The candidate can publish an unreviewed tree.",
            "location": "src/ship_flow/review.py:1",
        }
        first_nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="first-developer",
            role=ReviewRole.REVIEWER,
        )
        record_code_review(
            self.store,
            current_subject=self.subject,
            reviewer_actor="first-reviewer",
            handoff_nonce=first_nonce,
            verdict="changes_requested",
            findings=(finding,),
        )
        report_path = self.run_directory / "reviews" / "code-review.json"
        first_report = report_path.read_bytes()

        state = self.store.load()
        self.store.transition(Phase.CODE_REVIEW, expected_revision=state.revision)
        second_subject = replace(
            self.subject,
            candidate_oid="a" * 40,
            tree_oid="b" * 40,
        )
        second_nonce = issue_handoff(
            self.store,
            subject=second_subject,
            source_actor="second-developer",
            role=ReviewRole.REVIEWER,
        )
        report = record_code_review(
            self.store,
            current_subject=second_subject,
            reviewer_actor="second-reviewer",
            handoff_nonce=second_nonce,
            verdict="pass",
            findings=(),
        )

        second_report = report_path.read_bytes()
        self.assertNotEqual(second_report, first_report)
        self.assertEqual(report.subject, second_subject)
        self.assertEqual(
            json.loads(second_report)["subject_digest"], second_subject.digest()
        )
        self.assertEqual(self.store.load().phase, Phase.VERIFYING)

    def test_reviewer_must_differ_from_developer(self) -> None:
        nonce = issue_handoff(
            self.store,
            subject=self.subject,
            source_actor="same-context",
            role=ReviewRole.REVIEWER,
        )

        with self.assertRaisesRegex(ReviewError, "differ"):
            record_code_review(
                self.store,
                current_subject=self.subject,
                reviewer_actor="same-context",
                handoff_nonce=nonce,
                verdict="pass",
                findings=(),
            )

        self.assertEqual(self.store.load().phase, Phase.CODE_REVIEW)


if __name__ == "__main__":
    unittest.main()
