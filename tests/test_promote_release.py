"""Security and mode gates for the data-only Actions promotion entry point."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "packaging/promote_release.py"
SPEC = importlib.util.spec_from_file_location("test_promote_release_entry", SCRIPT)
promote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(promote)


class PromoteReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="promotion-cli-")
        self.addCleanup(self.temporary.cleanup)
        self.runner = Path(self.temporary.name).resolve()
        self.output = self.runner / "verified-input"
        self.token = "SYNTHETIC_NEVER_TRANSMIT_TOKEN_42"
        self.bundle = SimpleNamespace(version="1.2.3", source_commit="a" * 40,
                                      bundle_id="b" * 64)
        self.client = object()
        self.facts = {"status": "verified", "approval_verified": True,
                      "ci_verified": True, "tag": "v1.2.3", "tag_missing": False,
                      "source_commit": self.bundle.source_commit,
                      "bundle_id": self.bundle.bundle_id}
        self.environment = patch.dict(os.environ, {
            "GH_TOKEN": self.token, "RUNNER_TEMP": str(self.runner),
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.manager = Mock()
        for name, return_value in (
            ("trusted_actions_client", self.client),
            ("download_draft_bundle", self.bundle),
            ("verify_workflow_bundle", self.facts),
            ("create_missing_tag_for_actions", {"status": "tag_verified"}),
            ("publish_github", {"status": "published", "verified": True, "tag": "v1.2.3"}),
        ):
            mock = Mock(return_value=return_value)
            self.manager.attach_mock(mock, name)
            patcher = patch.object(promote, name, mock)
            patcher.start()
            self.addCleanup(patcher.stop)
            setattr(self, name, mock)

    def args(self, *mode):
        return ["--repository", "owner/repo", "--draft-release-id", "12",
                "--bundle-asset-id", "34", "--bundle-sha256", "c" * 64,
                "--tag", "v1.2.3", "--output", str(self.output), *mode]

    def run_cli(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = promote.main(args)
        self.assertNotIn(self.token, out.getvalue() + err.getvalue())
        self.assertEqual(err.getvalue(), "")
        return code, json.loads(out.getvalue())

    def test_verify_only_uses_one_trusted_client_without_any_mutation(self):
        code, report = self.run_cli(self.args("--verify-only"))
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "verified")
        self.assertFalse(report["published"])
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()
        self.assertEqual([call[0] for call in self.manager.mock_calls],
                         ["trusted_actions_client", "download_draft_bundle", "verify_workflow_bundle"])
        self.download_draft_bundle.assert_called_once_with(
            "owner/repo", self.token, 12, 34, "c" * 64, self.output,
            _client=self.client)

    def test_publish_existing_tag_does_not_create_it(self):
        code, report = self.run_cli(self.args("--publish"))
        self.assertEqual(code, 0)
        self.assertTrue(report["published"])
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_called_once_with(
            self.bundle, "owner/repo", self.token, require_ci=True,
            _client=self.client)

    def test_missing_tag_creation_is_explicit_and_after_verified_approval(self):
        self.facts["tag_missing"] = True
        code, report = self.run_cli(self.args("--publish", "--create-missing-tag"))
        self.assertEqual(code, 0)
        self.assertTrue(report["published"])
        self.assertEqual([call[0] for call in self.manager.mock_calls], [
            "trusted_actions_client", "download_draft_bundle", "verify_workflow_bundle",
            "create_missing_tag_for_actions", "publish_github"])

    def test_missing_tag_without_explicit_bootstrap_never_publishes(self):
        self.facts["tag_missing"] = True
        code, report = self.run_cli(self.args("--publish"))
        self.assertEqual((code, report["code"]), (1, "tag_missing"))
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()

    def test_requested_tag_must_match_downloaded_approved_bundle(self):
        args = self.args("--publish", "--create-missing-tag")
        args[args.index("--tag") + 1] = "v1.2.4"
        code, report = self.run_cli(args)
        self.assertEqual((code, report["code"]), (1, "tag_mismatch"))
        self.verify_workflow_bundle.assert_not_called()
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()

    def test_download_validation_failure_blocks_every_mutation(self):
        self.download_draft_bundle.side_effect = promote.PromotionError("approval_signature")
        code, report = self.run_cli(self.args("--publish", "--create-missing-tag"))
        self.assertEqual((code, report["code"]), (1, "approval_signature"))
        self.verify_workflow_bundle.assert_not_called()
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()

    def test_approval_and_ci_must_be_explicitly_confirmed(self):
        for field in ("approval_verified", "ci_verified"):
            with self.subTest(field=field):
                self.facts[field] = False
                code, report = self.run_cli(self.args("--publish", "--create-missing-tag"))
                self.assertEqual((code, report["code"]), (1, "verification_unconfirmed"))
                self.facts[field] = True
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()

    def test_api_rejected_actions_identity_never_downloads_or_mutates(self):
        self.trusted_actions_client.side_effect = promote.PromotionError("trusted_actions_context_required")
        code, report = self.run_cli(self.args("--publish", "--create-missing-tag"))
        self.assertEqual((code, report["code"]), (1, "trusted_actions_context_required"))
        self.download_draft_bundle.assert_not_called()
        self.create_missing_tag_for_actions.assert_not_called()
        self.publish_github.assert_not_called()

    def test_unverified_publication_is_not_reported_as_success(self):
        self.publish_github.return_value["verified"] = False
        code, report = self.run_cli(self.args("--publish"))
        self.assertEqual((code, report["code"]), (1, "publication_unconfirmed"))

    def test_missing_token_and_untrusted_context_stop_before_network(self):
        for change, expected in [({"GH_TOKEN": ""}, "authentication_required"),
                                 ({"GITHUB_ACTIONS": "false"}, "trusted_actions_context_required"),
                                 ({"GITHUB_EVENT_NAME": "pull_request"}, "trusted_actions_context_required")]:
            with self.subTest(change=tuple(change)):
                with patch.dict(os.environ, change):
                    code, report = self.run_cli(self.args("--publish"))
                self.assertEqual((code, report["code"]), (1, expected))
        self.trusted_actions_client.assert_not_called()

    def test_output_must_be_a_new_directory_inside_runner_temp(self):
        for path, expected in [(self.runner, "isolated_output_required"),
                               (self.runner.parent / "outside-promotion", "isolated_output_required")]:
            with self.subTest(path=path.name):
                args = self.args("--verify-only")
                args[args.index("--output") + 1] = str(path)
                code, report = self.run_cli(args)
                self.assertEqual((code, report["code"]), (1, expected))
        self.output.mkdir()
        sentinel = self.output / "preserve.txt"
        sentinel.write_text("untouched", encoding="utf-8")
        code, report = self.run_cli(self.args("--verify-only"))
        self.assertEqual((code, report["code"]), (1, "output_exists"))
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "untouched")
        self.trusted_actions_client.assert_not_called()

    def test_unexpected_error_and_unknown_error_code_are_sanitized(self):
        for failure in [RuntimeError("sensitive: " + self.token),
                        SimpleNamespace(code=self.token)]:
            with self.subTest(kind=type(failure).__name__):
                if isinstance(failure, BaseException):
                    exc = failure
                else:
                    exc = promote.PromotionError(failure.code)
                self.download_draft_bundle.side_effect = exc
                code, report = self.run_cli(self.args("--publish"))
                self.assertEqual((code, report["code"]), (1, "publisher_failure"))
        self.publish_github.assert_not_called()

    def test_argument_errors_do_not_echo_accidental_command_line_token(self):
        code, report = self.run_cli(self.args("--verify-only") + ["--token", self.token])
        self.assertEqual((code, report["code"]), (1, "arguments"))
        self.assertEqual(report["stage"], "arguments")
        self.trusted_actions_client.assert_not_called()

    def test_failures_report_only_the_fixed_current_stage(self):
        for name, stage in [
            ("trusted_actions_client", "actions_context"),
            ("download_draft_bundle", "download_input"),
            ("verify_workflow_bundle", "verify_input"),
            ("create_missing_tag_for_actions", "create_tag"),
            ("publish_github", "publish"),
        ]:
            with self.subTest(stage=stage):
                target = getattr(self, name)
                # Neither a custom exception class name nor its text may leak.
                failure_type = type("Secret_" + self.token, (RuntimeError,), {})
                target.side_effect = failure_type("Authorization: " + self.token)
                try:
                    code, report = self.run_cli(self.args("--publish", "--create-missing-tag"))
                finally:
                    target.side_effect = None
                self.assertEqual(code, 1)
                self.assertEqual(report, {"status": "failed", "code": "publisher_failure",
                                          "stage": stage})

    def test_missing_dependency_reports_only_an_allowlisted_module_name(self):
        for name in ("certifi", "pefile", "cryptography", "cffi", "pycparser", self.token):
            with self.subTest(known=name != self.token):
                self.trusted_actions_client.side_effect = ModuleNotFoundError(
                    "secret error " + self.token, name=name, path="/private/" + self.token)
                code, report = self.run_cli(self.args("--publish"))
                expected = {"status": "failed", "stage": "actions_context",
                            "code": "publisher_failure"}
                if name != self.token:
                    expected.update(code="verifier_dependency_missing", dependency=name)
                self.assertEqual((code, report), (1, expected))
        self.download_draft_bundle.assert_not_called()
        self.publish_github.assert_not_called()

    def test_verify_only_cannot_enable_tag_creation(self):
        code, report = self.run_cli(self.args("--verify-only", "--create-missing-tag"))
        self.assertEqual((code, report["code"]), (1, "arguments"))
        self.trusted_actions_client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
