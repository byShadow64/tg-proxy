from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def release_jobs(source):
    jobs = source.split("\njobs:\n", 1)[1]
    return dict(re.findall(r"(?ms)^  ([a-z][a-z-]*):\n(.*?)(?=^  [a-z][a-z-]*:|\Z)", jobs))


def job_permissions(job):
    match = re.search(r"(?m)^    permissions:\n((?:      [a-z-]+: [a-z]+\n)+)", job)
    if match is None:
        return {}
    return dict(re.findall(r"(?m)^      ([a-z-]+): ([a-z]+)$", match.group(1)))


def action_inputs(job, action):
    match = re.search(
        r"(?ms)^        uses: actions/" + re.escape(action)
        + r"@[0-9a-f]{40}[^\n]*\n        with:\n"
        + r"((?:          [a-z-]+: [^\n]+\n)+)", job,
    )
    if match is None:
        raise AssertionError("Pinned artifact action with explicit inputs is required")
    return dict(re.findall(r"(?m)^          ([a-z-]+): ([^\n]+)$", match.group(1)))


class ReleaseWorkflowTests(unittest.TestCase):
    def release_source(self):
        return (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")

    def test_release_uses_trusted_default_branch_and_exact_input_without_rebuild(self):
        source = self.release_source()
        self.assertIn("TGPROXY_EXACT_BUNDLE_PUBLISHER_V1", source)
        self.assertIn("workflow_dispatch:", source)
        self.assertNotIn("  push:", source)
        self.assertNotIn("pull_request_target", source)
        self.assertNotIn("--clobber", source)
        self.assertNotIn("PyInstaller", source)
        self.assertNotIn("pip install \".", source)
        self.assertNotIn("verify_windows_exe.py", source)
        self.assertIn("--verify-only", source)
        self.assertIn("--publish --create-missing-tag", source)
        self.assertIn("cancel-in-progress: false", source)
        self.assertIn("--only-binary=:all: --require-hashes", source)
        self.assertEqual(source.count("ref: ${{ github.sha }}"), 3)
        self.assertEqual(source.count("persist-credentials: false"), 3)
        for action in re.findall(r"uses:\s*([^\s#]+)", source):
            self.assertRegex(action, r"^actions/[a-z-]+@[0-9a-f]{40}$")

    def test_draft_fetch_readonly_verify_and_publish_have_separate_tokens(self):
        jobs = release_jobs(self.release_source())
        self.assertEqual(set(jobs), {"fetch", "verify", "publish"})
        self.assertEqual(job_permissions(jobs["fetch"]), {"contents": "write", "actions": "read"})
        self.assertEqual(job_permissions(jobs["verify"]), {"contents": "read", "actions": "read"})
        self.assertEqual(job_permissions(jobs["publish"]), {"contents": "write", "actions": "read"})
        self.assertRegex(jobs["verify"], r"(?m)^    needs: fetch$")
        self.assertRegex(jobs["publish"], r"(?m)^    needs: \[fetch, verify\]$")
        guard = ("if: github.repository == 'byShadow64/tg-proxy' && "
                 "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)")
        for job in jobs.values():
            self.assertIn(guard, job)
            self.assertIn("ref: ${{ github.sha }}", job)
            self.assertIn("persist-credentials: false", job)
            self.assertNotIn("secrets.", job)

    def test_privileged_fetch_only_transports_one_opaque_zip(self):
        fetch = release_jobs(self.release_source())["fetch"]
        self.assertIn("--fetch-only", fetch)
        self.assertNotIn("--verify-only", fetch)
        self.assertNotIn("--publish", fetch)
        self.assertNotIn("--create-missing-tag", fetch)
        self.assertNotIn("--input-archive", fetch)
        self.assertIn('--output "$env:RUNNER_TEMP/release-fetch"', fetch)
        self.assertIn("bundle_id: ${{ steps.fetch.outputs.bundle_id }}", fetch)
        self.assertIn("artifact_id: ${{ steps.upload.outputs.artifact-id }}", fetch)
        inputs = action_inputs(fetch, "upload-artifact")
        self.assertEqual(inputs, {
            "name": "publication-input-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/release-fetch/publication-bundle.zip",
            "if-no-files-found": "error",
            "retention-days": "1",
            "compression-level": "0",
            "overwrite": "false",
            "archive": "true",
        })
        self.assertNotRegex(inputs["path"], r"[*?]")
        self.assertIn("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", fetch)
        self.assertEqual(fetch.count("python -B packaging/promote_release.py"), 1)

    def test_both_consumers_download_the_same_single_artifact_from_current_run(self):
        jobs = release_jobs(self.release_source())
        for name in ("verify", "publish"):
            with self.subTest(job=name):
                job = jobs[name]
                self.assertEqual(action_inputs(job, "download-artifact"), {
                    "artifact-ids": "${{ needs.fetch.outputs.artifact_id }}",
                    "path": "${{ runner.temp }}/release-input",
                    "digest-mismatch": "error",
                })
                self.assertIn("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", job)
                self.assertNotIn("actions/upload-artifact", job)
                self.assertNotIn("--fetch-only", job)

    def test_each_stage_keeps_original_dispatch_identity_and_hash(self):
        jobs = release_jobs(self.release_source())
        for name, job in jobs.items():
            with self.subTest(job=name):
                for line in (
                    "DRAFT_ID: ${{ inputs.draft_release_id }}",
                    "ASSET_ID: ${{ inputs.bundle_asset_id }}",
                    "BUNDLE_SHA: ${{ inputs.bundle_sha256 }}",
                    "RELEASE_TAG: ${{ inputs.tag }}",
                    '--repository "$env:GITHUB_REPOSITORY"',
                    '--draft-release-id "$env:DRAFT_ID"',
                    '--bundle-asset-id "$env:ASSET_ID"',
                    '--bundle-sha256 "$env:BUNDLE_SHA"',
                    '--tag "$env:RELEASE_TAG"',
                ):
                    self.assertIn(line, job)
        for name in ("verify", "publish"):
            job = jobs[name]
            self.assertIn("INPUT_BUNDLE_ID: ${{ needs.fetch.outputs.bundle_id }}", job)
            self.assertIn('--input-bundle-id "$env:INPUT_BUNDLE_ID"', job)
            self.assertIn('--input-archive "$env:RUNNER_TEMP/release-input/publication-bundle.zip"', job)
            self.assertIn('--output "$env:RUNNER_TEMP/release-' + name + '"', job)
        self.assertIn("--verify-only", jobs["verify"])
        self.assertNotIn("--publish", jobs["verify"])
        self.assertIn("--publish --create-missing-tag", jobs["publish"])

    def test_no_job_runs_any_code_from_the_bundle_or_builds_a_replacement(self):
        jobs = release_jobs(self.release_source())
        for name, job in jobs.items():
            with self.subTest(job=name):
                # Every Python entry point is in the trusted checkout, never in input paths.
                commands = re.findall(r"(?m)^          python -B ([^\n]+)$", job)
                self.assertEqual(commands, ["packaging/promote_release.py"])
                self.assertNotRegex(job, r"(?i)(invoke-expression|expand-archive|unzip|extractall|source\.zip[\\/]|release-input[\\/].*\.py)")
                self.assertNotIn("TgWsProxy_windows.exe", job)
                self.assertNotIn("prepare_release.py", job)
                self.assertNotIn("pyinstaller", job.lower())

    def test_unsigned_ci_bundle_is_separate_from_publication(self):
        source = (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8")
        self.assertIn("contents: read", source)
        self.assertNotIn("contents: write", source)
        self.assertIn("--bundle-output dist/publication", source)
        self.assertIn("TgWsProxy-unsigned-publication-bundle", source)
        self.assertNotIn("promote_release.py", source)

    def test_client_channel_identity_is_unchanged_by_release_tools(self):
        source = (ROOT / "proxy/update_channel.py").read_text(encoding="utf-8")
        self.assertIn('UPDATE_MANIFEST_URL = "https://217.177.34.28/latest.json"', source)

    def test_ci_checks_release_verifier_in_its_own_hash_locked_environment(self):
        source = (ROOT / ".github/workflows/windows-ci.yml").read_text(encoding="utf-8")
        match = re.search(r"(?ms)^  release-verifier:\n(.*?)(?=^  [a-z-]+:|\Z)", source)
        self.assertIsNotNone(match)
        job = match.group(1)
        self.assertIn('python -m venv "$env:RUNNER_TEMP/release-verifier-env"', job)
        self.assertNotIn("--system-site-packages", job)
        self.assertIn("& $verifierPython -m pip install --only-binary=:all: --require-hashes -r packaging/release-verification-requirements.lock", job)
        self.assertIn("& $verifierPython -m pip check", job)
        self.assertIn("& $verifierPython -I -B -c", job)
        self.assertIn("import certifi, pefile", job)
        self.assertIn("from proxy.http_transport import create_connection, response_with_deadline", job)
        self.assertIn("from release_tools.trust import verify_approval", job)
        self.assertNotRegex(job, r'pip install\s+["\']?\.')
        self.assertNotIn("GH_TOKEN", job)
        self.assertIn("needs: [tests, android-core, release-verifier]", source)


if __name__ == "__main__":
    unittest.main()
