"""Fixed input endpoint labels only; never raw error or transport data."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from release_tools import github
from tests.test_promote_release import promote

class InputEndpointDiagnosticsTest(unittest.TestCase):
    def test_actual_download_calls_annotate_only_fixed_endpoint_without_retry(self):
        for phase in github.InputEndpoint:
            for code,status in (("permission_or_rate_limit",403),("authentication_required",401),("not_found",404),("rate_limited",429),("network_error",None)):
                with self.subTest(endpoint=phase.value,status=status),tempfile.TemporaryDirectory() as folder:
                    client=Mock()
                    client.json.return_value={"draft":True,"tag_name":"publisher-input-"+"b"*64}
                    client.pages.return_value=[{"id":34,"name":github.INPUT_ASSET,"size":10}]
                    error=github.GitHubError(code,status)
                    error.api_url="https://synthetic.invalid/private-token"
                    error.headers={"Authorization":"SYNTHETIC_PRIVATE_NEVER_LOG"}
                    call={github.InputEndpoint.DRAFT_METADATA:client.json,github.InputEndpoint.ASSET_METADATA:client.pages,github.InputEndpoint.ASSET_DOWNLOAD:client._request}[phase]
                    call.side_effect=error
                    with self.assertRaises(github.GitHubError) as raised:
                        github.download_draft_bundle("owner/repo","SYNTHETIC_PRIVATE_NEVER_LOG",12,34,"c"*64,Path(folder)/"input",_client=client)
                    self.assertIs(raised.exception,error)
                    self.assertIs(error.input_endpoint,phase)
                    self.assertEqual(len(client.mock_calls),list(github.InputEndpoint).index(phase)+1)
                    expected={"status":"failed","code":code,"stage":"download_input","input_endpoint":phase.value}
                    if status is not None:expected["http_status"]=status
                    self.assertEqual(promote._safe_failure(error,promote._FailureStage.DOWNLOAD_INPUT),expected)

    def test_untrusted_strings_objects_and_unknown_labels_are_omitted(self):
        for value in ("draft_metadata","asset_download","SYNTHETIC_PRIVATE_NEVER_LOG",object()):
            with self.subTest(kind=type(value).__name__):
                error=github.GitHubError("permission_or_rate_limit",403);error.input_endpoint=value
                self.assertEqual(promote._safe_failure(error,promote._FailureStage.DOWNLOAD_INPUT),
                    {"status":"failed","code":"permission_or_rate_limit","stage":"download_input","http_status":403})

    def test_other_stages_and_non_github_errors_do_not_gain_endpoint(self):
        error=github.GitHubError("permission_or_rate_limit",403);error.input_endpoint=github.InputEndpoint.ASSET_DOWNLOAD
        for stage in promote._FailureStage:
            if stage is not promote._FailureStage.DOWNLOAD_INPUT:
                self.assertNotIn("input_endpoint",promote._safe_failure(error,stage))
        error=RuntimeError("SYNTHETIC_PRIVATE_NEVER_LOG");error.input_endpoint=github.InputEndpoint.DRAFT_METADATA
        self.assertEqual(promote._safe_failure(error,promote._FailureStage.DOWNLOAD_INPUT),
            {"status":"failed","code":"publisher_failure","stage":"download_input"})
