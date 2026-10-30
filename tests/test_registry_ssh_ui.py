"""SSH enrollment must be independently confirmed by the trusted registry."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ui.ssh_setup import _install_server
from utils.helper_registry import HelperLease


class RegistrySSHFlowTest(unittest.TestCase):
    def test_registry_setup_never_accepts_only_the_ssh_receipt(self):
        receipt = SimpleNamespace(port=8444, tls_fingerprint="ab"*32, helper_id="helper-test")
        lease = HelperLease("192.0.2.10", 8444, "ab"*32, "synthetic-lease", 2000000000, "helper-test")
        with patch("utils.helper_payload.build_helper_payload", return_value=b"synthetic-payload"), \
             patch("utils.ssh_setup.deploy_helper", return_value=receipt) as deploy, \
             patch("utils.helper_registry.discover_helper", return_value=lease) as discover:
            result = _install_server("192.0.2.10",22,"root","synthetic-password",object(),lambda _:None,registry=True)
        self.assertIs(result, lease)
        self.assertTrue(result.registry)
        self.assertEqual(set(deploy.call_args.kwargs["registry_options"]), {"url","public_key","allow_existing_private_upgrade"})
        self.assertFalse(deploy.call_args.kwargs["registry_options"]["allow_existing_private_upgrade"])
        discover.assert_called_once_with("192.0.2.10",force=True)

    def test_mismatched_registered_port_pin_or_helper_identity_is_rejected(self):
        receipt = SimpleNamespace(port=8444,tls_fingerprint="ab"*32,helper_id="helper-test")
        for port,pin,identifier in [(9444,"ab"*32,"helper-test"),(8444,"bc"*32,"helper-test"),(8444,"ab"*32,"other")]:
            with self.subTest(port=port,pin=pin,identifier=identifier), \
                 patch("utils.helper_payload.build_helper_payload",return_value=b"synthetic-payload"), \
                 patch("utils.ssh_setup.deploy_helper",return_value=receipt), \
                 patch("utils.helper_registry.discover_helper",return_value=HelperLease("192.0.2.10",port,pin,"synthetic-lease",2000000000,identifier)):
                with self.assertRaisesRegex(ValueError,"registry_installation_mismatch"):
                    _install_server("192.0.2.10",22,"root","synthetic-password",object(),lambda _:None,registry=True)

    def test_legacy_setup_does_not_enroll_or_enable_public_access(self):
        receipt=object()
        with patch("utils.helper_payload.build_helper_payload",return_value=b"synthetic-payload"), \
             patch("utils.ssh_setup.deploy_helper",return_value=receipt) as deploy, \
             patch("utils.helper_registry.discover_helper") as discover:
            self.assertIs(_install_server("192.0.2.10",22,"root","synthetic-password",object(),lambda _:None),receipt)
        self.assertNotIn("registry_options",deploy.call_args.kwargs)
        discover.assert_not_called()
