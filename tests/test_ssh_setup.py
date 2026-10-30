"""SSH deployment tests use in-memory transports and never contact a server."""
import io
import hashlib
import json
import socket
import ssl
import stat
import tarfile
import threading
import time
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

import paramiko
from cryptography.hazmat.primitives.asymmetric import ec
from proxy.registry_protocol import b64encode, encode_public_key

from utils import ssh_setup


PASSWORD = "synthetic-ssh-password"
TOKEN = "synthetic-helper-token-" + "x" * 40
from utils.helper_payload import HELPER_PAYLOAD_FILES
FILES = HELPER_PAYLOAD_FILES
STAGE = "/root/.tg-proxy-setup-" + "c" * 24


def payload(extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name in FILES:
            data = ("# " + name + "\n").encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        if extra is not None:
            archive.addfile(extra, io.BytesIO(b""))
    return stream.getvalue()


class Key:
    def __init__(self, data=b"synthetic-server-public-key"):
        self.data = data

    def asbytes(self):
        return self.data

    def get_name(self):
        return "ssh-ed25519"


class Writer(io.BytesIO):
    def __init__(self, sftp, path):
        super().__init__()
        self.sftp, self.path = sftp, path

    def write(self, data):
        if self.sftp.modes[self.path] != 0o600:
            raise AssertionError("Payload must be private before bytes are written")
        return super().write(data)

    def close(self):
        if not self.closed:
            self.sftp.files[self.path] = self.getvalue()
        super().close()


class SFTP:
    def __init__(self):
        self.files, self.modes, self.dirs = {}, {}, {"/root": 0o700}
        self.removed, self.removed_dirs, self.opened = [], [], []
        self.channel, self.close = Mock(), Mock()
        self.metadata_override = {}

    def get_channel(self):
        return self.channel

    def mkdir(self, path, mode):
        if path in self.dirs:
            raise FileExistsError(path)
        self.dirs[path] = mode

    def chmod(self, path, mode):
        if path in self.dirs:
            self.dirs[path] = mode
        else:
            self.modes[path] = mode

    def open(self, path, mode, **kwargs):
        self.opened.append((path, mode))
        if "w" in mode:
            if path in self.files:
                raise FileExistsError(path)
            self.files[path], self.modes[path] = b"", 0o644
            return Writer(self, path)
        return io.BytesIO(self.files[path])

    def lstat(self, path):
        values = dict(st_mode=stat.S_IFREG | self.modes[path], st_uid=0, st_size=len(self.files[path]))
        values.update(self.metadata_override)
        return SimpleNamespace(**values)

    def remove(self, path):
        self.removed.append(path)
        if path not in self.files:
            raise FileNotFoundError(path)
        del self.files[path]

    def rmdir(self, path):
        self.removed_dirs.append(path)
        del self.dirs[path]


class SSHSetupTest(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.options = ssh_setup.SSHOptions("example.invalid", password=PASSWORD)
        self.key = Key()
        self.identity = ssh_setup._identity(self.key)
        self.sock = Mock()
        self.transport = Mock()
        self.transport.get_remote_server_key.return_value = self.key
        self.transport.is_authenticated.return_value = True
        self.sftp = SFTP()
        self.connect = self.stack.enter_context(patch.object(
            ssh_setup, "_open_connection", return_value=self.sock))
        self.stack.enter_context(patch.object(ssh_setup.paramiko, "Transport", return_value=self.transport))
        self.stack.enter_context(patch.object(ssh_setup, "_open_sftp", return_value=self.sftp))
        self.endpoint = self.stack.enter_context(patch.object(ssh_setup, "_verify_endpoint"))
        self.stack.enter_context(patch.object(ssh_setup.secrets, "token_hex", return_value="c" * 24))
        self.result = {"host": "10.0.0.4", "port": 8444, "fingerprint": "A" * 64, "token": TOKEN}
        self.command = self.stack.enter_context(patch.object(ssh_setup, "_run_command", side_effect=self.run_command))

    def run_command(self, transport, command, **kwargs):
        if command == "id -u":
            return 0, b"0\n"
        if "--result-file" in command:
            self.sftp.files[STAGE + "/result.json"] = json.dumps(self.result).encode()
            self.sftp.modes[STAGE + "/result.json"] = 0o600
        return 0, b""

    def deploy(self, **kwargs):
        return ssh_setup.deploy_helper(self.options, self.identity, payload(), **kwargs)

    def test_probe_returns_sha256_identity_without_sending_a_password(self):
        identity = ssh_setup.fetch_host_key(ssh_setup.SSHOptions("example.invalid"))
        self.assertEqual(identity.key_type, "ssh-ed25519")
        self.assertEqual(identity.key_data, self.key.asbytes())
        self.assertTrue(identity.fingerprint.startswith("SHA256:"))
        self.transport.auth_password.assert_not_called()
        self.transport.close.assert_called_once()
        self.sock.close.assert_called_once()

    def test_changed_host_key_is_rejected_before_authentication_or_any_remote_command(self):
        self.transport.get_remote_server_key.return_value = Key(b"changed-key")
        with self.assertRaises(ssh_setup.SSHSetupError) as caught:
            self.deploy()
        self.assertEqual(caught.exception.code, "host_key_mismatch")
        self.transport.auth_password.assert_not_called()
        self.command.assert_not_called()
        self.assertEqual(self.sftp.dirs, {"/root": 0o700})

    def test_success_uploads_private_whitelist_and_returns_only_credentials_in_memory(self):
        stages = []
        result = self.deploy(progress=stages.append)
        self.transport.auth_password.assert_called_once_with("root", PASSWORD, fallback=False)
        self.assertEqual(result.host, self.options.host)  # Reject a private NAT interface as the client endpoint.
        self.assertEqual(result.port, 8444)
        self.assertEqual(result.tls_fingerprint, "a" * 64)
        self.assertEqual(result.token, TOKEN)
        self.endpoint.assert_called_once_with(self.options, result)
        self.assertNotIn(PASSWORD, repr(self.options))
        self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(stages, ["connect", "verify", "upload", "install", "verify_result"])
        uploads = {path[len(STAGE) + 1:] for path, mode in self.sftp.opened if mode == "wx"}
        self.assertEqual(uploads, set(FILES))
        for path, mode in self.sftp.modes.items():
            self.assertEqual(mode, 0o600, path)
        self.assertEqual(self.sftp.dirs, {"/root": 0o700})
        self.assertEqual(self.sftp.files, {})
        commands = "\n".join(call.args[1] for call in self.command.call_args_list)
        self.assertIn("--result-file", commands)
        self.assertNotIn("--allow-legacy", commands)
        self.assertNotIn(PASSWORD, commands)
        self.assertNotIn(TOKEN, commands)
        self.assertNotIn(self.options.host, commands)
        self.sftp.close.assert_called_once()
        self.transport.close.assert_called_once()

    def test_authentication_errors_and_cleanup_errors_cannot_expose_secrets(self):
        self.transport.auth_password.side_effect = paramiko.AuthenticationException(PASSWORD)
        self.transport.close.side_effect = RuntimeError(TOKEN)
        self.sock.close.side_effect = RuntimeError(PASSWORD)
        with self.assertRaises(ssh_setup.SSHSetupError) as caught:
            self.deploy()
        self.assertEqual(caught.exception.code, "authentication")
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))
        self.command.assert_not_called()

    def test_non_root_and_unsupported_system_are_rejected_before_upload(self):
        for root, platform in ((False, True), (True, False)):
            with self.subTest(root=root, platform=platform):
                def command(transport, text, **kwargs):
                    return (0, b"0\n" if root else b"1000\n") if text == "id -u" else (int(not platform), b"")
                self.command.side_effect = command
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    self.deploy()
                self.assertEqual(caught.exception.code, "unsupported_system" if root else "root_required")
                self.assertEqual(self.sftp.opened, [])

    def test_untrusted_tar_links_paths_and_extra_files_never_connect(self):
        for name, kind in (("../../config.json", tarfile.REGTYPE),
                           ("proxy/unsafe.py", tarfile.REGTYPE), ("helper_server.py", tarfile.SYMTYPE)):
            with self.subTest(name=name, kind=kind):
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "/etc/shadow" if kind == tarfile.SYMTYPE else ""
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    ssh_setup.deploy_helper(self.options, self.identity, payload(member))
                self.assertEqual(caught.exception.code, "payload")
        self.connect.assert_not_called()

    def test_existing_staging_path_is_never_removed(self):
        self.sftp.dirs[STAGE] = 0o700
        with self.assertRaises(ssh_setup.SSHSetupError):
            self.deploy()
        self.assertIn(STAGE, self.sftp.dirs)
        self.assertEqual(self.sftp.removed, [])
        self.assertEqual(self.sftp.removed_dirs, [])

    def test_failed_install_cleans_only_owned_staging_and_uses_generic_error(self):
        original = self.run_command

        def command(transport, text, **kwargs):
            status, output = original(transport, text, **kwargs)
            return (1, (PASSWORD + TOKEN).encode()) if "--result-file" in text else (status, output)

        self.command.side_effect = command
        with self.assertRaises(ssh_setup.SSHSetupError) as caught:
            self.deploy()
        self.assertEqual(caught.exception.code, "install")
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertTrue(all(path.startswith(STAGE + "/") for path in self.sftp.removed))
        self.assertEqual(self.sftp.removed_dirs, [STAGE + "/proxy", STAGE])
        self.assertFalse(self.sftp.files)

    def test_malformed_result_never_becomes_a_successful_client_configuration(self):
        for change in ({"token": "short"}, {"fingerprint": "invalid"}, {"port": 8443}):
            with self.subTest(change=change):
                self.sftp = SFTP()
                ssh_setup._open_sftp.return_value = self.sftp
                self.result = {"host": "10.0.0.4", "port": 8444, "fingerprint": "a" * 64, "token": TOKEN}
                self.result.update(change)
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    self.deploy()
                self.assertEqual(caught.exception.code, "result")
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_result_must_be_a_private_root_owned_regular_file(self):
        for metadata in ({"st_mode": stat.S_IFREG | 0o644}, {"st_mode": stat.S_IFLNK | 0o600},
                         {"st_uid": 1000}, {"st_size": ssh_setup._MAX_RESULT + 1}):
            with self.subTest(metadata=metadata):
                self.sftp = SFTP()
                self.sftp.metadata_override = metadata
                ssh_setup._open_sftp.return_value = self.sftp
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    self.deploy()
                self.assertEqual(caught.exception.code, "result")
        self.endpoint.assert_not_called()

    def test_release_payload_builder_matches_the_upload_contract(self):
        from utils.helper_payload import build_helper_payload

        self.assertEqual(set(ssh_setup._unpack_payload(build_helper_payload())), set(FILES))

    def test_registry_install_result_has_no_global_token_and_upgrade_requires_separate_flag(self):
        self.options = ssh_setup.SSHOptions("9.9.9.9", password=PASSWORD)
        public = encode_public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        options = dict(url="https://registry.example.invalid", public_key=public)
        self.result = dict(host="9.9.9.9", port=8444, fingerprint="a" * 64,
                           registry=True, helper_id=b64encode(b"h" * 16))
        result = self.deploy(registry_options=options)
        self.assertTrue(result.registry)
        self.assertEqual("", result.token)
        self.assertEqual(self.result["helper_id"], result.helper_id)
        command = next(call.args[1] for call in self.command.call_args_list if "--result-file" in call.args[1])
        self.assertIn("--registry-mode", command)
        self.assertIn("--public-ip 9.9.9.9", command)
        self.assertNotIn("--allow-existing-private-upgrade", command)
        self.command.reset_mock()
        self.deploy(registry_options=dict(options, allow_existing_private_upgrade=True))
        command = next(call.args[1] for call in self.command.call_args_list if "--result-file" in call.args[1])
        self.assertIn("--allow-existing-private-upgrade", command)

    def test_registry_result_cannot_contain_a_global_token_or_change_the_public_endpoint(self):
        self.options = ssh_setup.SSHOptions("9.9.9.9", password=PASSWORD)
        public = encode_public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        options = dict(url="https://registry.example.invalid", public_key=public)
        for change in ({"token": TOKEN}, {"host": "8.8.8.8"}, {"registry": False}, {"helper_id": "bad"}):
            with self.subTest(change=change):
                self.sftp = SFTP()
                ssh_setup._open_sftp.return_value = self.sftp
                self.result = dict(host="9.9.9.9", port=8444, fingerprint="a" * 64,
                                   registry=True, helper_id=b64encode(b"h" * 16))
                self.result.update(change)
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    self.deploy(registry_options=options)
                self.assertEqual("result", caught.exception.code)
        self.endpoint.assert_not_called()

    def test_invalid_registry_consent_or_private_ip_is_rejected_before_ssh(self):
        public = encode_public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        self.options = ssh_setup.SSHOptions("9.9.9.9", password=PASSWORD)
        good = dict(url="https://registry.example.invalid", public_key=public)
        for change in ({"url": "http://registry.example.invalid"}, {"public_key": "bad"},
                       {"allow_existing_private_upgrade": "true"}, {"unexpected": True}):
            with self.subTest(change=change), self.assertRaises(ssh_setup.SSHSetupError):
                self.deploy(registry_options=dict(good, **change))
        self.options = ssh_setup.SSHOptions("127.0.0.1", password=PASSWORD)
        with self.assertRaises(ssh_setup.SSHSetupError):
            self.deploy(registry_options=good)
        self.connect.assert_not_called()


class EndpointVerificationTest(unittest.TestCase):
    def test_public_tls_certificate_matches_pin_without_sending_the_token(self):
        certificate = b"synthetic DER certificate"
        result = ssh_setup.DeploymentResult(
            "example.invalid", 8444, hashlib.sha256(certificate).hexdigest(), TOKEN)
        raw, secured, context = Mock(), Mock(), Mock()
        secured.getpeercert.return_value = certificate
        context.wrap_socket.return_value = secured
        options = ssh_setup.SSHOptions("example.invalid", password=PASSWORD)
        with patch.object(ssh_setup, "_open_connection", return_value=raw) as connect, \
                patch.object(ssh_setup.ssl, "SSLContext", return_value=context):
            ssh_setup._verify_endpoint(options, result)
        connect.assert_called_once_with(("example.invalid", 8444), 15)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertFalse(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        secured.sendall.assert_not_called()
        secured.write.assert_not_called()
        secured.close.assert_called_once()
        raw.close.assert_called_once()

    def test_unreachable_or_wrong_certificate_does_not_pass_endpoint_verification(self):
        options = ssh_setup.SSHOptions("example.invalid", password=PASSWORD)
        result = ssh_setup.DeploymentResult("example.invalid", 8444, "a" * 64, TOKEN)
        for unreachable in (False, True):
            with self.subTest(unreachable=unreachable):
                context, secured, raw = Mock(), Mock(), Mock()
                secured.getpeercert.return_value = b"wrong DER certificate"
                context.wrap_socket.return_value = secured
                with patch.object(ssh_setup, "_open_connection",
                                  side_effect=OSError(PASSWORD) if unreachable else None,
                                  return_value=raw), \
                        patch.object(ssh_setup.ssl, "SSLContext", return_value=context):
                    with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                        ssh_setup._verify_endpoint(options, result)
                self.assertEqual((caught.exception.code, caught.exception.stage), ("endpoint", "verify_result"))
                self.assertNotIn(PASSWORD, str(caught.exception))
                self.assertNotIn(TOKEN, str(caught.exception))


class SSHSocketDeadlineTest(unittest.TestCase):
    def test_real_loopback_connection_has_a_bounded_socket_timeout(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(1)
            started = time.monotonic()
            with ssh_setup._open_connection(listener.getsockname(), .5) as client:
                self.assertGreater(client.gettimeout(), 0)
                self.assertLessEqual(client.gettimeout(), .5)
                peer, _ = listener.accept()
                with peer:
                    client.sendall(b"probe")
                    self.assertEqual(peer.recv(5), b"probe")
            self.assertLess(time.monotonic() - started, 1)

    def test_real_loopback_refusal_does_not_leave_a_connected_socket(self):
        with socket.socket() as held_without_listener:
            held_without_listener.bind(("127.0.0.1", 0))
            started = time.monotonic()
            with self.assertRaises(OSError):
                ssh_setup._open_connection(held_without_listener.getsockname(), .15)
            self.assertLess(time.monotonic() - started, .8)

    def test_stalled_dns_times_out_and_holds_at_most_four_daemon_slots(self):
        gate = threading.Event()
        workers = []
        slots = threading.BoundedSemaphore(4)

        def resolve(*args):
            workers.append(threading.current_thread())
            gate.wait(2)
            raise socket.gaierror("synthetic resolver released")

        try:
            with patch.object(ssh_setup, "_DNS_SLOTS", slots), \
                    patch.object(ssh_setup.socket, "getaddrinfo", side_effect=resolve) as dns, \
                    patch.object(ssh_setup.socket, "socket") as create_socket:
                for _ in range(4):
                    started = time.monotonic()
                    with self.assertRaises(TimeoutError):
                        ssh_setup._open_connection(("stalled.invalid", 22), .025)
                    self.assertLess(time.monotonic() - started, .5)
                with self.assertRaises(TimeoutError):
                    ssh_setup._open_connection(("fifth.invalid", 22), .5)
                self.assertEqual(dns.call_count, 4)
                self.assertEqual(len(workers), 4)
                self.assertTrue(all(worker.daemon and worker.is_alive() for worker in workers))
                create_socket.assert_not_called()
        finally:
            gate.set()
            for worker in workers:
                worker.join(1)
                self.assertFalse(worker.is_alive())
        # A timed-out caller did not free a slot early or leak it forever.
        acquired = [slots.acquire(blocking=False) for _ in range(5)]
        self.assertEqual(acquired, [True] * 4 + [False])
        for _ in range(4):
            slots.release()

    def test_stalled_probe_returns_safe_timeout_without_starting_ssh(self):
        gate = threading.Event()
        workers = []

        def resolve(*args):
            workers.append(threading.current_thread())
            gate.wait(2)
            raise socket.gaierror(PASSWORD)

        try:
            with patch.object(ssh_setup.socket, "getaddrinfo", side_effect=resolve), \
                    patch.object(ssh_setup.paramiko, "Transport") as transport:
                with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                    ssh_setup.fetch_host_key(ssh_setup.SSHOptions(
                        "stalled.invalid", connect_timeout=.025))
                self.assertEqual(caught.exception.code, "timeout")
                self.assertNotIn(PASSWORD, str(caught.exception))
                transport.assert_not_called()
        finally:
            gate.set()
            for worker in workers:
                worker.join(1)

    def test_thread_creation_failure_returns_its_resolver_slot(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(ssh_setup, "_DNS_SLOTS", slots), \
                patch.object(ssh_setup.threading.Thread, "start", side_effect=RuntimeError("cannot start")):
            with self.assertRaises(RuntimeError):
                ssh_setup._open_connection(("unresolved.invalid", 22), .1)
        self.assertTrue(slots.acquire(blocking=False))
        self.assertFalse(slots.acquire(blocking=False))
        slots.release()

    def test_dns_failure_releases_slot_without_creating_a_socket(self):
        slots = threading.BoundedSemaphore(1)
        with patch.object(ssh_setup, "_DNS_SLOTS", slots), \
                patch.object(ssh_setup.socket, "getaddrinfo", side_effect=socket.gaierror("synthetic")), \
                patch.object(ssh_setup.socket, "socket") as create_socket:
            with self.assertRaises(socket.gaierror):
                ssh_setup._open_connection(("unknown.invalid", 22), .2)
            create_socket.assert_not_called()
        self.assertTrue(slots.acquire(timeout=.5))
        slots.release()

    def test_all_candidate_connects_share_one_deadline_and_failed_sockets_close(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
                     for port in (101, 102, 103)]
        sockets = []

        class FailingSocket:
            def __init__(self):
                self.timeout = None
                self.closed = False
                sockets.append(self)

            def settimeout(self, timeout):
                self.timeout = timeout

            def connect(self, address):
                time.sleep(min(.04, self.timeout))
                raise TimeoutError("synthetic connect timeout")

            def close(self):
                self.closed = True

        with patch.object(ssh_setup.socket, "getaddrinfo", return_value=addresses), \
                patch.object(ssh_setup.socket, "socket", side_effect=lambda *args: FailingSocket()):
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                ssh_setup._open_connection(("multiple.invalid", 22), .06)
            self.assertLess(time.monotonic() - started, .4)
        self.assertEqual(len(sockets), 2)
        self.assertLess(sockets[1].timeout, sockets[0].timeout)
        self.assertTrue(all(sock.closed for sock in sockets))


class CommandDrainTest(unittest.TestCase):
    def channel(self, stdout=(), stderr=()):
        out, err = list(stdout), list(stderr)
        channel = Mock()
        channel.recv_ready.side_effect = lambda: bool(out)
        channel.recv_stderr_ready.side_effect = lambda: bool(err)
        channel.recv.side_effect = lambda count: out.pop(0)
        channel.recv_stderr.side_effect = lambda count: err.pop(0)
        channel.exit_status_ready.side_effect = lambda: not out and not err
        channel.recv_exit_status.return_value = 0
        return channel

    def test_both_streams_are_drained_before_exit_status_is_read(self):
        channel = self.channel([b"one", b"two"], [b"warning", b"details"])
        transport = Mock(open_session=Mock(return_value=channel))
        code, output = ssh_setup._run_command(transport, "fixed-command", timeout=1, stage="verify", capture=True)
        self.assertEqual((code, output), (0, b"onetwo"))
        self.assertEqual(channel.recv.call_count, 2)
        self.assertEqual(channel.recv_stderr.call_count, 2)
        channel.close.assert_called_once()

    def test_excess_output_is_bounded_and_channel_is_closed(self):
        channel = self.channel([b"x" * (ssh_setup._MAX_OUTPUT + 1)])
        with self.assertRaises(ssh_setup.SSHSetupError) as caught:
            ssh_setup._run_command(Mock(open_session=Mock(return_value=channel)), "fixed", timeout=1, stage="install")
        self.assertEqual(caught.exception.code, "output_limit")
        channel.recv_exit_status.assert_not_called()
        channel.close.assert_called_once()

    def test_stalled_command_times_out_without_raw_remote_error_text(self):
        channel = self.channel()
        channel.exit_status_ready.return_value = False
        channel.exit_status_ready.side_effect = None
        with patch.object(ssh_setup.time, "monotonic", side_effect=[0, 2]):
            with self.assertRaises(ssh_setup.SSHSetupError) as caught:
                ssh_setup._run_command(Mock(open_session=Mock(return_value=channel)), "fixed", timeout=1, stage="install")
        self.assertEqual(caught.exception.code, "timeout")
        channel.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
