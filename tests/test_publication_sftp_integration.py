"""Real local SSH/SFTP protocol regression tests; synthetic in-memory files only."""
import errno
import hashlib
import socket
import stat
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

import paramiko

from tests import test_update_publication as fixtures
SFTP, WEBROOT, publisher = fixtures.SFTP, fixtures.WEBROOT, fixtures.publisher
from utils import ssh_setup


class _Auth(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ('test', 'synthetic') else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class _Handle(paramiko.SFTPHandle):
    def __init__(self, owner, path, flags):
        super().__init__(flags)
        self.owner, self.path = owner, path

    def read(self, offset, length):
        if self.path.endswith('/TgWsProxy_windows.exe'):
            self.owner.read_started.set()
            if self.owner.stall_once:
                stall, self.owner.stall_once = self.owner.stall_once, 0
                self.owner.closed.wait(stall)
            if self.owner.delay:
                self.owner.closed.wait(self.owner.delay)
        self.owner.read_count += 1
        if self.owner.closed.is_set():
            return b''
        return self.owner.fs.nodes.get(self.path, (0, b''))[1][offset:offset + length]

    def write(self, offset, data):
        mode, old = self.owner.fs.nodes[self.path]
        self.owner.fs.nodes[self.path] = (mode, old[:offset] + data + old[offset + len(data):])
        return paramiko.SFTP_OK


class _Protocol(paramiko.SFTPServerInterface):
    def __init__(self, server, *, owner):
        super().__init__(server)
        self.owner = owner

    def _call(self, function, *args):
        try:
            result = function(*args)
            return paramiko.SFTP_OK if result is None else result
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno or errno.EIO)

    def lstat(self, path):
        def get():
            source = self.owner.fs.lstat(path)
            result = paramiko.SFTPAttributes()
            result.st_mode, result.st_size = source.st_mode, source.st_size
            return result
        return self._call(get)

    stat = lstat

    def open(self, path, flags, attr):
        import os
        def get():
            if flags & os.O_CREAT:
                if flags & os.O_EXCL and path in self.owner.fs.nodes:
                    raise FileExistsError(errno.EEXIST, 'exists')
                self.owner.fs.nodes[path] = (stat.S_IFREG | 0o600, b'')
            if path not in self.owner.fs.nodes:
                raise FileNotFoundError(errno.ENOENT, 'missing')
            return _Handle(self.owner, path, flags)
        return self._call(get)

    def mkdir(self, path, attr):
        return self._call(self.owner.fs.mkdir, path, attr.st_mode or 0o700)

    def chattr(self, path, attr):
        return self._call(self.owner.fs.chmod, path, attr.st_mode)

    def remove(self, path):
        if self.owner.cleanup_stall:
            self.owner.closed.wait(self.owner.cleanup_stall)
        return self._call(self.owner.fs.remove, path)

    def rmdir(self, path):
        return self._call(self.owner.fs.rmdir, path)

    def rename(self, source, destination):
        return self._call(self.owner.fs.rename, source, destination)

    def posix_rename(self, source, destination):
        return self._call(self.owner.fs.posix_rename, source, destination)

    def list_folder(self, path):
        result = []
        for name in self.owner.fs.listdir(path):
            attrs = self.lstat(path + '/' + name)
            attrs.filename = name
            result.append(attrs)
        return result


class LocalSFTP:
    def __init__(self, delay=0, stall_once=0):
        self.fs, self.delay, self.read_count = SFTP(), delay, 0
        self.stall_once, self.cleanup_stall = stall_once, 0
        self.closed, self.read_started = threading.Event(), threading.Event()
        self.client_socket, self.server_socket = socket.socketpair()
        self.client = paramiko.Transport(self.client_socket)
        self.server = paramiko.Transport(self.server_socket)
        self.key = paramiko.RSAKey.generate(2048)
        self.server.add_server_key(self.key)
        self.server.set_subsystem_handler('sftp', paramiko.SFTPServer, _Protocol, owner=self)
        ready = threading.Event()
        self.server.start_server(event=ready, server=_Auth())
        self.client.start_client(timeout=3)
        self.client.auth_password('test', 'synthetic', fallback=False)
        if not ready.wait(3):
            raise TimeoutError('local handshake')
        self.sftp = paramiko.SFTPClient.from_transport(self.client)
        self.sftp.get_channel().settimeout(2)

    def close(self):
        self.closed.set()
        for resource in (self.sftp, self.client, self.server, self.client_socket, self.server_socket):
            ssh_setup._close_quietly(resource)
        self.client.join(2)
        self.server.join(2)


class PublicationSFTPIntegrationTest(unittest.TestCase):
    def test_real_prefetch_multiple_windows_hashes_exact_bytes(self):
        local = LocalSFTP()
        self.addCleanup(local.close)
        contents = b'MZ' + bytes(range(251)) * 6500
        path = WEBROOT + '/TgWsProxy_windows.exe'
        local.fs.nodes[path] = (stat.S_IFREG | 0o644, contents)
        entry = {'size': len(contents), 'sha256': hashlib.sha256(contents).hexdigest()}
        publisher._remote_hash(local.sftp, path, entry, lambda: local.sftp.get_channel().settimeout(2))
        self.assertGreater(local.read_count, 48)

    def test_total_deadline_reports_timeout_and_cleans_owned_stage(self):
        fixture = fixtures.UpdatePublicationTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        contents = b'MZ' + b'x' * (2 * 1024 * 1024)
        fixture.files['TgWsProxy_windows.exe'].write_bytes(contents)
        fixture.update_checksums()
        local = LocalSFTP(delay=0.001, stall_once=1.5)
        self.addCleanup(local.close)
        options = replace(fixture.options, command_timeout=0.25)
        # Authentication and all wire messages are real. Only the connector is
        # directed to an already-authenticated synthetic local session.
        with patch.object(ssh_setup, '_connect', return_value=(local.client, local.client_socket)), patch.object(
                ssh_setup, '_open_sftp', side_effect=lambda transport, timeout: paramiko.SFTPClient.from_transport(transport)):
            local.client.auth_password = lambda *args, **kwargs: None
            started = time.monotonic()
            with self.assertRaises(publisher.PublicationError) as caught:
                publisher.publish_release(options, ssh_setup._identity(local.key), WEBROOT,
                                          fixture.files, fixture.manifest(), trusted_keys=fixture.trusted_keys)
        self.assertEqual('timeout', caught.exception.code)
        self.assertLess(time.monotonic() - started, 5)
        self.assertNotIn(WEBROOT + '/latest.json', local.fs.nodes)
        self.assertFalse(any('.tmp' in name or '.publish.lock' in name for name in local.fs.nodes))


    def _run_failure(self, *, command_timeout=0.25, delay=0, stall_once=0,
                     cancel=False, cleanup_stall=0, reuse=False):
        fixture = fixtures.UpdatePublicationTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.files['TgWsProxy_windows.exe'].write_bytes(b'MZ' + b'x' * (2 * 1024 * 1024))
        fixture.update_checksums()
        local = LocalSFTP(delay=delay, stall_once=stall_once)
        local.cleanup_stall = cleanup_stall
        self.addCleanup(local.close)
        manifest = fixture.manifest()
        if reuse:
            version = WEBROOT + '/versions/' + fixtures.VERSION
            local.fs.nodes[WEBROOT + '/versions'] = (stat.S_IFDIR | 0o755, None)
            local.fs.nodes[version] = (stat.S_IFDIR | 0o755, None)
            for name, path in fixture.files.items():
                local.fs.nodes[version + '/' + name] = (stat.S_IFREG | 0o644, path.read_bytes())
        stopped = threading.Event()
        stopper = None
        if cancel:
            def cancel_during_read():
                if local.read_started.wait(2):
                    stopped.set()
            stopper = threading.Thread(target=cancel_during_read, daemon=True)
            stopper.start()
        options = replace(fixture.options, command_timeout=command_timeout)
        local.client.auth_password = lambda *args, **kwargs: None
        started = time.monotonic()
        with patch.object(ssh_setup, '_connect', return_value=(local.client, local.client_socket)), patch.object(
                ssh_setup, '_open_sftp', side_effect=lambda transport, timeout: paramiko.SFTPClient.from_transport(transport)):
            with self.assertRaises(publisher.PublicationError) as caught:
                publisher.publish_release(options, ssh_setup._identity(local.key), WEBROOT,
                    fixture.files, manifest, trusted_keys=fixture.trusted_keys, cancel=stopped)
        elapsed = time.monotonic() - started
        if stopper:
            stopper.join(2)
            self.assertFalse(stopper.is_alive())
        self.assertFalse(local.client.is_active())
        self.assertNotIn(WEBROOT + '/latest.json', local.fs.nodes)
        return caught.exception.code, elapsed, local

    def test_slow_drip_cannot_extend_total_deadline(self):
        code, elapsed, local = self._run_failure(delay=0.05)
        self.assertEqual('timeout', code)
        self.assertLess(elapsed, 1.5)
        self.assertFalse(any('.tmp' in n or '.publish.lock' in n for n in local.fs.nodes))

    def test_cancel_interrupts_stalled_read_and_cleanup_uses_fresh_channel(self):
        code, elapsed, local = self._run_failure(command_timeout=5, stall_once=3, cancel=True)
        self.assertEqual('cancelled', code)
        self.assertLess(elapsed, 1.5)
        self.assertFalse(any('.tmp' in n or '.publish.lock' in n for n in local.fs.nodes))

    def test_stalled_cleanup_has_its_own_absolute_bound(self):
        with patch.object(publisher, '_CLEANUP_TIMEOUT', 0.2):
            code, elapsed, local = self._run_failure(stall_once=3, cleanup_stall=3)
        self.assertEqual('timeout', code)
        self.assertLess(elapsed, 1.5)
        self.assertFalse(local.client.is_active())

    def test_existing_version_deadline_and_cancel_are_not_immutable_conflicts(self):
        for cancel in (False, True):
            with self.subTest(cancel=cancel):
                code, elapsed, local = self._run_failure(
                    command_timeout=5 if cancel else 0.25, stall_once=3, cancel=cancel, reuse=True)
                self.assertEqual('cancelled' if cancel else 'timeout', code)
                self.assertLess(elapsed, 1.5)
                self.assertIn(WEBROOT + '/versions/' + fixtures.VERSION + '/TgWsProxy_windows.exe', local.fs.nodes)
                self.assertNotIn(WEBROOT + '/.publish.lock', local.fs.nodes)


if __name__ == '__main__':
    unittest.main()
