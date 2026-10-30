"""Exercise a real frozen auto-update in isolated normal and portable profiles."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from utils.default_config import default_tray_config
from utils.secure_storage import protect_token, unprotect_token


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed_digest_matches(path, expected):
    # ReplaceFileW can briefly deny reads while the updater swaps the EXE.
    # Keep polling through that handoff; a persistent failure still times out.
    try:
        return digest(path) == expected
    except (PermissionError, FileNotFoundError):
        return False


def stop_owned(folder):
    folder = folder.resolve()
    deadline, quiet = time.monotonic() + 15, 0
    while time.monotonic() < deadline:
        owned, helpers = [], []
        for process in psutil.process_iter(['exe']):
            try:
                path = Path(process.info['exe']) if process.info['exe'] else None
                if path is not None and path.is_relative_to(folder) and path.resolve().is_relative_to(folder):
                    arguments = process.cmdline()
                    (helpers if any(arg in ('--apply-update', '--cleanup-update')
                                    for arg in arguments) else owned).append(process)
            except (OSError, psutil.Error):
                pass
        if not owned and not helpers:
            quiet += 1
            if quiet >= 3:
                return
            time.sleep(.1)
            continue
        quiet = 0
        # Stop the installer before the app so it cannot launch a replacement
        # after the cleanup inventory. Rescan for children already in flight.
        for group in (helpers, owned):
            for process in group:
                try:
                    process.terminate()
                except psutil.NoSuchProcess:
                    pass
            _, alive = psutil.wait_procs(group, timeout=.5)
            for process in alive:
                try:
                    process.kill()
                except psutil.NoSuchProcess:
                    pass
            psutil.wait_procs(alive, timeout=.5)
    raise TimeoutError('Isolated update-test processes did not stop')


def verify(old_exe, new_exe, output):
    output.mkdir(parents=True, exist_ok=True)
    new_digest = digest(new_exe)
    results = []
    for portable in (False, True):
        case = Path(tempfile.mkdtemp(prefix='portable-' if portable else 'standard-', dir=output)).resolve()
        executable = case / 'TG Proxy test.exe'
        shutil.copy2(old_exe, executable)
        appdata, temporary, profile = case / 'AppData', case / 'Temp', case / 'Profile'
        for directory in (appdata, temporary, profile):
            directory.mkdir()
        settings = case / 'TgWsProxy_data' if portable else appdata / 'TgWsProxy'
        settings.mkdir()
        with socket.socket() as free:
            free.bind(('127.0.0.1', 0))
            port = free.getsockname()[1]
        token = protect_token('isolated-update-test-token')
        config = default_tray_config()
        config.update(port=port, pool_size=0, dc_ip=[], cfproxy=False, h2=False,
                      cfproxy_user_domain_enabled=True, cfproxy_user_domain=['example.invalid'],
                      check_updates=True, auto_install_updates=True, autostart=False,
                      helper_enabled=False, helper_host='preserve-helper.example.invalid',
                      helper_fingerprint='ab' * 32, helper_token_dpapi=token,
                      language='ru', appearance='dark', custom_update_test='keep-me')
        config_path = settings / 'config.json'
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding='utf-8')
        key_path = settings / 'user-preserve.key'
        key_bytes = b'ISOLATED SYNTHETIC USER KEY; NOT A REAL CREDENTIAL\n'
        key_path.write_bytes(key_bytes)
        for marker in ('.first_run_done_mtproto', '.ipv6_warned'):
            (settings / marker).touch()
        environment = dict(os.environ, APPDATA=str(appdata), LOCALAPPDATA=str(appdata),
                           TEMP=str(temporary), TMP=str(temporary), USERPROFILE=str(profile))
        args = [str(executable), '--dashboard'] + (['--portable'] if portable else [])
        process = subprocess.Popen(args, cwd=case, env=environment)
        log_path = settings / 'proxy.log'
        last_state = None
        try:
            deadline = time.monotonic() + 200
            while time.monotonic() < deadline:
                stages = list(case.glob('.tgproxy-update-*'))
                for stage in stages:
                    state = stage / 'state.json'
                    if state.exists():
                        try:
                            last_state = json.loads(state.read_text(encoding='utf-8')).get('stage')
                        except (OSError, ValueError):
                            pass
                logs = log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else ''
                if 'Update failed' in logs:
                    raise RuntimeError('The application reported an update failure; see its isolated log')
                if (installed_digest_matches(executable, new_digest) and not stages and
                        not (case / '.tgproxy-update.lock').exists() and
                        process.poll() is not None and 'Dashboard ready' in logs):
                    break
                if last_state in {'failed', 'rolled_back', 'rollback_failed'}:
                    raise RuntimeError('Installer state: ' + last_state)
                time.sleep(.2)
            else:
                raise TimeoutError('Auto-update did not complete; last state=' + str(last_state))
            saved = json.loads(config_path.read_text(encoding='utf-8'))
            if any(saved.get(k) != v for k, v in config.items()):
                raise AssertionError('Settings were not preserved')
            if key_path.read_bytes() != key_bytes or unprotect_token(saved['helper_token_dpapi']) != 'isolated-update-test-token':
                raise AssertionError('User key or encrypted token changed')
            with socket.create_connection(('127.0.0.1', port), timeout=5):
                pass
            if process.poll() is None:
                raise AssertionError('The original application is still running')
            result = dict(portable=portable, status='passed', version_sha256=new_digest,
                          settings_preserved=True, helper_token_preserved=True,
                          key_preserved=True, previous_exe_removed=True,
                          helper_removed=True, restarted_listener=True,
                          last_installer_state=last_state)
            results.append(result)
            print(json.dumps(result), flush=True)
        except BaseException:
            print(json.dumps({'portable': portable, 'case': str(case), 'state': last_state}), flush=True)
            raise
        finally:
            stop_owned(case)
    (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old-exe', type=Path, required=True)
    parser.add_argument('--new-exe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    verify(args.old_exe.resolve(strict=True), args.new_exe.resolve(strict=True), args.output.resolve())


if __name__ == '__main__':
    main()
