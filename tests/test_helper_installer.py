"""Installer transactions are tested only inside temporary, sourced sandboxes."""
import builtins
import json
import os
import re
import shutil
import stat
import subprocess
import symtable
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "deploy_helper.sh"
BASH = shutil.which("bash")


class InstallerContractTest(unittest.TestCase):
    def test_embedded_python_programs_compile(self):
        source = SCRIPT.read_text(encoding="utf-8")
        programs = re.findall(r"<<'PY'\n(.*?)\nPY", source, re.DOTALL)
        self.assertEqual(len(programs), 3)
        for program in programs:
            compile(program, str(SCRIPT), "exec")

    def test_embedded_python_programs_have_no_unbound_global_names(self):
        source = SCRIPT.read_text(encoding="utf-8")
        programs = re.findall(r"<<'PY'\n(.*?)\nPY", source, re.DOTALL)
        for index, program in enumerate(programs):
            table = symtable.symtable(program, str(SCRIPT), "exec")
            bound = set(dir(builtins)) | {symbol.get_name() for symbol in table.get_symbols()
                                         if symbol.is_assigned() or symbol.is_imported()}

            def unresolved(scope):
                names = {symbol.get_name() for symbol in scope.get_symbols()
                         if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in bound}
                return names | set().union(*(unresolved(child) for child in scope.get_children()))

            with self.subTest(program=index):
                self.assertEqual(unresolved(table), set())

    def test_dependencies_and_backup_precede_service_mutation(self):
        source = SCRIPT.read_text(encoding="utf-8")
        main = source[source.index("main() {"):]
        self.assertLess(main.index("preflight_sources"), main.index("prepare_candidate"))
        self.assertLess(main.index("prepare_candidate"), main.index("backup_current"))
        self.assertLess(main.index("backup_current"), main.index("commit_candidate"))
        self.assertIn("trap 'exit 143' TERM", source)
        self.assertIn("trap 'finish_install", source)
        self.assertIn('chown -hR root:', source)
        for command in ("ufw enable", "ufw reset", "ufw delete", "usermod", "apt-get upgrade"):
            self.assertNotIn(command, source)


@unittest.skipUnless(BASH and os.name != "nt", "Bash transaction tests run on Linux CI")
class InstallerTransactionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_function(self, body):
        # Sourcing exposes the real functions without running main or apt.
        # Every managed path is redirected to this test's private directory.
        prelude = r'''
source "$1"
INSTALL_DIR="$2/install"
CREDENTIAL_DIR="$2/credentials"
SERVICE_FILE="$2/tg-helper.service"
BACKUP_ROOT="$2/backups"
WORK_PARENT="$2"
LOCK_DIR="$2/locks"
WORK_DIR="$2/.tg-helper-setup.test"
mkdir -p "$WORK_DIR"
systemctl() { printf '%s\n' "$*" >> "$WORK_PARENT/systemctl-events"; return 0; }
timeout() { shift; "$@"; }
chown() { :; }
stat() {
    if [[ "$1" == -c && "$2" == %u ]]; then printf '0\n'; else command stat "$@"; fi
}
install() {
    local args=()
    while (($#)); do
        case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    command install "${args[@]}"
}
'''
        result = subprocess.run([BASH, "-c", prelude + body, "test", str(SCRIPT), str(self.root)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_script_parses_and_automatic_mode_rejects_legacy(self):
        subprocess.run([BASH, "-n", str(SCRIPT)], check=True)
        result = subprocess.run([BASH, str(SCRIPT), "--allow-legacy", "--result-file", str(self.root / "result.json")],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not allow legacy", result.stderr)

    def test_rollback_restores_existing_sources_credentials_unit_and_activation(self):
        install = self.root / "install"
        install.mkdir()
        (install / "helper_server.py").write_text("old-server")
        (install / "old-venv-marker").write_text("previous runtime")
        credentials = self.root / "credentials"
        credentials.mkdir(mode=0o750)
        for name in ("token", "server.key", "server.crt"):
            (credentials / name).write_text("previous-" + name)
        unit = self.root / "tg-helper.service"
        unit.write_text("old-unit")
        self.run_function(r'''
backup_current
mv "$INSTALL_DIR" "$WORK_DIR/previous-install"
PREVIOUS_MOVED=true
mkdir "$INSTALL_DIR"
printf new > "$INSTALL_DIR/helper_server.py"
CANDIDATE_MOVED=true
for name in token server.key server.crt; do printf new > "$CREDENTIAL_DIR/$name"; done
printf new-unit > "$SERVICE_FILE"
restore_service
''')
        self.assertEqual((install / "helper_server.py").read_text(), "old-server")
        self.assertEqual((install / "old-venv-marker").read_text(), "previous runtime")
        self.assertEqual(unit.read_text(), "old-unit")
        for name in ("token", "server.key", "server.crt"):
            self.assertEqual((credentials / name).read_text(), "previous-" + name)
        self.assertEqual(stat.S_IMODE(next((self.root / "backups").iterdir()).stat().st_mode), 0o700)
        events = (self.root / "systemctl-events").read_text()
        self.assertIn("start tg-helper.service", events)

    def test_failed_rollback_keeps_private_recovery_directory(self):
        result = self.run_function(r'''
MUTATING=true
restore_service() { return 1; }
if finish_install 143; then exit 1; else [[ $? == 143 ]]; fi
[[ -d "$WORK_DIR" ]]
''')
        self.assertIn("needs attention", result.stderr)

    def test_prepared_and_moved_certbot_renew_hook_remains_executable(self):
        credentials = self.root / "credentials"
        credentials.mkdir()
        for name in ("token", "server.key", "server.crt"):
            (credentials / name).write_text("synthetic-" + name)
        self.run_function(r'''
apt-get() { :; }
python3() {
    [[ "$1 $2" == '-m venv' ]] || return 1
    mkdir -p "$3/bin"
    printf '#!/bin/sh\nexit 0\n' > "$3/bin/python"
    chmod 0700 "$3/bin/python"
}
prepare_candidate
[[ -x "$WORK_DIR/candidate/helper_registry_renew.sh" ]]
mv "$WORK_DIR/candidate" "$INSTALL_DIR"
chmod -R g+rX,o-rwx "$INSTALL_DIR"
[[ -x "$INSTALL_DIR/helper_registry_renew.sh" ]]
[[ "$(command stat -c %a "$INSTALL_DIR/helper_registry_renew.sh")" == 750 ]]
''')

    def test_busy_install_lock_prevents_preparation_or_service_mutation(self):
        self.run_function(r'''
acquire_install_lock
export -f stat install
if bash -c '
    source "$1"
    LOCK_DIR="$2/locks"
    WORK_PARENT="$2"
    preflight_host() { :; }
    preflight_sources() { :; }
    prepare_candidate() { touch "$WORK_PARENT/preparation-ran"; }
    main
' test "$1" "$WORK_PARENT" 2> "$WORK_PARENT/lock-error"; then
    exit 1
fi
grep -q 'already running' "$WORK_PARENT/lock-error"
[[ ! -e "$WORK_PARENT/preparation-ran" ]]
[[ ! -e "$WORK_PARENT/systemctl-events" ]]
''')

    def test_result_file_is_private_and_stdout_does_not_contain_credentials(self):
        openssl = shutil.which("openssl")
        if not openssl:
            self.skipTest("OpenSSL is unavailable")
        credentials = self.root / "credentials"
        credentials.mkdir()
        install = self.root / "install"
        install.mkdir()
        shutil.copy2(SCRIPT.parent / "helper_pairing.py", install / "helper_pairing.py")
        token = "synthetic-only-token-" + "a" * 40
        (credentials / "token").write_text(token)
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=helper-test", "-keyout", str(credentials / "server.key"),
                        "-out", str(credentials / "server.crt")], capture_output=True, check=True)
        result = self.run_function('RESULT_FILE="$WORK_PARENT/result.json"\nwrite_result\n')
        output = self.root / "result.json"
        value = json.loads(output.read_text())
        self.assertEqual(set(value), {"host", "port", "fingerprint", "token"})
        self.assertEqual(value["token"], token)
        self.assertEqual(value["port"], 8444)
        self.assertRegex(value["fingerprint"], r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertNotIn(value["fingerprint"], result.stdout + result.stderr)
