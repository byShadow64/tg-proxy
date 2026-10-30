"""Optional registry installer checks run only in redirected temporary paths."""
import os
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from utils.helper_payload import HELPER_PAYLOAD_FILES


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
if not BASH and os.name == "nt":
    bundled = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/usr/bin/sh.exe"
    if bundled.is_file():
        BASH = str(bundled)


class RegistryPayloadContractTest(unittest.TestCase):
    def test_installer_allowlist_matches_public_upload_payload(self):
        source = (ROOT / "deploy_helper.sh").read_text(encoding="utf-8")
        names = re.search(r"PAYLOAD_FILES=\((.*?)\)\n", source, re.S).group(1).split()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(HELPER_PAYLOAD_FILES), set(names))
        for name in names:
            self.assertTrue((ROOT / name).is_file(), name)
            self.assertNotIn("PRIVATE KEY-----", (ROOT / name).read_text(encoding="utf-8"))

    def test_renewal_only_restarts_proof_and_does_not_force_issuance(self):
        source = (ROOT / "helper_registry_renew.sh").read_text(encoding="utf-8")
        self.assertNotIn("tg-helper.service", source)
        self.assertNotIn("server.key", source)
        self.assertNotIn("server.crt", source)
        self.assertIn('"/etc/letsencrypt/live/$REGISTRY_CERT_NAME"', source)
        self.assertIn("-verify_ip", source)
        self.assertIn("-m 0600", source)
        installer = (ROOT / "deploy_helper_registry.sh").read_text(encoding="utf-8")
        self.assertNotIn("--force-renewal", installer)
        prepare = (ROOT / 'deploy_helper.sh').read_text(encoding='utf-8')
        self.assertIn('chmod 0750 "$WORK_DIR/candidate/helper_registry_renew.sh"', prepare)

    def test_certbot_uses_console_entrypoint_in_candidate_and_renewal(self):
        installer = (ROOT / "deploy_helper_registry.sh").read_text(encoding="utf-8")
        renewal = (ROOT / "tg-helper-certbot-renew.service").read_text(encoding="utf-8")
        self.assertNotIn("-m certbot", installer + renewal)
        self.assertIn('"$WORK_DIR/candidate/venv/bin/certbot" --version', installer)
        self.assertIn('"$WORK_DIR/candidate/venv/bin/certbot" certonly --standalone', installer)
        self.assertIn('ExecStart=/opt/tg-helper/venv/bin/certbot renew ', renewal)
        commit = (ROOT / "deploy_helper.sh").read_text(encoding="utf-8").split('commit_candidate() {', 1)[1]
        self.assertLess(commit.index('CANDIDATE_MOVED=true'), commit.index('registry_relocate_entrypoints'))
        self.assertLess(commit.index('registry_relocate_entrypoints'), commit.index('systemctl start "$SERVICE"'))


class CertbotConsoleEntrypointTest(unittest.TestCase):
    @staticmethod
    def fixture_package(folder):
        package = folder / "certbot"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "main.py").write_text("import json, sys\ndef main():\n print(json.dumps(sys.argv[1:]))\n return 0\n", encoding="utf-8")
        metadata = folder / "certbot-5.8.0.dist-info"
        metadata.mkdir()
        (metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: certbot\nVersion: 5.8.0\n", encoding="utf-8")
        (metadata / "entry_points.txt").write_text("[console_scripts]\ncertbot = certbot.main:main\n", encoding="utf-8")

    @staticmethod
    def relocation_program():
        installer = (ROOT / "deploy_helper_registry.sh").read_text(encoding="utf-8")
        section = installer.split("registry_relocate_entrypoints() {", 1)[1]
        return re.search(r"<<'PY'\n(.*?)\nPY", section, re.S).group(1)

    def test_package_without_main_module_works_via_relocated_console_script(self):
        # Production is a Linux /opt path. Windows' development venv may have
        # spaces, which the POSIX shebang guard correctly rejects.
        interpreter = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve())
        if any(char.isspace() for char in interpreter):
            self.skipTest("No whitespace-free base interpreter for POSIX console fixture")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            packages = root / "packages"
            self.fixture_package(packages)
            environment = dict(os.environ, PYTHONPATH=str(packages))
            invalid = subprocess.run([sys.executable, "-m", "certbot", "--version"], env=environment,
                                     capture_output=True, text=True, timeout=5)
            self.assertNotEqual(0, invalid.returncode)
            self.assertIn("__main__", invalid.stderr)
            script = root / "certbot"
            script.write_text("#!/deleted/candidate/venv/bin/python\n", encoding="utf-8")
            with patch.object(sys, "path", [str(packages), *sys.path]), patch.object(
                    sys, "argv", ["relocate", str(script), interpreter]):
                exec(compile(self.relocation_program(), "registry-relocation", "exec"), {})
            self.assertEqual("#!" + interpreter, script.read_text(encoding="utf-8").splitlines()[0])
            for arguments in (["--version"], ["certonly", "--standalone"], ["renew", "--non-interactive"]):
                result = subprocess.run([sys.executable, str(script), *arguments], env=environment,
                                        capture_output=True, text=True, check=True, timeout=5)
                self.assertEqual(arguments, json.loads(result.stdout))

    @unittest.skipUnless(BASH and os.name != "nt", "Kernel shebang and moved venv need POSIX")
    def test_actual_moved_venv_console_executable_uses_final_interpreter(self):
        import venv
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            candidate = root / "candidate"
            runtime = root / "installed"
            venv.EnvBuilder(with_pip=False).create(candidate / "venv")
            interpreter = candidate / "venv/bin/python"
            packages = Path(subprocess.check_output([str(interpreter), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"], text=True).strip())
            self.fixture_package(packages)
            script = candidate / "venv/bin/certbot"
            script.write_text("#!" + str(interpreter) + "\nfrom certbot.main import main\nraise SystemExit(main())\n", encoding="utf-8")
            script.chmod(0o750)
            subprocess.run([str(script), "--version"], capture_output=True, check=True, timeout=5)
            candidate.rename(runtime)
            result = subprocess.run([BASH, "-c", 'source "$1/deploy_helper.sh"; INSTALL_DIR="$2"; REGISTRY_MODE=true; registry_relocate_entrypoints',
                                     "test", str(ROOT), str(runtime)], capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            result = subprocess.run([str(runtime / "venv/bin/certbot"), "renew"], capture_output=True, text=True, check=True, timeout=5)
            self.assertEqual(["renew"], json.loads(result.stdout))


@unittest.skipUnless(BASH, "A local Bash interpreter is unavailable")
class RegistryInstallerSandboxTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.profile_dir = self.root / "apps"
        self.profile_dir.mkdir()
        self.ufw_state = self.root / "ufw.json"
        self.ufw_program = self.root / "fake_ufw.py"
        self.ufw_program.write_text('''import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
state = json.loads(path.read_text())
args = sys.argv[2:]
if args[:1] == ['status']:
 print('Status: ' + ('active' if state['active'] else 'inactive'))
 if state['active']:
  if args[1:] == ['verbose']:
   print('Default: deny (incoming), allow (outgoing), disabled (routed)')
  print('To                         Action      From')
  for index, row in enumerate(state['rules'],1):
   prefix = '[%2d] ' % index if args[1:] == ['numbered'] else ''
   print(prefix + '%-28s  %-12s  %s%s' % (row['to'],row['action'],row['source'],(' # '+row['comment']) if row.get('comment') else ''))
elif len(args)==12 and args[:5]==['allow','in','proto','tcp','from'] and args[6:9]==['to','any','port'] and args[10]=='comment':
 port, comment, v6 = args[9],args[11],args[5]=='::/0'
 assert args[5] in {'0.0.0.0/0','::/0'}
 to, source = port+'/tcp'+(' (v6)' if v6 else ''),'Anywhere'+(' (v6)' if v6 else '')
 found = next((r for r in state['rules'] if r['to']==to and r['source']==source and r['action']=='ALLOW IN'),None)
 if found is None:
  state['rules'].append(dict(to=to,action='ALLOW IN',source=source,comment=comment))
 else:
  found['comment']=comment
 state.setdefault('mutations',[]).append(['allow',port])
 path.write_text(json.dumps(state))
 if state.get('fail_after_add') == port:
  raise SystemExit(1)
elif len(args)==14 and args[:7]==['--force','delete','allow','in','proto','tcp','from'] and args[8:11]==['to','any','port'] and args[12]=='comment':
 if state.get('renumber_before_delete'):
  state['rules'].insert(0,dict(to='2222/tcp',source='Anywhere',action='ALLOW IN',comment='concurrent owner SSH'))
  state['renumber_before_delete']=False
 v6=args[7]=='::/0'
 to, source=args[11]+'/tcp'+(' (v6)' if v6 else ''),'Anywhere'+(' (v6)' if v6 else '')
 index=next(i for i,r in enumerate(state['rules']) if r['to']==to and r['source']==source and r['action']=='ALLOW IN')
 removed=state['rules'].pop(index)
 state.setdefault('mutations',[]).append(['delete',removed['to']])
 path.write_text(json.dumps(state))
else:
 raise SystemExit('Unexpected UFW operation: '+repr(args))
''', encoding="utf-8")

    def firewall_state(self, rows=(), *, active=True, **extra):
        self.ufw_state.write_text(json.dumps(dict(active=active, rules=list(rows), **extra)), encoding="utf-8")

    @staticmethod
    def rule(destination, *, source="Anywhere", action="ALLOW IN", comment="owner rule"):
        return dict(to=destination, source=source, action=action, comment=comment)

    def current_firewall(self):
        return json.loads(self.ufw_state.read_text(encoding="utf-8"))

    def execute(self, body):
        # Every mutable managed path is replaced before invoking ANY function.
        # Systemd, ownership and remote-agent calls are private mocks. This also
        # works in bundled Windows MSYS Bash; Linux chmod/UID claims are separate.
        prelude = r'''
export PATH="${BASH%/*}:$PATH"
source "$1/deploy_helper.sh"
PYTHON_FOR_TEST="$3"
python3() { "$PYTHON_FOR_TEST" "$@"; }
UFW_FIXTURE="$2/fake_ufw.py"
ufw() { "$PYTHON_FOR_TEST" "$UFW_FIXTURE" "$WORK_PARENT/ufw.json" "$@"; }
INSTALL_DIR="$2/install"
CREDENTIAL_DIR="$2/credentials"
SERVICE_FILE="$2/units/tg-helper.service"
BACKUP_ROOT="$2/backups"
BACKUP_DIR="$2/backups/attempt"
WORK_PARENT="$2"
WORK_DIR="$2/.tg-helper-setup.test"
REGISTRY_STATE_DIR="$2/state"
REGISTRY_UFW_APP_DIR="$2/apps"
PUBLIC_IP=9.9.9.9
LOCK_DIR="$2/locks"
mkdir -p "$WORK_DIR" "$CREDENTIAL_DIR" "$REGISTRY_STATE_DIR" "$2/units" "$INSTALL_DIR" "$BACKUP_DIR"
systemctl() { printf '%s\n' "$*" >> "$WORK_PARENT/systemctl-events"; return 0; }
timeout() { shift; "$@"; }
runuser() { printf '%s\n' "$*" >> "$WORK_PARENT/agent-events"; return 1; }
chown() { :; }
chmod() { :; }
stat() { printf '750 0 0\n'; }
install() {
    local args=()
    [[ "$1" == -d ]] || return 1
    shift
    while (($#)); do
        case "$1" in -o|-g|-m) shift 2 ;; *) args+=("$1"); shift ;; esac
    done
    mkdir -p "${args[@]}"
}
'''
        if not self.ufw_state.exists():
            self.firewall_state(active=False)
        result = subprocess.run([BASH, "-c", prelude + body, "test", ROOT.as_posix(), self.root.as_posix(), Path(sys.executable).as_posix()],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        return result

    def test_all_public_scripts_parse(self):
        for name in ("deploy_helper.sh", "deploy_helper_registry.sh", "helper_registry_renew.sh"):
            subprocess.run([BASH, "-n", str(ROOT / name)], check=True, capture_output=True)

    def test_existing_private_upgrade_is_refused_without_separate_approval(self):
        self.execute(r'''
REGISTRY_MODE=true
printf old > "$INSTALL_DIR/helper_server.py"
ss() { :; }
openssl() { :; }
command() { if [[ "$*" == '-v systemd-run' ]]; then return 0; fi; builtin command "$@"; }
if registry_preflight 2> "$WORK_PARENT/error"; then exit 1; fi
grep -q 'explicit --allow-existing-private-upgrade' "$WORK_PARENT/error"
[[ ! -f "$WORK_PARENT/systemctl-events" ]]
ALLOW_EXISTING_PRIVATE_UPGRADE=true
registry_preflight
''')

    def test_uncertain_attempt_retains_agent_identity_and_restores_exact_private_files(self):
        result = self.execute(r'''
REGISTRY_MODE=true
for name in token server.key server.crt; do printf 'old-%s' "$name" > "$CREDENTIAL_DIR/$name"; done
printf old-source > "$INSTALL_DIR/helper_server.py"
printf old-unit > "$SERVICE_FILE"
backup_current
REGISTRY_MUTATING=true
REGISTRY_ENROLL_ATTEMPTED=true
REGISTRY_WAS_CONFIGURED=false
CANDIDATE_MOVED=false
printf retained-agent-key > "$REGISTRY_STATE_DIR/registry-agent.key"
printf partial-new-config > "$REGISTRY_STATE_DIR/registry-config.json"
for name in token server.key server.crt; do printf new > "$CREDENTIAL_DIR/$name"; done
mkdir -p "$WORK_DIR/credentials"
printf synthetic-crt > "$WORK_DIR/credentials/server.crt"
restore_service
[[ "$(cat "$REGISTRY_STATE_DIR/registry-agent.key")" == retained-agent-key ]]
[[ ! -f "$REGISTRY_STATE_DIR/registry-config.json" ]]
for name in token server.key server.crt; do [[ "$(cat "$CREDENTIAL_DIR/$name")" == "old-$name" ]]; done
[[ "$(cat "$SERVICE_FILE")" == old-unit ]]
[[ "$(cat "$INSTALL_DIR/helper_server.py")" == old-source ]]
grep -q -- '--disable' "$WORK_PARENT/agent-events"
''')
        self.assertIn("retained for owner review", result.stderr)

    def test_rollback_restores_preexisting_registry_identity_and_optional_units(self):
        self.execute(r'''
REGISTRY_MODE=true
printf previous-key > "$REGISTRY_STATE_DIR/registry-agent.key"
printf previous-config > "$REGISTRY_STATE_DIR/registry-config.json"
printf previous-env > "$CREDENTIAL_DIR/registry-agent.env"
printf previous-proof-unit > "$WORK_PARENT/units/tg-helper-enroll.service"
backup_current
REGISTRY_MUTATING=true
REGISTRY_ENROLL_ATTEMPTED=true
printf new-key > "$REGISTRY_STATE_DIR/registry-agent.key"
printf new-env > "$CREDENTIAL_DIR/registry-agent.env"
registry_before_restore
registry_restore_files
[[ "$(cat "$REGISTRY_STATE_DIR/registry-agent.key")" == previous-key ]]
[[ "$(cat "$REGISTRY_STATE_DIR/registry-config.json")" == previous-config ]]
[[ "$(cat "$CREDENTIAL_DIR/registry-agent.env")" == previous-env ]]
[[ "$(cat "$WORK_PARENT/units/tg-helper-enroll.service")" == previous-proof-unit ]]
[[ ! -f "$WORK_PARENT/agent-events" ]]
''')

    def test_closed_active_firewall_adds_only_ports_and_rollback_preserves_ssh(self):
        original = [self.rule("22/tcp", comment="owner SSH")]
        self.firewall_state(original)
        self.execute('registry_firewall_check\nregistry_prepare_firewall\nregistry_restore_firewall\n')
        state = self.current_firewall()
        self.assertEqual(original, state["rules"])
        self.assertEqual([["allow", "80"], ["allow", "443"], ["delete", "80/tcp"], ["delete", "443/tcp"]], state["mutations"])

    def test_existing_exact_rule_comment_is_preserved_and_successful_rules_reused(self):
        original = [self.rule("80/tcp", comment="existing HTTP owner comment")]
        self.firewall_state(original)
        self.execute('registry_prepare_firewall\n')
        first = self.current_firewall()
        self.assertEqual(original[0], first["rules"][0])
        self.assertEqual([["allow", "443"]], first["mutations"])
        self.execute('registry_prepare_firewall\nregistry_restore_firewall\n')
        self.assertEqual(first, self.current_firewall())

    def test_named_range_and_default_broad_rules_are_reused(self):
        (self.profile_dir / "nginx").write_text('[Nginx Full]\ntitle=Web\nports=80,443/tcp\n', encoding="utf-8")
        for destination in ("Nginx Full", "80:500/tcp", "Anywhere"):
            with self.subTest(destination=destination):
                rows = [self.rule(destination)]
                self.firewall_state(rows)
                self.execute('SETUP_FIREWALL=false\nregistry_firewall_check\nregistry_prepare_firewall\nregistry_restore_firewall\n')
                self.assertEqual(dict(active=True, rules=rows), self.current_firewall())

    def test_no_firewall_refuses_closed_ports_and_never_mutates(self):
        original = [self.rule("22/tcp")]
        self.firewall_state(original)
        result = self.execute('''SETUP_FIREWALL=false
if registry_firewall_check; then exit 1; fi
if registry_prepare_firewall; then exit 1; fi
''')
        self.assertIn("--no-firewall requires owner-approved TCP/80", result.stderr)
        self.assertEqual(dict(active=True, rules=original), self.current_firewall())

    def test_partial_add_failure_still_removes_only_owned_new_rules(self):
        original = [self.rule("22/tcp")]
        self.firewall_state(original, fail_after_add="443")
        self.execute('if registry_prepare_firewall; then exit 1; fi\nregistry_restore_firewall\n')
        self.assertEqual(original, self.current_firewall()["rules"])

    def test_modified_comment_is_not_deleted_during_rollback(self):
        self.firewall_state()
        result = self.execute('''registry_prepare_firewall
python3 - "$WORK_PARENT/ufw.json" <<'PY'
import json, pathlib, sys
path=pathlib.Path(sys.argv[1]); state=json.loads(path.read_text())
state['rules'][0]['comment']='owner changed this rule'
path.write_text(json.dumps(state))
PY
registry_restore_firewall
''')
        self.assertIn("changed or disappeared", result.stderr)
        self.assertEqual([self.rule("80/tcp", comment="owner changed this rule")], self.current_firewall()["rules"])

    def test_inactive_firewall_and_explicit_owner_deny_are_never_changed(self):
        self.firewall_state(active=False)
        self.execute('registry_firewall_check\nregistry_prepare_firewall\nregistry_restore_firewall\n')
        self.assertEqual(dict(active=False, rules=[]), self.current_firewall())
        rows = [self.rule("80/tcp", action="DENY IN", comment="owner block")]
        self.firewall_state(rows)
        result = self.execute('if registry_firewall_check; then exit 1; fi\nif registry_prepare_firewall; then exit 1; fi\n')
        self.assertIn("owner rule will be changed", result.stderr)
        self.assertEqual(dict(active=True, rules=rows), self.current_firewall())

    def test_ipv6_target_does_not_rewrite_ipv4_owner_comments(self):
        rows = [self.rule("80/tcp", comment="IPv4 HTTP")]
        self.firewall_state(rows)
        self.execute('PUBLIC_IP=2606:4700:4700::1111\nregistry_prepare_firewall\nregistry_restore_firewall\n')
        self.assertEqual(rows, self.current_firewall()["rules"])

    def test_rollback_rule_number_drift_cannot_delete_an_unrelated_ssh_rule(self):
        self.firewall_state([self.rule("22/tcp")], renumber_before_delete=True)
        self.execute('registry_prepare_firewall\nregistry_restore_firewall\n')
        self.assertEqual([self.rule("2222/tcp", comment="concurrent owner SSH"), self.rule("22/tcp")], self.current_firewall()["rules"])


if __name__ == "__main__":
    unittest.main()
