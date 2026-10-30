#!/usr/bin/env bash
# Install or upgrade only the TG Proxy helper on a systemd Ubuntu/Debian host.
set -euo pipefail
set +x

SECURE_PORT=8444
LEGACY_PORT=8443
SERVICE_USER=tg-helper
SERVICE=tg-helper.service
INSTALL_DIR=/opt/tg-helper
CREDENTIAL_DIR=/etc/tg-helper
SERVICE_FILE=/etc/systemd/system/tg-helper.service
BACKUP_ROOT=/var/backups/tg-helper
WORK_PARENT=/opt
LOCK_DIR=/run/tg-helper-setup
LOCK_FD=
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ALLOW_LEGACY=false
SETUP_FIREWALL=true
RESULT_FILE=
WORK_DIR=
BACKUP_DIR=
MUTATING=false
PREVIOUS_MOVED=false
CANDIDATE_MOVED=false
WAS_ACTIVE=false
WAS_ENABLED=false
HAD_CREDENTIAL_DIR=false
PAYLOAD_FILES=(helper_server.py helper_pairing.py deploy_helper.sh tg-helper.service LICENSE
    proxy/__init__.py proxy/config.py proxy/balancer.py proxy/utils.py proxy/project.py proxy/http_transport.py proxy/route_policy.py
    helper_registry.py helper_registry_agent.py helper_enrollment.py deploy_helper_registry.sh
    proxy/registry_protocol.py proxy/registry_helper.py helper_requirements.txt helper_registry_requirements.txt
    helper_certbot_requirements.txt tg-helper-registry-agent.service tg-helper-registry-agent.timer
    tg-helper-enroll.service tg-helper-certbot-renew.service tg-helper-certbot-renew.timer helper_registry_renew.sh)
. "$SOURCE_DIR/deploy_helper_registry.sh"

die() { echo "$*" >&2; return 1; }

usage() {
    cat <<'EOF'
Usage: sudo bash deploy_helper.sh [--no-firewall] [--result-file /private/result.json]
       sudo bash deploy_helper.sh --allow-legacy

Installs TLS-pinned v2 on TCP/8444. Existing certificate and token are retained.
--result-file writes host, port, fingerprint and token as root-only JSON and
does not print credentials. Automated installs never enable legacy v1.
Only an already-active UFW receives an allow rule; no firewall is enabled.
--registry-mode --registry-url HTTPS --registry-trust-spki PUBLIC_SPKI --public-ip IP
explicitly allows registered program devices after a CA/IP ownership callback.
Existing private servers additionally require --allow-existing-private-upgrade.
No web configuration is overwritten; TCP/80 and TCP/443 must be available.
Active UFW receives only missing registry port rules; --no-firewall requires
those ports to be owner-opened. Existing rules and firewall policy are retained.
EOF
}

parse_args() {
    while (($#)); do
        case "$1" in
            --allow-legacy) ALLOW_LEGACY=true; shift ;;
            --no-firewall) SETUP_FIREWALL=false; shift ;;
            --registry-mode) REGISTRY_MODE=true; shift ;;
            --allow-existing-private-upgrade) ALLOW_EXISTING_PRIVATE_UPGRADE=true; shift ;;
            --registry-url|--registry-trust-spki|--public-ip|--registry-config|--registry-public-key)
                [[ $# -ge 2 && -n "$2" ]] || { die "A registry option needs a value"; return 1; }
                case "$1" in
                    --registry-url) REGISTRY_URL=$2 ;;
                    --registry-trust-spki) REGISTRY_TRUST_SPKI=$2 ;;
                    --public-ip) PUBLIC_IP=$2 ;;
                    --registry-config) REGISTRY_CONFIG=$2 ;;
                    --registry-public-key) REGISTRY_PUBLIC_KEY=$2 ;;
                esac
                shift 2 ;;
            --result-file)
                [[ $# -ge 2 && -n "$2" ]] || { die "--result-file needs a path"; return 1; }
                RESULT_FILE=$2; shift 2 ;;
            -h|--help) usage; return 2 ;;
            *) die "Unknown installer option"; return 1 ;;
        esac
    done
    if [[ -n "$RESULT_FILE" ]]; then
        [[ "$RESULT_FILE" == /* && -d "$(dirname -- "$RESULT_FILE")" && ! -d "$RESULT_FILE" ]] \
            || { die "Result must be an absolute file path in an existing directory"; return 1; }
        [[ "$ALLOW_LEGACY" == false ]] \
            || { die "Automated installation does not allow legacy mode"; return 1; }
    fi
    registry_validate_options
}

preflight_host() {
    [[ ${EUID} -eq 0 ]] || { die "Run this installer as root"; return 1; }
    [[ -r /etc/os-release ]] || { die "Cannot identify the host OS"; return 1; }
    . /etc/os-release
    case "${ID:-}" in ubuntu|debian) ;; *) die "Ubuntu or Debian is required"; return 1 ;; esac
    [[ -d /run/systemd/system ]] || { die "A running systemd host is required"; return 1; }
    for command in systemctl apt-get install cp mv stat mktemp timeout flock; do
        command -v "$command" >/dev/null || { die "A required system tool is missing"; return 1; }
    done
    systemctl show-environment >/dev/null || { die "Cannot reach systemd"; return 1; }
    for path in "$INSTALL_DIR" "$CREDENTIAL_DIR"; do
        [[ ! -L "$path" && ( ! -e "$path" || -d "$path" ) ]] \
            || { die "A managed helper directory has an unsafe type"; return 1; }
    done
    [[ ! -L "$SERVICE_FILE" && ( ! -e "$SERVICE_FILE" || -f "$SERVICE_FILE" ) ]] \
        || { die "The helper service unit has an unsafe type"; return 1; }
    for name in token server.key server.crt; do
        path="$CREDENTIAL_DIR/$name"
        [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] \
            || { die "A helper credential has an unsafe type"; return 1; }
    done
    registry_preflight
}

preflight_sources() {
    for relative in "${PAYLOAD_FILES[@]}"; do
        [[ -f "$SOURCE_DIR/$relative" && ! -L "$SOURCE_DIR/$relative" ]] \
            || { die "The helper source payload is incomplete"; return 1; }
    done
}

acquire_install_lock() {
    local lock_file="$LOCK_DIR/install.lock"
    [[ ! -L "$LOCK_DIR" && ( ! -e "$LOCK_DIR" || -d "$LOCK_DIR" ) ]] \
        || { die "The helper installer lock directory has an unsafe type"; return 1; }
    if [[ -e "$LOCK_DIR" ]]; then
        [[ "$(stat -c %u "$LOCK_DIR")" == 0 && "$(stat -c %a "$LOCK_DIR")" == 700 ]] \
            || { die "The helper installer lock directory is not private and root-owned"; return 1; }
    else
        install -d -o root -g root -m 0700 "$LOCK_DIR"
    fi
    [[ ! -L "$lock_file" && ( ! -e "$lock_file" || -f "$lock_file" ) ]] \
        || { die "The helper installer lock file has an unsafe type"; return 1; }
    if [[ -e "$lock_file" ]]; then
        [[ "$(stat -c %u "$lock_file")" == 0 && "$(stat -c %a "$lock_file")" == 600 ]] \
            || { die "The helper installer lock file is not private and root-owned"; return 1; }
    fi
    (umask 077; : >> "$lock_file")
    exec {LOCK_FD}>> "$lock_file"
    flock -n "$LOCK_FD" || { die "Another helper installation is already running"; return 1; }
}

prepare_candidate() {
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
    # Dependencies are prepared while the previous helper is still running.
    apt-get -o DPkg::Lock::Timeout=60 update -qq
    apt-get -o DPkg::Lock::Timeout=60 install -y -qq --no-install-recommends \
        python3 python3-venv openssl ca-certificates
    install -d -m 0700 "$WORK_DIR/candidate" "$WORK_DIR/candidate/proxy" "$WORK_DIR/credentials"
    for relative in "${PAYLOAD_FILES[@]}"; do
        install -m 0644 "$SOURCE_DIR/$relative" "$WORK_DIR/candidate/$relative"
    done
    chmod 0755 "$WORK_DIR/candidate/deploy_helper.sh"
    # Certbot executes its deploy hook directly after a successful renewal.
    chmod 0750 "$WORK_DIR/candidate/helper_registry_renew.sh"
    python3 -m venv "$WORK_DIR/candidate/venv"
    "$WORK_DIR/candidate/venv/bin/python" -m pip install --disable-pip-version-check \
        --only-binary=:all: --require-hashes -r "$WORK_DIR/candidate/helper_requirements.txt"
    (
        cd "$WORK_DIR/candidate"
        venv/bin/python -c 'import helper_server; assert helper_server.route_catalog()'
    )
    if [[ -e "$CREDENTIAL_DIR/token" ]]; then
        [[ -s "$CREDENTIAL_DIR/token" ]] || { die "The existing helper token is empty"; return 1; }
        cp -- "$CREDENTIAL_DIR/token" "$WORK_DIR/credentials/token"
    else
        openssl rand -hex 32 > "$WORK_DIR/credentials/token"
    fi
    if [[ -e "$CREDENTIAL_DIR/server.key" || -e "$CREDENTIAL_DIR/server.crt" ]]; then
        [[ -s "$CREDENTIAL_DIR/server.key" && -s "$CREDENTIAL_DIR/server.crt" ]] \
            || { die "The existing helper TLS pair is incomplete"; return 1; }
        cp -- "$CREDENTIAL_DIR/server.key" "$WORK_DIR/credentials/server.key"
        cp -- "$CREDENTIAL_DIR/server.crt" "$WORK_DIR/credentials/server.crt"
    else
        openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
            -subj "/CN=tg-ws-proxy-helper" \
            -keyout "$WORK_DIR/credentials/server.key" \
            -out "$WORK_DIR/credentials/server.crt" >/dev/null 2>&1
    fi
    (
        cd "$WORK_DIR/candidate"
        venv/bin/python - "$WORK_DIR/credentials" <<'PY'
import ssl
import sys
from pathlib import Path
from helper_server import _read_token
credentials = Path(sys.argv[1])
_read_token(credentials / 'token')
ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(
    credentials / 'server.crt', credentials / 'server.key')
PY
    )
    cp -- "$SOURCE_DIR/tg-helper.service" "$WORK_DIR/tg-helper.service"
    if [[ "$ALLOW_LEGACY" == true ]]; then
        sed -i '/^ExecStart=/s/$/ --allow-legacy/' "$WORK_DIR/tg-helper.service"
    fi
    registry_prepare_candidate
}

backup_current() {
    install -d -o root -g root -m 0700 "$BACKUP_ROOT"
    BACKUP_DIR="$(mktemp -d "$BACKUP_ROOT/install-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")"
    install -d -m 0700 "$BACKUP_DIR/source/proxy" "$BACKUP_DIR/credentials"
    for relative in "${PAYLOAD_FILES[@]}"; do
        if [[ -f "$INSTALL_DIR/$relative" ]]; then
            cp -a -- "$INSTALL_DIR/$relative" "$BACKUP_DIR/source/$relative"
        fi
    done
    if [[ -e "$SERVICE_FILE" || -L "$SERVICE_FILE" ]]; then
        cp -a -- "$SERVICE_FILE" "$BACKUP_DIR/service"
    fi
    if [[ -d "$CREDENTIAL_DIR" ]]; then
        HAD_CREDENTIAL_DIR=true
        stat -c '%a %u %g' "$CREDENTIAL_DIR" > "$BACKUP_DIR/credential-directory-mode"
    fi
    for name in token server.key server.crt; do
        if [[ -f "$CREDENTIAL_DIR/$name" ]]; then
            cp -a -- "$CREDENTIAL_DIR/$name" "$BACKUP_DIR/credentials/$name"
        fi
    done
    systemctl is-active --quiet "$SERVICE" && WAS_ACTIVE=true || true
    systemctl is-enabled --quiet "$SERVICE" && WAS_ENABLED=true || true
    registry_backup
}

restore_service() {
    local restored=true mode uid gid
    registry_before_restore
    if [[ "$HELPER_SERVICE_TOUCHED" == true || "$CANDIDATE_MOVED" == true || "$PREVIOUS_MOVED" == true ]]; then
        timeout 20s systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    fi
    if [[ "$CANDIDATE_MOVED" == true && -d "$INSTALL_DIR" ]]; then
        mv -- "$INSTALL_DIR" "$WORK_DIR/failed-install" || restored=false
    fi
    if [[ "$PREVIOUS_MOVED" == true ]]; then
        mv -- "$WORK_DIR/previous-install" "$INSTALL_DIR" || restored=false
    fi
    if [[ -e "$BACKUP_DIR/service" || -L "$BACKUP_DIR/service" ]]; then
        cp -a --remove-destination -- "$BACKUP_DIR/service" "$SERVICE_FILE" || restored=false
    else
        rm -f -- "$SERVICE_FILE" || restored=false
    fi
    for name in token server.key server.crt; do
        if [[ -f "$BACKUP_DIR/credentials/$name" ]]; then
            cp -a --remove-destination -- "$BACKUP_DIR/credentials/$name" "$CREDENTIAL_DIR/$name" || restored=false
        else
            rm -f -- "$CREDENTIAL_DIR/$name" || restored=false
        fi
    done
    if [[ "$HAD_CREDENTIAL_DIR" == true ]]; then
        read -r mode uid gid < "$BACKUP_DIR/credential-directory-mode"
        chown "$uid:$gid" "$CREDENTIAL_DIR" || restored=false
        chmod "$mode" "$CREDENTIAL_DIR" || restored=false
    else
        rmdir -- "$CREDENTIAL_DIR" 2>/dev/null || true
    fi
    registry_restore_files || restored=false
    if [[ "$HAD_CREDENTIAL_DIR" == false ]]; then
        rmdir -- "$CREDENTIAL_DIR" 2>/dev/null || true
    fi
    systemctl daemon-reload || restored=false
    if [[ "$WAS_ENABLED" == true ]]; then
        systemctl enable "$SERVICE" >/dev/null 2>&1 || restored=false
    else
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
    fi
    if [[ "$WAS_ACTIVE" == true ]]; then
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
        timeout 30s systemctl start "$SERVICE" || restored=false
    fi
    registry_restore_activation || restored=false
    [[ "$restored" == true ]]
}

finish_install() {
    local status=$1
    trap - EXIT TERM INT HUP
    set +e
    if [[ $status -ne 0 && "$MUTATING" == true ]]; then
        echo "Helper installation failed; restoring its previous service and credentials." >&2
        if ! restore_service; then
            echo "Automatic helper rollback needs attention. Private recovery files: $WORK_DIR" >&2
            return "$status"
        fi
    fi
    registry_stop_setup
    if [[ -n "$WORK_DIR" && "$WORK_DIR" == "$WORK_PARENT"/.tg-helper-setup.* && ! -L "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
    return "$status"
}

verify_listener() {
    python3 - "$CREDENTIAL_DIR/server.crt" "$SECURE_PORT" "$INSTALL_DIR" <<'PY'
import hashlib
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from helper_pairing import certificate_digest
expected = certificate_digest(Path(sys.argv[1]).read_text(encoding='ascii'))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
deadline = time.monotonic() + 20
while time.monotonic() < deadline:
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'tg-helper.service']).returncode == 0:
        try:
            with socket.create_connection(('127.0.0.1', int(sys.argv[2])), timeout=1) as raw:
                with context.wrap_socket(raw) as secure:
                    if hashlib.sha256(secure.getpeercert(binary_form=True)).digest() == expected:
                        break
        except OSError:
            pass
    time.sleep(0.25)
else:
    raise SystemExit('The helper did not open its authenticated TLS listener')
PY
}

write_result() {
    python3 - "$CREDENTIAL_DIR" "$RESULT_FILE" "$SECURE_PORT" "$INSTALL_DIR" "$REGISTRY_MODE" "$PUBLIC_IP" "$HELPER_ID" <<'PY'
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[4])
from helper_pairing import certificate_digest
credentials, result = Path(sys.argv[1]), sys.argv[2]
addresses = subprocess.check_output(['hostname', '-I'], text=True).split()
host = addresses[0] if addresses else socket.gethostname()
fingerprint = certificate_digest((credentials / 'server.crt').read_text(encoding='ascii')).hex()
registry = len(sys.argv) > 5 and sys.argv[5] == 'true'
if registry:
    host = sys.argv[6]
    value = dict(host=host, port=int(sys.argv[3]), fingerprint=fingerprint, registry=True, helper_id=sys.argv[7])
else:
    token = (credentials / 'token').read_text(encoding='utf-8').strip()
    value = dict(host=host, port=int(sys.argv[3]), fingerprint=fingerprint, token=token)
if result:
    fd, temporary = tempfile.mkstemp(prefix='.tg-helper-result-', dir=str(Path(result).parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, result)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
else:
    print(f'Helper endpoint: {host}:{sys.argv[3]} (TLS v2)')
    print(f'Certificate SHA-256: {fingerprint}')
    if registry:
        print('Registered-device access is ready; the private Helper token is unchanged.')
    else:
        print(f'Helper token: {token}')
PY
}

ensure_service_user() {
    if ! getent group "$SERVICE_USER" >/dev/null; then
        groupadd --system "$SERVICE_USER"
    fi
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system --no-create-home --gid "$SERVICE_USER" --shell /usr/sbin/nologin "$SERVICE_USER"
    fi
}

commit_candidate() {
    ensure_service_user
    chown -hR root:"$SERVICE_USER" "$WORK_DIR/candidate"
    chmod -R g+rX,o-rwx "$WORK_DIR/candidate"
    MUTATING=true
    if systemctl cat "$SERVICE" >/dev/null 2>&1; then
        HELPER_SERVICE_TOUCHED=true
        timeout 30s systemctl stop "$SERVICE"
    fi
    if [[ -d "$INSTALL_DIR" ]]; then
        mv -- "$INSTALL_DIR" "$WORK_DIR/previous-install"
        PREVIOUS_MOVED=true
    fi
    mv -- "$WORK_DIR/candidate" "$INSTALL_DIR"
    CANDIDATE_MOVED=true
    registry_relocate_entrypoints
    install -d -o root -g "$SERVICE_USER" -m 0750 "$INSTALL_DIR" "$INSTALL_DIR/proxy" "$CREDENTIAL_DIR"
    for name in token server.key; do
        install -o root -g "$SERVICE_USER" -m 0640 "$WORK_DIR/credentials/$name" "$CREDENTIAL_DIR/$name"
    done
    install -o root -g "$SERVICE_USER" -m 0644 "$WORK_DIR/credentials/server.crt" "$CREDENTIAL_DIR/server.crt"
    install -o root -g root -m 0644 "$WORK_DIR/tg-helper.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    timeout 30s systemctl start "$SERVICE"
    verify_listener
    registry_finalize
    # Never enable/reset UFW or remove an existing rule (including SSH rules).
    if [[ "$SETUP_FIREWALL" == true ]] && command -v ufw >/dev/null \
            && LC_ALL=C ufw status | grep '^Status: active' >/dev/null; then
        ufw allow "$SECURE_PORT/tcp" comment 'TG Helper TLS v2'
        if [[ "$ALLOW_LEGACY" == true ]]; then
            ufw allow "$LEGACY_PORT/tcp" comment 'TG Helper legacy v1 temporary'
        fi
    fi
    write_result
    MUTATING=false
    echo "Helper TLS service is ready on TCP/$SECURE_PORT. Backup: $BACKUP_DIR"
}

main() {
    local parsed=0
    parse_args "$@" || parsed=$?
    [[ $parsed -ne 2 ]] || return 0
    [[ $parsed -eq 0 ]] || return "$parsed"
    preflight_host
    preflight_sources
    umask 077
    acquire_install_lock
    WORK_DIR="$(mktemp -d "$WORK_PARENT/.tg-helper-setup.XXXXXXXX")"
    trap 'finish_install "$?"' EXIT
    trap 'exit 143' TERM
    trap 'exit 130' INT
    trap 'exit 129' HUP
    prepare_candidate
    backup_current
    registry_preprovision
    commit_candidate
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
