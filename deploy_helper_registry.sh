#!/usr/bin/env bash
# Optional owner-consented registry setup. Sourced by deploy_helper.sh only.
REGISTRY_MODE=false
REGISTRY_URL=
REGISTRY_TRUST_SPKI=
PUBLIC_IP=
ALLOW_EXISTING_PRIVATE_UPGRADE=false
REGISTRY_CONFIG=
REGISTRY_PUBLIC_KEY=
REGISTRY_STATE_DIR=/var/lib/tg-helper
REGISTRY_MUTATING=false
REGISTRY_READY=false
REGISTRY_ENROLL_ATTEMPTED=false
REGISTRY_WAS_CONFIGURED=false
REGISTRY_CERT_NAME=
HELPER_ID=
SETUP_UNIT=
HELPER_SERVICE_TOUCHED=false
REGISTRY_UFW_APP_DIR=/etc/ufw/applications.d
REGISTRY_UFW_COMMENT=
REGISTRY_UFW_ADDED_PORTS=()
REGISTRY_UNITS=(tg-helper-enroll.service tg-helper-registry-agent.service tg-helper-registry-agent.timer
    tg-helper-certbot-renew.service tg-helper-certbot-renew.timer)
REGISTRY_CREDENTIALS=(registry-agent.env registry-public.pem enrollment.crt enrollment.key)
REGISTRY_STATE_FILES=(registry-agent.key registry-config.json)
declare -A REGISTRY_WAS_ACTIVE=() REGISTRY_WAS_ENABLED=()

registry_enabled() { [[ "$REGISTRY_MODE" == true || -n "$REGISTRY_CONFIG" ]]; }

registry_validate_options() {
    if [[ "$REGISTRY_MODE" == true ]]; then
        [[ -n "$REGISTRY_URL" && -n "$REGISTRY_TRUST_SPKI" && -n "$PUBLIC_IP" ]] \
            || { die "Registry mode requires its trusted central URL/key and public IP"; return 1; }
        [[ "$REGISTRY_URL" == https://* && ${#REGISTRY_URL} -le 512 ]] \
            || { die "Invalid registry HTTPS URL"; return 1; }
        [[ "$REGISTRY_TRUST_SPKI" =~ ^[A-Za-z0-9_-]+$ && ${#REGISTRY_TRUST_SPKI} -le 256 ]] \
            || { die "Invalid registry trust key encoding"; return 1; }
        PUBLIC_IP="$(python3 -c 'import ipaddress,sys,urllib.parse; u=urllib.parse.urlsplit(sys.argv[2]); assert u.scheme=="https" and u.hostname and u.username is None and u.password is None and not(u.query or u.fragment); assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.:/_-[]" for c in sys.argv[2]); assert u.port is None or 1<=u.port<=65535; a=ipaddress.ip_address(sys.argv[1]); assert a.is_global and not(a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local) and getattr(a,"ipv4_mapped",None) is None; print(str(a))' "$PUBLIC_IP" "$REGISTRY_URL")" \
            || { die "Registry setup needs a numeric public IP"; return 1; }
        REGISTRY_CONFIG="$REGISTRY_STATE_DIR/registry-config.json"
        REGISTRY_PUBLIC_KEY="$CREDENTIAL_DIR/registry-public.pem"
    else
        [[ "$ALLOW_EXISTING_PRIVATE_UPGRADE" == false ]] \
            || { die "Private-to-registry approval requires --registry-mode"; return 1; }
        [[ -z "$REGISTRY_URL$REGISTRY_TRUST_SPKI$PUBLIC_IP" ]] \
            || { die "Registry setup arguments require --registry-mode"; return 1; }
        [[ ( -z "$REGISTRY_CONFIG" && -z "$REGISTRY_PUBLIC_KEY" ) || ( -n "$REGISTRY_CONFIG" && -n "$REGISTRY_PUBLIC_KEY" ) ]] \
            || { die "Registry configuration and trust key are required together"; return 1; }
    fi
    for path in "$REGISTRY_CONFIG" "$REGISTRY_PUBLIC_KEY"; do
        [[ -z "$path" || "$path" =~ ^/[A-Za-z0-9_./-]+$ ]] \
            || { die "Registry paths must be absolute managed paths"; return 1; }
    done
}

registry_preflight() {
    [[ "$REGISTRY_MODE" == true ]] || {
        if [[ -f "$CREDENTIAL_DIR/registry-agent.env" && -z "$REGISTRY_CONFIG" ]]; then
            die "Existing registry access must be explicitly retained; use --registry-mode"
            return 1
        fi
        return 0
    }
    for command in python3 ss runuser systemd-run openssl; do
        command -v "$command" >/dev/null || { die "A registry setup tool is missing"; return 1; }
    done
    if [[ -f "$INSTALL_DIR/helper_server.py" && ! -f "$CREDENTIAL_DIR/registry-agent.env" \
            && "$ALLOW_EXISTING_PRIVATE_UPGRADE" != true ]]; then
        die "An existing private Helper needs explicit --allow-existing-private-upgrade approval"
        return 1
    fi
    [[ ! -L "$REGISTRY_STATE_DIR" && ( ! -e "$REGISTRY_STATE_DIR" || -d "$REGISTRY_STATE_DIR" ) ]] \
        || { die "Unsafe registry state directory"; return 1; }
    for name in "${REGISTRY_CREDENTIALS[@]}"; do
        path="$CREDENTIAL_DIR/$name"
        [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] || { die "Unsafe registry credential path"; return 1; }
    done
    for name in "${REGISTRY_STATE_FILES[@]}"; do
        path="$REGISTRY_STATE_DIR/$name"
        [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] || { die "Unsafe registry state path"; return 1; }
    done
    for name in "${REGISTRY_UNITS[@]}"; do
        path="$(dirname -- "$SERVICE_FILE")/$name"
        [[ ! -L "$path" && ( ! -e "$path" || -f "$path" ) ]] || { die "Unsafe registry unit path"; return 1; }
    done
    [[ -z "$(ss -H -ltn 'sport = :80')" ]] \
        || { die "Port 80 is in use; no existing web configuration will be changed"; return 1; }
    local occupied pid
    occupied="$(ss -H -ltnp 'sport = :443')"
    if [[ -n "$occupied" ]]; then
        pid="$(systemctl show -p MainPID --value tg-helper-enroll.service 2>/dev/null || true)"
        [[ "$pid" =~ ^[1-9][0-9]*$ && -f "$CREDENTIAL_DIR/registry-agent.env" ]] \
            || { die "Port 443 is in use; no existing web configuration will be changed"; return 1; }
        while IFS= read -r line; do
            [[ "$line" == *"pid=$pid,"* ]] || { die "Port 443 belongs to another service"; return 1; }
        done <<< "$occupied"
    fi
    registry_firewall_check
}

# Read only UFW's public status and application profiles. A broad/named rule or
# an existing exact rule is reused, including its comment. Never enable UFW,
# change policy, reorder a deny, or restore an owner's whole firewall snapshot.
registry_ufw_inspect() {
    local port=$1 mode=${2:-coverage} rules
    rules="$(LC_ALL=C timeout 10s ufw status verbose)" || return 1
    if [[ "$mode" == owned ]]; then
        rules="$(LC_ALL=C timeout 10s ufw status numbered)" || return 1
    fi
    python3 - "$PUBLIC_IP" "$port" "$mode" "$REGISTRY_UFW_APP_DIR" "$REGISTRY_UFW_COMMENT" "$rules" <<'PY'
import configparser, ipaddress, pathlib, re, socket, sys
ip, port, mode, directory, comment, status = sys.argv[1:]
status = status.replace('\r\n', '\n')
family = ipaddress.ip_address(ip).version
port = int(port)
if len(status) > 262144:
    raise SystemExit(1)
if not re.search(r'^Status: active$', status, re.M):
    print('inactive' if mode != 'owned' else '')
    raise SystemExit(0)
def contains(spec):
    for group in spec.split('|'):
        ports, _, protocol = group.partition('/')
        if protocol and protocol != 'tcp':
            continue
        for item in ports.split(','):
            if ':' in item:
                low, high = item.split(':', 1)
                if low.isdigit() and high.isdigit() and int(low) <= port <= int(high):
                    return True
            elif item.isdigit():
                if int(item) == port:
                    return True
            else:
                try:
                    if socket.getservbyname(item, 'tcp') == port:
                        return True
                except OSError:
                    pass
    return False
def covers(destination):
    if destination == 'Anywhere':
        return True
    parts = destination.split()
    if len(parts) == 2:
        try:
            target_address = ipaddress.ip_address(parts[0])
        except ValueError:
            pass  # Two-word application names (for example, Nginx Full).
        else:
            if target_address != ipaddress.ip_address(ip):
                return False
            destination = parts[1]
    if re.fullmatch(r'[0-9,:/a-zA-Z-]+', destination) and contains(destination):
        return True
    # Application names are looked up as data, never evaluated as commands.
    folder = pathlib.Path(directory)
    files = list(folder.iterdir()) if folder.is_dir() else []
    if len(files) > 128:
        raise SystemExit(1)
    for path in files:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
            continue
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(path, encoding='utf-8')
            if parser.has_option(destination, 'ports') and contains(parser.get(destination, 'ports')):
                return True
        except (configparser.Error, OSError, UnicodeError):
            continue
    return False
for line in status.splitlines():
    match = re.fullmatch(r'\s*(?:\[\s*(\d+)\]\s*)?(.*?)\s{2,}(ALLOW(?: IN| OUT)?|DENY(?: IN| OUT)?|REJECT(?: IN| OUT)?|LIMIT(?: IN| OUT)?)\s{2,}(.*?)\s*', line)
    if not match:
        continue
    number, destination, action, source = match.groups()
    source, marker, actual_comment = source.partition(' # ')
    source = source.rstrip()
    v6 = destination.endswith(' (v6)')
    if v6 != (family == 6):
        continue
    destination = destination.removesuffix(' (v6)')
    source = source.removesuffix(' (v6)')
    if mode == 'owned':
        if (number and destination == str(port) + '/tcp' and action == 'ALLOW IN'
                and source == 'Anywhere' and marker and actual_comment == comment):
            print(number)
        continue
    if action.endswith(' OUT') or source != 'Anywhere':
        continue
    if covers(destination):
        print('open' if action in {'ALLOW', 'ALLOW IN'} else 'blocked')
        raise SystemExit(0)
if mode != 'owned':
    print('open' if re.search(r'^Default: allow \(incoming\)', status, re.M) else 'missing')
PY
}

registry_firewall_check() {
    command -v ufw >/dev/null || return 0
    local port state
    for port in 80 443; do
        state="$(registry_ufw_inspect "$port")" || { die "Cannot safely inspect the active UFW rules"; return 1; }
        case "$state" in
            inactive|open) ;;
            missing) [[ "$SETUP_FIREWALL" == true ]] || { die "--no-firewall requires owner-approved TCP/$port in active UFW"; return 1; } ;;
            *) die "An existing UFW policy blocks TCP/$port; no owner rule will be changed"; return 1 ;;
        esac
    done
}

registry_prepare_firewall() {
    command -v ufw >/dev/null || return 0
    local port state source
    [[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || { die "Registry firewall setup requires its private recovery backup"; return 1; }
    REGISTRY_UFW_COMMENT="TG Proxy registry ACME/proof ${WORK_DIR##*.} $$"
    printf '%s\n' "$REGISTRY_UFW_COMMENT" > "$BACKUP_DIR/registry-firewall-attempt"
    source=0.0.0.0/0
    [[ "$PUBLIC_IP" != *:* ]] || source=::/0
    for port in 80 443; do
        state="$(registry_ufw_inspect "$port")" || return 1
        case "$state" in
            inactive|open) continue ;;
            missing) [[ "$SETUP_FIREWALL" == true ]] || { die "--no-firewall requires owner-approved TCP/$port in active UFW"; return 1; } ;;
            *) die "An existing UFW policy blocks TCP/$port; no owner rule will be changed"; return 1 ;;
        esac
        # Record the attempt first, so even a failing UFW command is inspected
        # for an actually-created, uniquely-commented rule during rollback.
        REGISTRY_UFW_ADDED_PORTS+=("$port")
        LC_ALL=C timeout 15s ufw allow in proto tcp from "$source" to any port "$port" comment "$REGISTRY_UFW_COMMENT" || return 1
        [[ "$(registry_ufw_inspect "$port")" == open && -n "$(registry_ufw_inspect "$port" owned)" ]] \
            || { die "UFW did not confirm the new registry port rule"; return 1; }
    done
}

registry_restore_firewall() {
    local port number source=0.0.0.0/0
    [[ "$PUBLIC_IP" != *:* ]] || source=::/0
    for port in "${REGISTRY_UFW_ADDED_PORTS[@]}"; do
        number="$(registry_ufw_inspect "$port" owned)" || return 1
        # Re-read immediately before each deletion. An absent/changed comment
        # or ambiguous match leaves the rule for explicit owner review.
        [[ -n "$number" ]] || { echo "Registry UFW rule changed or disappeared; owner review may be needed." >&2; continue; }
        [[ "$number" =~ ^[1-9][0-9]*$ ]] || return 1
        # Delete by exact family/port/spec, not a potentially shifted index.
        # UFW ignores comments for identity; the fresh ownership check above
        # is required, and concurrent owner edits still need operator review.
        LC_ALL=C timeout 15s ufw --force delete allow in proto tcp from "$source" to any port "$port" comment "$REGISTRY_UFW_COMMENT" || return 1
    done
    REGISTRY_UFW_ADDED_PORTS=()
}

registry_prepare_candidate() {
    registry_enabled || return 0
    "$WORK_DIR/candidate/venv/bin/python" -m pip install --disable-pip-version-check \
        --only-binary=:all: --require-hashes -r "$WORK_DIR/candidate/helper_registry_requirements.txt"
    if [[ "$REGISTRY_MODE" == true ]]; then
        "$WORK_DIR/candidate/venv/bin/python" -m pip install --disable-pip-version-check \
            --only-binary=:all: --require-hashes -r "$WORK_DIR/candidate/helper_certbot_requirements.txt"
        "$WORK_DIR/candidate/venv/bin/certbot" --version >/dev/null
    else
        # Explicit local provisioning is a separate owner/admin path. Reject a
        # stale, disabled, foreign-key or wrong-leaf configuration before the
        # existing data service is stopped.
        PYTHONPATH="$WORK_DIR/candidate" "$WORK_DIR/candidate/venv/bin/python" -c 'import pathlib,sys; from helper_pairing import certificate_digest; from proxy.registry_helper import RegistryLeaseAuthorizer; a=RegistryLeaseAuthorizer(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]),certificate_digest(pathlib.Path(sys.argv[3]).read_text("ascii")),port=int(sys.argv[4])); assert a._configuration()["enabled"]' \
            "$REGISTRY_PUBLIC_KEY" "$REGISTRY_CONFIG" "$WORK_DIR/credentials/server.crt" "$SECURE_PORT"
    fi
    sed -i "/^ExecStart=/s|$| --registry-config $REGISTRY_CONFIG --registry-public-key $REGISTRY_PUBLIC_KEY|" "$WORK_DIR/tg-helper.service"
    if [[ "$REGISTRY_MODE" == true && "$PUBLIC_IP" == *:* ]]; then
        sed -i 's/--bind 0.0.0.0/--bind 0.0.0.0 --bind ::/' "$WORK_DIR/tg-helper.service"
    fi
}

registry_relocate_entrypoints() {
    [[ "$REGISTRY_MODE" == true ]] || return 0
    # pip's console-script shebang names the temporary candidate interpreter.
    # Regenerate the verified Certbot entry point after its venv is moved. The
    # package has no __main__.py; renewal must use this final executable path.
    "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/venv/bin/certbot" "$INSTALL_DIR/venv/bin/python" <<'PY'
from importlib.metadata import distribution
import os
from pathlib import Path
import sys
entrypoints = [entry for entry in distribution('certbot').entry_points
               if entry.group == 'console_scripts' and entry.name == 'certbot']
if len(entrypoints) != 1 or entrypoints[0].value != 'certbot.main:main':
    raise SystemExit('The installed Certbot console entry point is invalid')
path = Path(sys.argv[1])
interpreter = sys.argv[2]
if path.is_symlink() or not path.is_file() or not Path(interpreter).is_absolute() or any(c.isspace() for c in interpreter):
    raise SystemExit('The installed Certbot executable path is invalid')
path.write_text('#!' + interpreter + '\nimport sys\nfrom certbot.main import main\n'
                "if __name__ == '__main__':\n    sys.exit(main())\n", encoding='utf-8')
os.chmod(path, 0o750)
PY
    "$INSTALL_DIR/venv/bin/certbot" --version >/dev/null
}

registry_backup() {
    [[ "$REGISTRY_MODE" == true ]] || return 0
    install -d -m 0700 "$BACKUP_DIR/registry-credentials" "$BACKUP_DIR/registry-state" "$BACKUP_DIR/registry-units"
    for name in "${REGISTRY_CREDENTIALS[@]}"; do
        [[ ! -f "$CREDENTIAL_DIR/$name" ]] || cp -a -- "$CREDENTIAL_DIR/$name" "$BACKUP_DIR/registry-credentials/$name"
    done
    [[ ! -f "$CREDENTIAL_DIR/registry-agent.env" ]] || REGISTRY_WAS_CONFIGURED=true
    for name in "${REGISTRY_STATE_FILES[@]}"; do
        [[ ! -f "$REGISTRY_STATE_DIR/$name" ]] || cp -a -- "$REGISTRY_STATE_DIR/$name" "$BACKUP_DIR/registry-state/$name"
    done
    for name in "${REGISTRY_UNITS[@]}"; do
        path="$(dirname -- "$SERVICE_FILE")/$name"
        [[ ! -f "$path" ]] || cp -a -- "$path" "$BACKUP_DIR/registry-units/$name"
        REGISTRY_WAS_ACTIVE[$name]=false
        REGISTRY_WAS_ENABLED[$name]=false
        systemctl is-active --quiet "$name" && REGISTRY_WAS_ACTIVE[$name]=true || true
        systemctl is-enabled --quiet "$name" && REGISTRY_WAS_ENABLED[$name]=true || true
    done
}

registry_stop_setup() {
    if [[ "$SETUP_UNIT" == tg-helper-enroll-setup-*.service ]]; then
        timeout 10s systemctl stop "$SETUP_UNIT" >/dev/null 2>&1 || true
    fi
    SETUP_UNIT=
}

registry_copy_certificate() {
    local lineage="/etc/letsencrypt/live/$REGISTRY_CERT_NAME"
    for name in enrollment.crt enrollment.key enrollment.crt.new enrollment.key.new; do
        [[ ! -L "$CREDENTIAL_DIR/$name" ]] || { die "Unsafe enrollment certificate destination"; return 1; }
    done
    openssl verify -purpose sslserver -verify_ip "$PUBLIC_IP" -CAfile /etc/ssl/certs/ca-certificates.crt \
        -untrusted "$lineage/chain.pem" "$lineage/cert.pem" >/dev/null 2>&1
    install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0600 "$lineage/fullchain.pem" "$CREDENTIAL_DIR/enrollment.crt.new"
    install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0600 "$lineage/privkey.pem" "$CREDENTIAL_DIR/enrollment.key.new"
    mv -- "$CREDENTIAL_DIR/enrollment.crt.new" "$CREDENTIAL_DIR/enrollment.crt"
    mv -- "$CREDENTIAL_DIR/enrollment.key.new" "$CREDENTIAL_DIR/enrollment.key"
}

registry_obtain_certificate() {
    REGISTRY_CERT_NAME="tg-helper-ip-$(printf '%s' "$PUBLIC_IP" | openssl dgst -sha256 | awk '{print substr($NF,1,16)}')"
    local lineage="/etc/letsencrypt/live/$REGISTRY_CERT_NAME"
    # Reuse a still-valid, CA/IP-verified lineage. Never force issuance on retry.
    if ! { [[ -f "$lineage/cert.pem" && -f "$lineage/chain.pem" && -f "$lineage/privkey.pem" ]] \
            && openssl x509 -checkend 172800 -noout -in "$lineage/cert.pem" >/dev/null 2>&1 \
            && openssl verify -purpose sslserver -verify_ip "$PUBLIC_IP" -CAfile /etc/ssl/certs/ca-certificates.crt \
                -untrusted "$lineage/chain.pem" "$lineage/cert.pem" >/dev/null 2>&1; }; then
        timeout 180s "$WORK_DIR/candidate/venv/bin/certbot" certonly --standalone \
            --non-interactive --agree-tos --register-unsafely-without-email --required-profile shortlived \
            --keep-until-expiring --cert-name "$REGISTRY_CERT_NAME" --ip-address "$PUBLIC_IP"
    fi
    registry_copy_certificate
}

registry_wait_proof() {
    "$WORK_DIR/candidate/venv/bin/python" -c 'import socket,ssl,sys,time
deadline=time.monotonic()+8
while time.monotonic()<deadline:
 try:
  raw=socket.create_connection(("::1" if ":" in sys.argv[1] else "127.0.0.1",443),timeout=1)
  with ssl.create_default_context().wrap_socket(raw,server_hostname=sys.argv[1]): break
 except OSError: time.sleep(.1)
else: raise SystemExit("The owner enrollment endpoint did not start")' "$PUBLIC_IP"
}

registry_preprovision() {
    [[ "$REGISTRY_MODE" == true ]] || return 0
    MUTATING=true
    REGISTRY_MUTATING=true
    ensure_service_user
    for name in "${REGISTRY_UNITS[@]}"; do
        timeout 20s systemctl stop "$name" >/dev/null 2>&1 || true
    done
    install -d -o root -g "$SERVICE_USER" -m 0750 "$CREDENTIAL_DIR"
    if [[ -d "$REGISTRY_STATE_DIR" ]]; then
        [[ "$(stat -c %a "$REGISTRY_STATE_DIR")" == 700 && "$(stat -c %u "$REGISTRY_STATE_DIR")" == "$(id -u "$SERVICE_USER")" ]] \
            || { die "Registry state must remain private to the Helper account"; return 1; }
    else
        install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0700 "$REGISTRY_STATE_DIR"
    fi
    chown -hR root:"$SERVICE_USER" "$WORK_DIR/candidate"
    chmod -R g+rX,o-rwx "$WORK_DIR/candidate"
    chgrp "$SERVICE_USER" "$WORK_DIR"
    chmod 0710 "$WORK_DIR"
    PYTHONPATH="$WORK_DIR/candidate" "$WORK_DIR/candidate/venv/bin/python" -c 'from proxy.registry_protocol import decode_public_key; from cryptography.hazmat.primitives import serialization; import sys; open(sys.argv[2],"wb").write(decode_public_key(sys.argv[1]).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))' \
        "$REGISTRY_TRUST_SPKI" "$WORK_DIR/registry-public.pem"
    install -o root -g "$SERVICE_USER" -m 0644 "$WORK_DIR/registry-public.pem" "$REGISTRY_PUBLIC_KEY"
    runuser -u "$SERVICE_USER" -- "$WORK_DIR/candidate/venv/bin/python" "$WORK_DIR/candidate/helper_registry_agent.py" \
        --generate-key --private-key "$REGISTRY_STATE_DIR/registry-agent.key"
    registry_prepare_firewall
    registry_obtain_certificate
    # Only the staged public leaf becomes group-readable before the proof starts.
    chmod 0750 "$WORK_DIR/credentials"
    chgrp "$SERVICE_USER" "$WORK_DIR/credentials"
    chgrp "$SERVICE_USER" "$WORK_DIR/credentials/server.crt"
    chmod 0640 "$WORK_DIR/credentials/server.crt"
    SETUP_UNIT="tg-helper-enroll-setup-${WORK_DIR##*.}.service"
    systemd-run --unit "$SETUP_UNIT" --collect --property="User=$SERVICE_USER" --property="Group=$SERVICE_USER" \
        --property=AmbientCapabilities=CAP_NET_BIND_SERVICE --property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE \
        --property=NoNewPrivileges=yes --property="WorkingDirectory=$WORK_DIR/candidate" \
        "$WORK_DIR/candidate/venv/bin/python" "$WORK_DIR/candidate/helper_enrollment.py" \
        --ip "$PUBLIC_IP" --port "$SECURE_PORT" --private-key "$REGISTRY_STATE_DIR/registry-agent.key" \
        --tls-cert "$WORK_DIR/credentials/server.crt" --https-cert "$CREDENTIAL_DIR/enrollment.crt" --https-key "$CREDENTIAL_DIR/enrollment.key"
    registry_wait_proof
    # A failed fresh installation restores the previous private relay. Keep its
    # staged new TLS identity in the root-only recovery backup as well: a lost
    # central reply may already have committed this exact public descriptor.
    install -d -m 0700 "$BACKUP_DIR/registry-attempt-credentials"
    for name in server.crt server.key token; do
        cp -a -- "$WORK_DIR/credentials/$name" "$BACKUP_DIR/registry-attempt-credentials/$name"
    done
    REGISTRY_ENROLL_ATTEMPTED=true
    timeout 60s runuser -u "$SERVICE_USER" -- "$WORK_DIR/candidate/venv/bin/python" "$WORK_DIR/candidate/helper_registry_agent.py" \
        --registry-url "$REGISTRY_URL" --registry-public-key "$REGISTRY_PUBLIC_KEY" \
        --private-key "$REGISTRY_STATE_DIR/registry-agent.key" --enroll --ip "$PUBLIC_IP" \
        --tls-cert "$WORK_DIR/credentials/server.crt" --output "$REGISTRY_CONFIG" > "$WORK_DIR/registry-receipt.json"
    HELPER_ID="$(PYTHONPATH="$WORK_DIR/candidate" "$WORK_DIR/candidate/venv/bin/python" -c 'import json,sys; from proxy.registry_protocol import b64decode; v=json.load(open(sys.argv[1])); assert set(v)=={"v","helper_id"} and type(v["v"]) is int and v["v"]==1; b64decode(v["helper_id"],16); print(v["helper_id"])' "$WORK_DIR/registry-receipt.json")"
    REGISTRY_READY=true
    printf 'REGISTRY_URL=%s\nHELPER_ID=%s\nPUBLIC_IP=%s\nREGISTRY_CERT_NAME=%s\n' \
        "$REGISTRY_URL" "$HELPER_ID" "$PUBLIC_IP" "$REGISTRY_CERT_NAME" > "$WORK_DIR/registry-agent.env"
    install -o root -g "$SERVICE_USER" -m 0640 "$WORK_DIR/registry-agent.env" "$CREDENTIAL_DIR/registry-agent.env"
    registry_stop_setup
}

registry_finalize() {
    [[ "$REGISTRY_MODE" == true ]] || return 0
    for name in "${REGISTRY_UNITS[@]}"; do
        install -o root -g root -m 0644 "$INSTALL_DIR/$name" "$(dirname -- "$SERVICE_FILE")/$name"
    done
    systemctl daemon-reload
    systemctl enable tg-helper-enroll.service tg-helper-registry-agent.timer tg-helper-certbot-renew.timer
    timeout 20s systemctl start tg-helper-enroll.service tg-helper-registry-agent.service
    systemctl start tg-helper-registry-agent.timer tg-helper-certbot-renew.timer
}

registry_before_restore() {
    [[ "$REGISTRY_MUTATING" == true ]] || return 0
    registry_stop_setup
    for name in "${REGISTRY_UNITS[@]}"; do
        timeout 15s systemctl stop "$name" >/dev/null 2>&1 || true
    done
    if [[ "$REGISTRY_ENROLL_ATTEMPTED" == true && "$REGISTRY_WAS_CONFIGURED" == false ]]; then
        local runtime="$WORK_DIR/candidate"
        [[ "$CANDIDATE_MOVED" != true ]] || runtime="$INSTALL_DIR"
        if ! timeout 30s runuser -u "$SERVICE_USER" -- "$runtime/venv/bin/python" "$runtime/helper_registry_agent.py" \
                --registry-url "$REGISTRY_URL" --registry-public-key "$REGISTRY_PUBLIC_KEY" \
                --private-key "$REGISTRY_STATE_DIR/registry-agent.key" --helper-id "$HELPER_ID" --disable --ip "$PUBLIC_IP" \
                --tls-cert "$WORK_DIR/credentials/server.crt" --output "$REGISTRY_CONFIG" >/dev/null 2>&1; then
            echo "The local public endpoint will be removed; the new registry record needs owner review." >&2
        fi
        echo "Enrollment was attempted; the new private agent identity is retained for owner review." >&2
    fi
    registry_restore_firewall || echo "Registry firewall cleanup needs owner review; existing rules were not restored globally." >&2
}

registry_restore_files() {
    [[ "$REGISTRY_MUTATING" == true ]] || return 0
    local ok=true
    for name in "${REGISTRY_CREDENTIALS[@]}"; do
        if [[ -f "$BACKUP_DIR/registry-credentials/$name" ]]; then
            cp -a --remove-destination -- "$BACKUP_DIR/registry-credentials/$name" "$CREDENTIAL_DIR/$name" || ok=false
        else
            rm -f -- "$CREDENTIAL_DIR/$name" || ok=false
        fi
    done
    for name in "${REGISTRY_STATE_FILES[@]}"; do
        if [[ -f "$BACKUP_DIR/registry-state/$name" ]]; then
            cp -a --remove-destination -- "$BACKUP_DIR/registry-state/$name" "$REGISTRY_STATE_DIR/$name" || ok=false
        else
            if [[ "$name" != registry-agent.key || "$REGISTRY_ENROLL_ATTEMPTED" != true ]]; then
                rm -f -- "$REGISTRY_STATE_DIR/$name" || ok=false
            fi
        fi
    done
    for name in "${REGISTRY_UNITS[@]}"; do
        path="$(dirname -- "$SERVICE_FILE")/$name"
        if [[ -f "$BACKUP_DIR/registry-units/$name" ]]; then
            cp -a --remove-destination -- "$BACKUP_DIR/registry-units/$name" "$path" || ok=false
        else
            rm -f -- "$path" || ok=false
        fi
    done
    [[ "$ok" == true ]]
}

registry_restore_activation() {
    [[ "$REGISTRY_MUTATING" == true ]] || return 0
    local ok=true
    for name in "${REGISTRY_UNITS[@]}"; do
        if [[ "${REGISTRY_WAS_ENABLED[$name]:-false}" == true ]]; then
            systemctl enable "$name" >/dev/null 2>&1 || ok=false
        else
            systemctl disable "$name" >/dev/null 2>&1 || true
        fi
        if [[ "${REGISTRY_WAS_ACTIVE[$name]:-false}" == true ]]; then
            timeout 20s systemctl start "$name" || ok=false
        fi
    done
    [[ "$ok" == true ]]
}
