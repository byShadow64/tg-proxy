#!/usr/bin/env bash
# Dedicated static update hosting; run on a new Ubuntu/Debian VPS as root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
IP=${1:?Usage: deploy_update_server.sh PUBLIC_IP SSH_PUBLIC_KEY}
PUBLISH_KEY=${2:?SSH public key required}
[[ $IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
[[ $PUBLISH_KEY == 'ssh-ed25519 '* ]]
test "$(id -u)" = 0
apt-get update -qq
apt-get install -y -qq nginx python3-venv
install -d -m 755 /srv/tg-proxy-publisher /var/www/tg-proxy-acme
id tgupdates >/dev/null 2>&1 || useradd --no-create-home --home-dir / --shell /usr/sbin/nologin tgupdates
install -d -o tgupdates -g tgupdates -m 755 /srv/tg-proxy-publisher/updates
install -d -o root -g root -m 755 /etc/ssh/authorized_keys
printf 'restrict %s\n' "$PUBLISH_KEY" >/etc/ssh/authorized_keys/tgupdates
chmod 644 /etc/ssh/authorized_keys/tgupdates
cat >/etc/ssh/sshd_config.d/60-tg-proxy-publisher.conf <<'EOF'
Match User tgupdates
    ChrootDirectory /srv/tg-proxy-publisher
    ForceCommand internal-sftp
    AuthorizedKeysFile /etc/ssh/authorized_keys/tgupdates
    AuthenticationMethods publickey
    PasswordAuthentication no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTTY no
Match all
EOF
sshd -t
systemctl reload ssh
cat >/etc/nginx/sites-available/tg-proxy-updates <<EOF
server {
    listen 80;
    server_name $IP;
    location /.well-known/acme-challenge/ { root /var/www/tg-proxy-acme; }
    location / { return 404; }
}
EOF
ln -sfn /etc/nginx/sites-available/tg-proxy-updates /etc/nginx/sites-enabled/tg-proxy-updates
nginx -t
systemctl enable --now nginx
systemctl reload nginx
if command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi
python3 -m venv /opt/tg-update-certbot
/opt/tg-update-certbot/bin/pip install -q 'certbot>=5.4,<6'
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\n/usr/sbin/nginx -t && /bin/systemctl reload nginx\n' >/etc/letsencrypt/renewal-hooks/deploy/tg-proxy-nginx
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/tg-proxy-nginx
/opt/tg-update-certbot/bin/certbot certonly --non-interactive --agree-tos \
    --register-unsafely-without-email --preferred-profile shortlived --webroot \
    --webroot-path /var/www/tg-proxy-acme --ip-address "$IP" --cert-name tg-proxy-updates
cat >/etc/nginx/sites-available/tg-proxy-updates <<EOF
server {
    listen 80;
    server_name $IP;
    location /.well-known/acme-challenge/ { root /var/www/tg-proxy-acme; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl;
    server_name $IP;
    ssl_certificate /etc/letsencrypt/live/tg-proxy-updates/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tg-proxy-updates/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    root /srv/tg-proxy-publisher/updates;
    autoindex off;
    add_header X-Content-Type-Options nosniff always;
    location ~ /\. { deny all; }
    location = /latest.json { add_header Cache-Control 'no-store'; default_type application/json; }
    location /versions/ { add_header Cache-Control 'public, max-age=31536000, immutable'; }
    location / { try_files \$uri =404; }
}
EOF
nginx -t
systemctl reload nginx
cat >/etc/systemd/system/tg-proxy-certificate.service <<'EOF'
[Unit]
Description=Renew TG Proxy update HTTPS certificate
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/tg-update-certbot/bin/certbot renew --quiet
EOF
cat >/etc/systemd/system/tg-proxy-certificate.timer <<'EOF'
[Unit]
Description=Check TG Proxy update certificate twice daily
[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now tg-proxy-certificate.timer
printf 'UPDATE_SERVER_READY\n'
