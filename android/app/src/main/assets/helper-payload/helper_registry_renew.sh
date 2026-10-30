#!/usr/bin/env bash
# Root-only Certbot deploy hook; never restarts the 8444 data relay.
set -euo pipefail
set +x
[[ ${EUID} -eq 0 && -n "${RENEWED_LINEAGE:-}" ]] || exit 1
[[ "${REGISTRY_CERT_NAME:-}" =~ ^tg-helper-ip-[a-f0-9]{16}$ && -n "${PUBLIC_IP:-}" ]] || exit 1
[[ "$RENEWED_LINEAGE" == "/etc/letsencrypt/live/$REGISTRY_CERT_NAME" && ! -L /etc/tg-helper ]] || exit 1
for name in enrollment.crt enrollment.key enrollment.crt.new enrollment.key.new; do
    [[ ! -L "/etc/tg-helper/$name" ]] || exit 1
done
# Certbot's live/ links are intentional. A different lineage, wrong IP, or
# untrusted replacement cannot change the owner's enrollment endpoint.
openssl verify -purpose sslserver -verify_ip "$PUBLIC_IP" -CAfile /etc/ssl/certs/ca-certificates.crt \
    -untrusted "$RENEWED_LINEAGE/chain.pem" "$RENEWED_LINEAGE/cert.pem" >/dev/null 2>&1
install -o tg-helper -g tg-helper -m 0600 "$RENEWED_LINEAGE/fullchain.pem" /etc/tg-helper/enrollment.crt.new
install -o tg-helper -g tg-helper -m 0600 "$RENEWED_LINEAGE/privkey.pem" /etc/tg-helper/enrollment.key.new
mv -- /etc/tg-helper/enrollment.crt.new /etc/tg-helper/enrollment.crt
mv -- /etc/tg-helper/enrollment.key.new /etc/tg-helper/enrollment.key
systemctl try-restart tg-helper-enroll.service
