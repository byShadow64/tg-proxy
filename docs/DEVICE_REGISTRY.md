# Registered-client Helper registry v1

Specified for Windows 1.15.3 and Android 0.1.7-dev. Publisher 1.0.4 validates
the Windows publication bundle independently. This is a protocol specification;
completed checks and remaining limits are recorded in [PROJECT_STATE](PROJECT_STATE.md).

## Access model

The owner explicitly enables `registered-device-public` access. Any client can
automatically register its installation key and request a short-lived lease for
an enrolled Helper. Registration proves possession of that P-256 key. It does
not prove a human identity, physical device, hardware ID, genuine application,
paid account or private ownership of the Helper. Reinstallation can create a
new identity; per-key revocation is not a ban on a person.

Existing private Helpers remain private. Their global bearer token and owner-code
pairing are not published through the registry. Converting an existing private
server requires a separate, initially unchecked owner consent. Merely entering
an IP, receiving an unknown-server reply, installing an app or cancelling a form
must not enable public access. Private owner-code pairing remains described in
[HELPER_PAIRING.md](HELPER_PAIRING.md).

## Trust and client exchange

1. Each installation creates a P-256 signing key: Android Keystore on Android,
   DPAPI-protected private app storage on Windows. It is not copied into source,
   exports, reports or logs. The device ID is SHA-256 of canonical DER SPKI.
2. The client connects to its configured central registry using HTTPS with CA
   trust and hostname validation. A fixed trusted P-256 SPKI verifies registry
   signatures. This is a signing-key trust anchor, not acceptance of an arbitrary
   TLS certificate. There are no redirects, HTTP fallback or TOFU.
3. A fresh 32-byte challenge lasts at most 60 seconds. A signed proof binds the
   installation key, purpose, target and nonce. Valid matching proofs consume
   challenges once; an unauthenticated invalid signature must not burn another
   request's nonce or consume its privileged per-key quota.
4. An enrolled Helper is looked up by numeric IP. The registry signs a descriptor
   binding IP, port, Helper ID, TLS certificate SHA-256, protocol, access mode and
   validity. The client also verifies the signed lease's Helper ID, device ID,
   certificate pin and validity against that descriptor.
5. The lease lasts at most 600 seconds. The client checks the actual Helper TLS
   pin before presenting it, keeps it in RAM and refreshes it through the registry.
   A stored address or mode is not a stored lease. No permanent private token is
   returned to a public client.

The data socket uses a **bearer lease**, not proof-of-possession. Anyone obtaining
a valid lease can use it until expiry subject to Helper limits; the installation
signature is checked during registry authentication, not on every data frame.
Revocation prevents new issuance for that key. Already issued signatures are
not magically withdrawn; their lifetime is bounded by the lease expiry.

A missing registration reclaimed as inactive may be re-enrolled **once using the
same key**. A denied/revoked key must not take that recovery path. Failed requests
have bounded negative caching: normally 15 seconds, 60 for rate-limit/denial.
No busy retry loop or silent creation of a replacement identity is allowed.

## Proving and enrolling a Helper

An app cannot submit an arbitrary pin and thereby establish server ownership.
An explicit owner setup creates a separate P-256 agent identity and a public
HTTPS enrollment endpoint on TCP/443. The central registry performs its own
nonce-bound callback to the numeric public IP, requiring a CA-trusted IP SAN
certificate. It verifies the signed descriptor and TLS IP identity before
recording the Helper. Private/loopback/link-local/mapped address targets, DNS
re-resolution, redirects and disabled certificate validation are rejected.

The enrollment endpoint exposes public signed metadata only. It never reads or
returns the old Helper bearer token. This 443 certificate is separate from the
existing pinned data certificate on 8444. Renewal replaces only enrollment TLS
files and restarts its 443 endpoint; the old data certificate/token are retained.
The short-lived CA profile currently used by the installer has about 160 hours
of validity, so the renewal timer and public ACME reachability are operational
requirements. See [SSH_SETUP.md](SSH_SETUP.md) for ports, consent and failure states.

## Resource and availability limits

Wire JSON is canonical, has exact version/key sets, unique keys, canonical
base64url and an 8192-byte bound. Requests, response bodies, TLS setup, socket
admission and DNS are bounded. Registry storage is bounded (10,000 device rows,
1,024 Helpers, 2,048 challenges); inactive approved registrations may be reclaimed
while revoked identities must remain denied. Global/IP quotas complement
per-key limits. A public enrollment model cannot prevent an attacker from
creating many independent keys; these controls bound resource use rather than
provide hardware identity or an absolute denial-of-service guarantee.

The Helper independently checks the central signature, signed config, Helper
identity, pin, lease lifetime, connection/frame and bandwidth budgets. Registered
data frames cannot be empty; each frame is charged at least 4 KiB against the
resource quota (not a monetary bill). Complete FIN messages and FIFO control/data
are preserved after the confirmed whole/fragment/whole Telegram regression. Admission
must include raw sockets still waiting for TLS. Reconnects and fresh leases must
not reset a device's traffic budget. The payload list and hashes are generated for each exact build. A protocol description
is not a claim that the current client or server release audit is complete.
Registered traffic permits at most 32 concurrent sessions globally and 2 MiB per
message, with upstream queue1. Upload reserves the entire bounded message atomically,
then sends one unfragmented binary WebSocket frame; async-iterator fragmentation is
not compatible with Telegram's initialization path. Default token buckets allow
4 MiB/s per device with a 2 MiB burst, and 16 MiB/s shared with a 4 MiB burst.
Download uses 64 KiB admission chunks. Closed device buckets remain until the full
burst-refill interval has passed, so reconnecting does not grant fresh credit.
Waiting for quota is cancellable. Legacy private-token traffic keeps its prior policy.
A FIFO bounded to two waiters per registered connection admits against both budgets
atomically. Small downloads cannot overtake an older whole-message upload; cancelling
a waiter removes it without spending or retaining quota credit.
Every registered message costs at least 4 KiB of billable budget, limiting tiny
messages to 1,024/s per device and 4,096/s shared after the bounded initial bursts
at the default rates. Empty registered uploads are rejected before forwarding.
These are quota charges; traffic counters continue to report actual transferred bytes.

## Persistence, operations and privacy

Only protected per-install private keys, nonsecret preferences and managed server
credentials/configuration are persisted. Passwords, leases, owner codes, raw
exceptions, SSH output and network payloads do not belong in logs or diagnostics.
Device IDs/IP descriptors are operational pseudonymous data, not hardware
attestation. The central signing key and server agent key stay in protected
owner-managed storage outside Git and publication assets.

Stopping a registry blocks refresh; it does not prove an already accepted data
socket has stopped. Owner disable/rollback procedures must confirm actual central
state. If an enrollment request may have committed but its response was lost,
report the state as unconfirmed, retain the agent identity for owner review and
do not promise an atomic cross-server rollback.

## Verification status

Shared synthetic vectors: `tests/fixtures/helper_registry_v1.json` and the Android
core test resources. Test credentials must never be deployed. Current unit, local TLS, frozen, native UI, APK and physical-device results belong to
[PROJECT_STATE.md](PROJECT_STATE.md), not to this protocol specification.
