# Helper owner-code pairing v1

This optional private-server protocol uses an owner-issued code. IP-only access
for registered clients is described in [DEVICE_REGISTRY.md](DEVICE_REGISTRY.md).

The standalone Helper keeps its TLS certificate and global bearer token.
An owner authenticated over SSH runs:

```sh
sudo /opt/tg-helper/venv/bin/python /opt/tg-helper/helper_pairing.py issue
```

The command prints only a fresh code. It drops root privileges to `tg-helper`
before touching `/var/lib/tg-helper/pairing.sqlite3`. The service unit creates
that directory with `StateDirectory=tg-helper`, mode `0700`; SQLite is `0600`.
Symlinked paths, hard-linked databases, wrong ownership and unsafe POSIX modes
are rejected. Existing certificate and token files remain unchanged. Pairing is
disabled on servers started without `--pairing-store`.

Codes last 300 seconds by default (`--ttl`, maximum 600), have at most five
failed proofs, and are consumed atomically before sending a successful reply.
At most 32 active codes are allowed. SQLite stores the derived key, expiry,
attempt count and consumed status, never the code or bearer token. Expired,
used and exhausted rows are pruned when issuing another code. Cancelling or
losing a successful reply may consume a code; issue a new one to retry.

## Wire format

Use the existing TLS endpoint, normally TCP/8444. TLS 1.2 or newer is required.
Frames contain an unsigned big-endian 32-bit length followed by that many bytes.
The first frame is exactly the seven ASCII bytes `TGPAIR1`. It is recognized
before the regular bearer-token comparison, on the TLS listener only. Normal
authenticated v2 and opt-in legacy v1 remain compatible.

The owner code is `TG1.<id>.<secret>`: ID is eight random bytes (11 unpadded
base64url characters), secret is 16 random bytes (22 characters). Derive
`key = SHA256(full ASCII code)`. All base64url fields must be canonical and
unpadded. JSON is UTF-8, must have unique keys, version must be integer `1`,
and the listed key sets must match exactly.

The client reads the actual TLS leaf certificate and computes its 32-byte
SHA-256 digest `C`. It generates a fresh 32-byte nonce `N` and sends a second
frame, at most 1024 bytes:

```json
{"v":1,"id":"<id>","nonce":"<base64url N>","proof":"<base64url P>"}
```

`P = HMAC-SHA256(key, ASCII("TGPROXY_PAIR_CLIENT_V1") || 0x00 || ASCII(id) || 0x00 || N || C)`.

The server validates against the digest of its own loaded TLS certificate. This
prevents an intermediary with a substituted certificate from forwarding the
client's proof. No owner code, secret or bearer token is sent by the client.

All unavailable, invalid, expired, exhausted or used codes receive the exact
frame body `PAIR_NO`. No diagnostic response contains configuration or secrets.
Pairing frames have a five-second read deadline. The existing admitted-client
limits remain 256 globally and 32 per IP; pre-auth pairing requests also have
rolling limits of 120 per minute globally and 10 per minute per IP. The rate
limiter holds at most 120 timestamp records. SQLite work runs outside the event
loop with a one-second lock timeout and a two-second server task deadline.

After consuming the code, the server generates a fresh 32-byte nonce `S`. The
raw UTF-8 bytes `B` of its configuration payload contain:

```json
{"v":1,"port":8444,"fingerprint":"<lowercase SHA256 hex>","token":"<existing token>"}
```

The response frame, at most 4096 bytes, contains:

```json
{"v":1,"nonce":"<base64url S>","payload":"<base64url B>","proof":"<base64url Q>"}
```

`Q = HMAC-SHA256(key, ASCII("TGPROXY_PAIR_SERVER_V1") || 0x00 || ASCII(id) || 0x00 || N || S || C || B)`.

The client verifies `Q` over the raw payload bytes before parsing the payload
or using its token, then requires the payload fingerprint to equal `C` and the
token to contain 32–512 UTF-8 bytes without controls, DEL or edge whitespace.
The decoded payload is bounded to 2048 bytes and the response to 4096 bytes.
No redirects or transport fallback are used during pairing. The client retains
the reachable IP and port the owner entered, since NAT may map the listener's
port. Only the existing Save operation persists the verified configuration;
Windows protects the token with DPAPI. Closing or cancelling the UI signals
the background worker and discards its result.

Public synthetic vectors for Python/Android interoperability are in
`tests/fixtures/helper_pairing_v1.json`; these credentials must never be used
on a real server.
