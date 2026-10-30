# Publishing the signed update channel

The desktop client checks GitHub first and can fall back to a signed HTTPS
manifest. `publish_updates.py` publishes that channel separately from GitHub.
It does not configure Nginx, certificates, SSH, the firewall or the Helper service.

The `Staging` diagnostics branch is explicitly local-only. Never publish it to
GitHub, the stable channel or the candidate channel without a new direct user
instruction. A higher version or passing tests does not authorize promotion.

Build and test the release once, then prepare a new immutable bundle with
`python packaging/prepare_release.py --exe <tested.exe> --bundle-output <new-folder> --build-commit <full-sha>`.
The separate Publisher UI verifies that bundle and signs an explicit approval
outside it. A `release_ready` boolean alone does not authorize publication.
See [the Publisher guide](../docs/PUBLISHER.md).
The publisher accepts exactly these public files:

- `dist/release/TgWsProxy_windows.exe`
- `dist/release/TgWsProxy_helper.zip`
- `dist/release/SHA256SUMS.txt`
- `CHANGELOG.md`

The EXE's file and product versions must match the declared release. The checksum
file must match the EXE and Helper archive. The Helper archive must contain only
the approved server sources, installer, service, license and Helper guide.
Configuration, signing keys, SSH keys and logs are never publication inputs.

## Server prerequisites

Provide a dedicated unprivileged SFTP account with write access to a public
directory, preferably with key authentication and no shell access. The account
must support OpenSSH's `posix-rename` SFTP extension. Create the directory before
publishing; use its absolute path as `--webroot`. For an SFTP chroot, this is the
path visible inside the chroot. The HTTPS `--base-url` must serve that directory.

Configure the HTTPS server to serve regular files, disable directory listings
and deny dot-prefixed paths. Serve `latest.json` with revalidation or a short
cache lifetime; versioned assets can use a long immutable cache lifetime. TLS
must have a certificate trusted by the clients. The server receives no private
signing material.

The resulting directory contains `latest.json` and
`versions/<version>/{TgWsProxy_windows.exe,TgWsProxy_helper.zip,SHA256SUMS.txt,CHANGELOG.md}`.
Uploads use a private temporary directory. Every asset is read back over SFTP
and its size and SHA256 are checked before the complete version directory is
renamed into place. `latest.json` is replaced atomically as the final operation.
Writes are pipelined and readback uses at most 16 concurrent requests in bounded
windows; deadlines and remote hash verification still apply to every upload.
An interrupted publication retains the previous manifest. A completed version
may remain available if only the final manifest replacement fails.

Concurrent publication is blocked by `.publish.lock`. An interrupted process
can leave this directory behind; verify that no publication is running before
an administrator removes that empty lock directory. The publisher never removes
another process's lock, existing releases or unrelated server files.

## Keys and invocation

On the configured Windows publisher PC, run:

```powershell
.venv\Scripts\python.exe packaging/prepare_release.py --exe C:\Build\TgWsProxy.exe --bundle-output C:\Build\publication --build-commit <full-sha>
.venv\Scripts\python.exe packaging/publish_local_updates.py --bundle C:\Build\publication
```

The wrapper reads every public asset, CHANGELOG and release notes from the same
validated bundle, never from the current working tree. It requires a matching
signed approval. It uses `%LOCALAPPDATA%\TGProxyPublisher\publisher.dpapi.json` outside
the project. Signing and SFTP private keys are encrypted with the current
Windows user's DPAPI and decrypted only in memory. They are not sent to the
VPS. Do not delete this file or the Windows profile; loss of the signing key
requires a new client trust key. `--check-connection` tests pinned SFTP without
publishing. Read the real HTTPS/SFTP destination from the local publisher
profile; do not put live offsite download destinations into public documentation.
The managed SFTP account is `tgupdates` and its webroot is `/updates`.
Public user downloads point to GitHub Releases; see
[the public content policy](../docs/GITHUB_CONTENT_POLICY.md).

The managed VPS host keys were rotated to unique per-server keys on 2026-10-24.
The local publisher's pinned host identity was updated and verified with SFTP
write/readback and the normal `--check-connection` command. Existing encrypted
signing/SFTP credentials and the HTTPS release-signing identity were preserved.
Future host-key rotations must update this pin only after verifying the new
identity through the existing trusted administrative connection.

For a release rehearsal, add `--candidate`. This publishes to the isolated
`/candidate/latest.json` channel and leaves the public channel unchanged.
Build the private older test client with that manifest URL, then run
`packaging/verify_update_chain.py --old-exe <test.exe> --new-exe <release.exe>
--output <external-test-folder>`. It verifies normal and portable automatic
installation, restart, listener recovery, settings and encrypted-token
preservation, and removal of the previous EXE and updater workspace. Publish
without `--candidate` only after this succeeds. Test builds are not release assets.

`deploy_update_server.sh` sets up Nginx, an IP-address Let's Encrypt certificate,
twice-daily certificate renewal and this restricted SFTP account on a dedicated
Ubuntu/Debian server. The manifest expires after 90 days; publishing the same
unchanged version again refreshes its signed metadata without replacing assets.

Use the Ed25519 key matching the public `key_id` embedded in
`proxy/update_channel.py`. Keep the private signing key outside the checkout and
release directories. A caller can decrypt a DPAPI-protected key in memory and
pass the resulting `Ed25519PrivateKey` to `build_signed_manifest`; no PEM export
is needed. The API does not serialize or upload that key.

The standalone CLI supports an external Ed25519 PEM key. Install the Windows
build dependencies with `python -m pip install ".[build]"`. For example, in
PowerShell, replace the example URLs, paths and verified SSH fingerprint:

```powershell
python packaging/publish_updates.py `
  --version 1.14.2 `
  --base-url https://updates.example.org/tg-proxy `
  --key-id tgproxy-2026-01 `
  --signing-key "$env:LOCALAPPDATA\TG Proxy Publisher\signing.pem" `
  --ssh-host updates.example.org --ssh-user tg-updates `
  --ssh-key "$env:USERPROFILE\.ssh\tg-updates" `
  --host-key 'SHA256:<verified-base64-fingerprint>' `
  --webroot /srv/tg-proxy-updates
```

Verify the SSH host fingerprint independently before using it. Authentication
happens only after the pin matches. Use `--ask-key-passphrase` or
`--ask-ssh-key-passphrase` for encrypted keys. If password authentication is
needed, replace `--ssh-key` with `--ask-ssh-password`; passwords are read from the
terminal and are never command-line arguments or saved by the publisher.

The Python API is:

```python
build_signed_manifest(version, assets, base_url, private_key, key_id,
                      notes="", page_url=None, *,
                      published_at=None, expires_at=None) -> bytes

publish_release(options, expected_hostkey, webroot, release_files, manifest, *,
                ssh_private_key=None, trusted_keys=None) -> PublicationReport
```

Both file mappings use the four public asset names as keys and local paths as
values. `options` is `utils.ssh_setup.SSHOptions`; `expected_hostkey` is an
`SSHHostKey` or the verified `SHA256:...` fingerprint. `ssh_private_key` is an
in-memory Paramiko key. `trusted_keys` maps key IDs to base64 raw Ed25519 public
keys and defaults to the client's embedded keys. The publisher verifies its
manifest with the same verifier as the client before connecting.

The manifest is schema 1. Its Ed25519 signature covers the canonical UTF-8 JSON
object `{schema, key_id, payload}` using sorted keys, compact separators and
unescaped Unicode. The payload contains version, UTC publication/expiry times,
notes, page URL and each asset's name, HTTPS URL, size and SHA256. Expiry defaults
to 90 days and cannot exceed that interval. Re-sign an unchanged release before
expiry if no new release is ready.

Existing version assets are immutable: publishing the same version again is
allowed only when all four files match their existing bytes. A different build
requires a new version. Replacing `latest.json` with an older version is refused.
Use a separate webroot, URL and test signing key for channel experiments. No
`--force` option changes the production channel's immutability rules.
