# Android development updates

Available since **0.1.6-dev / code 8**; the selected version is **0.1.7-dev / code 9**.
Exact artifact, executed checks and remaining limitations are recorded in
[PROJECT_STATE](../../docs/PROJECT_STATE.md). Build instructions are in
[BUILDING](../BUILDING.md). The first installation over 0.1.5 remains manual.

In 0.1.7, the update implementation, origin and trust keys are unchanged. Its
native ownership/security/cleanup regressions and original code8 -> exact9
in-place migration were checked separately. A new production channel download
and real PackageInstaller UI E2E for code9 were not repeated; the earlier code8
installer receipt is historical evidence, not a new code9 result.

## Using updates

Open **Help → Updates** (**Помощь → Обновления**). The app can check manually,
show the version and short release notes, download the APK with byte/percentage
progress, verify it, and hand it to Android for installation.

Both preferences are enabled by default:

- **Automatically check** requests a daily background check and checks when the
  app is opened if a check is due. Metadata checks can use the current network,
  including mobile data. Disabling this preference cancels the app's automatic
  update jobs; manual checks remain available.
- **Automatically download on unmetered Wi-Fi** permits automatic APK downloads
  only when automatic checking is also enabled and Android reports an unmetered
  Wi-Fi connection. A Wi-Fi connection marked as metered is excluded. A VPN may
  hide the underlying Wi-Fi capability, in which case automatic download waits.
  Manual download uses the current connection and may consume mobile data.

An automatic download stops if its Wi-Fi requirement or either preference stops
being satisfied. Failed automatic attempts have a minimum retry interval of
30 minutes. There is no continuous polling or automatic installation. Jobs also
require the battery not to be low.

The daily interval is a scheduling request, not a promised wall-clock time.
Android can defer jobs until constraints are satisfied, and Doze defers scheduled
work until maintenance opportunities. See Android's
[JobScheduler](https://developer.android.com/reference/android/app/job/JobScheduler),
[periodic job contract](https://developer.android.com/reference/android/app/job/JobInfo.Builder#setPeriodic(long))
and [Doze guidance](https://developer.android.com/training/monitoring-device-state/doze-standby).
Persisting update jobs across reboot does not start the local proxy at boot.

After download and verification, tap **Install update**. Android may first ask
you to permit installation from TG Proxy; return to the app and tap Install again.
Confirm the system installation dialog. The app uses
[PackageInstaller](https://developer.android.com/reference/android/content/pm/PackageInstaller#STATUS_PENDING_USER_ACTION)
and waits for Android's result. A downloaded file at 100%, a submitted installer
session or an open confirmation dialog is not a successful installation.
The existing app does not need to be uninstalled. APK replacement can stop its
process; reopen TG Proxy and check its running state afterward.

Checking, downloading and verification can be cancelled. Failed or cancelled
installation can be retried with the verified APK. An update verification failure
blocks installation rather than relaxing a check. Update notifications are
optional; the update card remains available when notifications are disabled.

**First installation:** 0.1.5-dev and earlier have no updater. Install the first
version with this feature manually over the old app, retaining its original
signer and data. In-app updates apply to subsequent versions. This remains an
Android development channel; it does not turn a dev build into a stable release.

## Related 0.1.6 behavior

The overview button is **Open in Telegram** / **Открыть в Telegram**. It keeps the
system app chooser and uses the running local proxy's current parameters, just
like Copy link. There is no client-specific setup. Help separates the short
start/stop instructions from optional Helper, connection, video and background
troubleshooting. A ready Helper still needs only its IP and an explicit Connect;
SSH setup is a separate action for the server owner.

A failed individual route candidate is an informational event because another
route may succeed. Exhausting all available routes remains a warning. Actual
timed-out attempts enter cooldown; a cancelled race loser or a route that never
started does not. Incoming WebSocket/Helper data can be forwarded as available
instead of waiting to fill a 64 KiB read. Local regressions verify that behavior,
not the cause or speed of a particular Telegram video on Samsung or Xiaomi.

## Trust and compatibility

The client accepts only its compiled Android development origin and the `dev`
channel. It verifies a strict signed metadata envelope before trusting the APK
path, version, size or notes. TLS remains required; neither certificate failures
nor redirects are silently accepted. Android and Windows have separate metadata.
These changes do not alter the Windows stable/candidate channels, Publisher,
Staging or their profiles.

The updater uses Android's `HttpsURLConnection` on all supported API levels,
with the platform certificate and hostname checks and TLS 1.2 or 1.3. It does
not retry a TLS failure through a less trusted transport. This replaces the raw
TLS download path after an API 26 integrity failure; a successful isolated
platform download does not replace verification of the exact selected APK.

Only HTTP 200 with one valid Content-Length and identity encoding is accepted.
Redirects, Transfer-Encoding and duplicate header names, including different
letter case, are rejected. The 8 KiB / 32-header acceptance limit is checked
after the platform has parsed the headers; it is not a limit on the platform's
earlier allocation or bytes read. Metadata and APK body limits remain enforced.

Connect and read operations have timeouts of at most 10 seconds, with an
overall deadline of 15 seconds for metadata and 180 seconds for an APK.
Cancellation closes tracked sockets before disconnecting the HTTP connection.
Before the TLS factory receives the raw socket, a TCP connection or proxy
CONNECT can take until its current platform timeout, up to 10 seconds, to end.
The production origin is a fixed IP; this transport does not provide a separate
bounded DNS resolver. Cancellation and timeout never make partial bytes ready
or bypass the subsequent signature and file checks.

The metadata signature is Ed25519 with key ID `tgproxy-2026-01`. Its signing input
is the domain `TGPROXY_ANDROID_UPDATE_V1` followed by one NUL byte and the canonical
UTF-8 payload. Canonical JSON has sorted keys, compact separators and ASCII escapes
for non-ASCII characters (`ensure_ascii=True`, matching `RegistryJson`). A fixed
cross-language payload fixture guards this encoding. The outer envelope contains
exactly `v`, `key_id`, `payload` and `signature`; the last two are Base64 strings.

Payload fields are exactly `v`, `package_name`, `channel`, `version_code`,
`version_name`, `min_sdk`, `apk_path`, `size`, `sha256`, `signer_sha256`, `notes_ru`,
`notes_en` and `published_at`. The APK path includes its version code and SHA-256.
The client bounds metadata and APK size; publisher-generated envelopes are at
most 8 KiB and APKs at most 64 MiB. Notes are data, not commands or trusted links.

After downloading, the client checks exact byte count, SHA-256, package identity,
version code/name, supported SDK and original signing certificate. Debuggable
and `testOnly` APKs are rejected. The package is `io.github.byshadow64.tgproxy`,
minimum API 26, with the original development signer:

```text
266924f2558b9a81571376f37d21c59310028d810fd6f1e0b2c4e064a0fc71c0
```

The client remembers the highest authenticated version code and its APK hash.
It refuses lower versions and a different hash for the same code, even if the
older metadata has a valid signature. It also refuses reinstalling the current
version. Keep this state when testing upgrades; clearing data would hide a
rollback-protection failure. Cached APKs are revalidated before use, partial files
are discarded, and update storage is separate from the encrypted proxy profile.

## Preparing one immutable bundle

Run the scripts from the repository root with the existing Python environment
and its project dependencies. These tools are for an authorized operator; they
do not build or test the application for you. Complete the exact production APK's
validation first, including both supported API levels and original-release migration.
The first candidate enables controlled end-to-end installer verification; record its
receipt as candidate-only, with public promotion pending. Complete that installer
flow before promoting the exact same bundle to dev. PRIVATE fixtures are never
publication inputs.

The private JSON receipt must contain:

- `validation_passed`: boolean `true`, only after the required checks pass.
- `version`: exact APK version name, for this release `0.1.7-dev`.
- `versionCode`: integer, for this release `9`.
- `sha256`: exact APK SHA-256 as 64 lowercase hexadecimal characters.
- `size`: exact APK byte count as an integer.
- `buildSourceCommit`: actual APK build-source commit as 40 lowercase hex characters.
- `completedUtc`: timezone-qualified ISO timestamp; alternatively supply the
  explicit Unix timestamp with `--published-at`.

Optional `minSdk`, `signerSha256` and `nondebuggable` fields, when present, must
match the independently inspected APK. The receipt is not copied into the public
bundle. It records evidence; it is not a substitute for testing, nor does the
script independently prove the full source/build relationship from a commit ID.

Provide a UTF-8 notes JSON file with exactly two fields, each a single paragraph
of 1–400 characters. For example:

```json
{"ru":"Обновлена помощь и добавлена проверка обновлений приложения.","en":"Updated Help and added application update checks."}
```

Use the actual approved release notes. Keep personal details, server addresses,
download links and private evidence out of them. Instead of `--notes-file`, both
`--notes-ru` and `--notes-en` can be supplied; do not combine the two input modes.

```powershell
python android/scripts/prepare-update.py --apk "<exact-tested.apk>" --receipt "<private-validation.json>" --output "<new-bundle-directory>" --sdk "<existing-sdk>" --java "<existing-jdk>/bin/java.exe" --notes-file "<public-notes.json>"
```

The output directory must not exist. `--sdk` can be omitted when the existing SDK
environment is configured; Java can be resolved from `JAVA_HOME` or PATH.
The script inspects a fixed copy of the input bytes using `aapt` and `apksigner`,
checks package/version/minSDK, the original signer, nondebuggable/non-testOnly
status and fixture exclusions, then compares the receipt's hash and size.
It loads the existing signing key from protected operator storage through the
publisher code. The private key is never put in arguments, logs or the bundle.

The output consists of exactly `manifest.json`, `app.apk` and `SHA256SUMS.txt`.
The APK is copied byte-for-byte; it is not rebuilt. A fixed APK, timestamp, notes
and signing key produce the same signed metadata. Do not regenerate timestamps
or notes when promoting the package to another endpoint.

## Candidate, then the same bundle to dev

```powershell
python android/scripts/publish-update.py --bundle "<same-bundle-directory>" --candidate
python android/scripts/publish-update.py --bundle "<same-bundle-directory>"
```

Run the second command only after verifying the candidate with the intended
client and installer. Candidate selection is for controlled verification, not a
public setting that switches ordinary users onto test fixtures. The publisher
uses the existing protected default profile, requires its origin to match the
client's compiled origin, and checks the current exact SSH host key **before**
authentication. A changed destination is not a way to change installed clients'
update address. Do not bypass a pin failure or print credentials for diagnosis.

Relative to the configured HTTPS origin, candidate metadata is
`/android-dev/candidate/latest.json` and dev metadata is `/android-dev/latest.json`.
Both refer to the same immutable `/android-dev/releases/<code>/<sha256>.apk`.
The corresponding server files are under the configured `/updates` web root;
the origin itself is not embedded in these instructions.

Publication uses SFTP, an exclusive operation lock, immutable version/hash APK
paths and an atomic metadata rename. An already published identical APK is reused;
a conflict, downgrade or different payload for the same version code is rejected.
There is no overwrite, clobber, retag, server-side build or remote shell command.
An existing lock may belong to another operation; do not blindly delete it.

The publisher verifies HTTPS without redirects and requires exactly one valid
Content-Length, identity content encoding, no Transfer-Encoding and exact body
length/hash. It verifies the final metadata bytes too. Before/after snapshots of
Windows stable and candidate metadata must be unchanged. This check protects
those files; it is not a general audit of the whole server.

Record each endpoint's result independently. A failure after metadata commit may
report `committed: true`; inspect and verify that state instead of claiming a
rollback or retrying blindly. A local build, signed bundle, candidate success,
dev success and Android installation are distinct outcomes. Keep the exact APK
build/source commit separate from later test or documentation commits.

GitHub access restoration has been confirmed. Ordinary publication still awaits
the repository preflight and successful CI for the exact source revision;
restored access is not evidence that CI or workflow checks have passed. These
commands publish only the dedicated Android update channel. The restriction on
public download/release-page URLs remains in force; restoration does not waive
that content policy or the normal publication checks.
