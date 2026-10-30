# Building and verifying Android 0.1.7-dev

The selected application uses version name `0.1.7-dev` and version code `9`.
It is an Android development build. Exact source/build commits, artifact hashes
and completed checks are recorded in [PROJECT_STATE](../docs/PROJECT_STATE.md).
Documentation changes do not create a new APK.

## Toolchain and host checks

Run from `android/` with the existing isolated JDK 17 and Android SDK 36:

```powershell
.\scripts\build-local.ps1
.\scripts\build-local.ps1 -Delivery
```

The script runs `:core:verifySshArtifacts`, `:app:verifyHelperPayload`, core tests,
app unit tests, assembly and lint. It verifies the pinned toolchain and the
original development signer. A failed source, dependency or checksum check must
be resolved before proceeding.

`-ToolRoot` selects an existing isolated `TGProxyAndroidBuild` directory.
`-VerifyToolchainOnly` records tool discovery and hash evidence without building.
The script handles the Codex MSIX physical LocalCache path, writes ignored
`local.properties` and restores the process environment afterward. It does not
install system tools, start an emulator or publish an APK.

Pinned tools: Gradle 8.13, AGP 8.11.1, Kotlin 2.2.21, Compose BOM 2025.10.01,
build-tools 35.0.0, minimum API 26 and target API 36. JSch 2.28.8 and Bouncy Castle
1.86 artifact hashes and licenses are verified. The embedded Helper contains
27 normalized source files checked against its manifest. SDKs, caches, signing
keys, actual profiles and private test evidence remain outside Git.

## APK identity and audit

The delivery variant is nondebuggable and unminified. Its original development
signer SHA-256 is:

```text
266924f2558b9a81571376f37d21c59310028d810fd6f1e0b2c4e064a0fc71c0
```

Retain this signer for in-place upgrades. Do not generate a new signing key,
uninstall the application or clear data to conceal a migration failure.

Before accepting `app/build/outputs/apk/release/app-release.apk`, independently
verify its hash, version, manifest, signer and source provenance. Audit DEX for
test/debug harness absence, the embedded Helper manifest, licenses, owner logo,
green launcher asset and four native ABIs, including ZIP/ELF 16 KiB alignment.
Instrumentation is a separate APK and must never be included in the app artifact.

## Device test selection

```powershell
.\scripts\build-local.ps1 -DeviceTests -Serial emulator-5584
.\scripts\build-local.ps1 -Delivery -DeviceTests -Serial emulator-5584
```

Use only the owned disposable `TGProxyAndroidDev` or `TGProxyAndroidApi26` AVD.
The guard requires exactly the selected online emulator and refuses other
device records. Do not bypass it to install on a physical or unrelated device.
Run API 26 and API 36 separately. Restore test settings, clipboard and locales;
close owned listeners, foreground jobs and emulators after checking.

The delivery script currently selects a baseline of service/store/security
classes. It is **not the complete audit suite**. With the matching release test
APK installed, explicitly select these runtime classes as appropriate:

- `ProxyServiceInstrumentedTest`: actual start/stop notification behavior and
  obsolete or missing service commands, including delayed Android foreground
  acknowledgement failures.
- `SettingsApplyRestartInstrumentedTest`: save then restart on a second local
  port, applied-versus-saved port/link behavior, invalid settings rejection and
  exact encrypted-profile restoration. No upstream connection is needed.
- `ConnectionLinkActionsInstrumentedTest`: current running profile, sensitive
  clipboard, system chooser and late-action guards after Stop.
- `HelperSetupServiceInstrumentedTest`: private/dataSync service declaration,
  missing or stale RAM job, obsolete commands and foreground cleanup; no SSH
  connection or server change.
- `HelperEnrollmentServiceInstrumentedTest`: local signed enrollment fixtures,
  cancellation, background lifecycle and settings preservation.
- `SecureStoreInstrumentedTest`, `RegistryIdentityStoreTest`,
  `ActivityScreenshotPolicyInstrumentedTest` and `IdleTrafficInstrumentedTest`:
  storage integrity, installation key, screenshot policy and bounded idle sample.
- `HelperPayloadInstrumentedTest`: load and hash-check the real APK's complete
  27-file public Helper and verify the standalone project's source references.
- `RealEnglishLinkInstrumentedTest`: actual Activity/OS locale behavior on
  API 33 or newer, separate from fake-state locale tests.
- `UpdateRuntimeInstrumentedTest`: updater job ownership, preference changes,
  protected components, rejected foreign installer callbacks and refusal to
  reinstall the current version. Its live offer/download case is opt-in and
  needs separately approved candidate inputs; it is not a default network test.

`io.github.byshadow64.tgproxy.ui.TgProxyUiTest` runs the fake-state Compose suite
on the debug target. It covers RU/EN, both themes, compact 320 × 640 dp layouts
at 1.3 font scale, navigation, settings drafts, applied port, connection links,
masked inputs, endpoint-scoped SSH consent, Help and update states. Verify the
"Open in Telegram" label and the existing system chooser/Copy link behavior.
A passing fake-state test does not establish service or network behavior.

For a generic unattended run, exclude the version-specific migration classes
`UpgradePersistenceInstrumentedTest`, `Upgrade012InstrumentedTest`,
`Upgrade013InstrumentedTest`, `Upgrade015InstrumentedTest` and
`Upgrade016InstrumentedTest` and `Upgrade017InstrumentedTest`; run them only with
their matching original APK and phase arguments. Also keep `DirectRuntimeInstrumentedTest`,
`LivePairingRuntimeInstrumentedTest`, `LiveSshRuntimeInstrumentedTest` and
`SshForegroundRuntimeInstrumentedTest` separate from default tests: they require
explicit live-network or local-fixture inputs. Use AndroidJUnitRunner `class`
or `notClass` arguments with fully qualified class names. Except for the UI
class, the package prefix is `io.github.byshadow64.tgproxy.`.

## Original 0.1.6 → 0.1.7 upgrade

`Upgrade017InstrumentedTest` is a two-phase check on each owned emulator:

1. Install the exact original 0.1.6-dev/code 8 APK with its original signer,
   together with the separately signed compatible instrumentation APK. Select
   `Upgrade017InstrumentedTest#prepareOriginal016Profile` with
   `upgrade017Phase=prepare`. The test verifies the original APK's SHA-256,
   opens the real Activity, and saves hashes rather than profile values.
2. Install the exact candidate 0.1.7-dev/code 9 APK in place, with no uninstall
   or data clearing. Select
   `Upgrade017InstrumentedTest#verifyCode9PreservesExactPrivateProfileAndDeviceKey`
   with `upgrade017Phase=verify`.
3. Preserve both receipts. They must confirm unchanged encrypted settings,
   decoded profile, local secret, Helper mode and installation public-key hash.
   A managed Helper must not persist a bearer lease. Repeat on API26 and API36.

This is an original-release in-place installation check; it is not a lowered
version fixture or evidence that the production update channel has published9.
The updater implementation and its origin are unchanged in this release.
Run the native updater ownership/security/permission/cancellation regressions
separately, together with service background/Stop and the actual embedded Helper
asset check. A migration pass alone does not prove account/media behavior.
Private updater fixtures are never delivery artifacts. Earlier upgrade classes
remain historical fixtures and are excluded from a generic unattended suite.

## Network and lifecycle verification

Core tests must cover strict TLS identity/pin failures, Helper authorization,
WebSocket framing, packet bounds, DNS/connect deadlines, cancellation, address
fallback and Stop races. `TlsAddressFallbackTest` covers real local TLS after
an initial TCP refusal, no fallback on a TLS identity failure, deduplicated and
bounded addresses, a shared deadline, cancellation and stalled DNS.
`SetupCancellationTest` includes a stalled connector across Stop/restart.
`RouteQualificationTest` distinguishes actual failed/deadline-expired candidates
from cancelled race losers and candidates that never started. Individual route
attempt failures are informational; final failure of all routes remains a warning.
`IncrementalMediaReceiveTest` uses real local TLS to ensure a received WebSocket
or Helper body prefix reaches its consumer before the peer sends the remainder.
This catches avoidable 64 KiB batching delays; it does not measure a Telegram
account's video speed or identify the cause of a particular phone's buffering.

Multi-address TCP fallback is bounded by the original connection deadline and
does not retry a failed TLS identity check on another address. Stopping discards
late connector results; a native DNS call that ignores interruption must not be
described as a terminated worker.

Opt-in direct probes select `DirectRuntimeInstrumentedTest` with
`directPublicProbe=1`; `directAllDataCenters=1` exercises all five DCs in ordinary
and media modes. These use anonymous `resPQ`/nonce validation and do not prove
account operation or media throughput. Keep failed cases in the result.

`LivePairingRuntimeInstrumentedTest` accepts an explicitly approved numeric
`liveRegistryHost` and optional `liveBackground=1`. No owner code is needed for
the current IP-only UI. The `SshForegroundRuntimeInstrumentedTest` uses the
isolated local fixture inputs `sshFixturePort` and `sshFixtureFingerprint`.
Live SSH setup has its own protected runtime input path; do not put passwords,
tokens or keys into command-line arguments, Gradle properties, screenshots or
published reports. Do not repeat a real server deployment for a UI-only check.

Check foreground cancellation, socket closure, a fresh retry, Home/return,
notification actions and bounded wake locks. Long Doze, OEM background policies,
physical Samsung/Xiaomi networks, actual Telegram accounts and media speed need
their own evidence. Emulator results do not establish those outcomes.

## Update verification and publication tooling

Core `UpdateProtocolTest` and `UpdateTransportTest` cover signed metadata,
canonical bytes, strict schema, bounds, TLS/HTTP failures and downloads.
The updater uses platform HttpsURLConnection with normal CA/hostname validation
and TLS 1.2/1.3. Repeat the exact native download on API 26 and API 36; JVM success
does not establish Android TLS behavior. Header acceptance limits run after
platform parsing, and pre-TLS cancellation can wait for the configured connection
timeout. See [transport limits](docs/ANDROID_UPDATES.md#trust-and-compatibility).
App `UpdatePolicyTest` covers scheduling, bounded retries and the remembered
highest version/hash. Native tests must additionally exercise Android package
identity/signers, permission and confirmation handling, cancellation, background
jobs and preservation of the existing profile. Download completion alone is not
installation success.

Run the offline publisher tests from the repository root with the existing Python
environment containing the project's dependencies:

```powershell
python android/scripts/test_update_publication.py
```

They use isolated fixtures and do not sign a real release, read server secrets or
contact a server. The suite covers deterministic canonical metadata, original APK
identity, `testOnly` rejection, strict HTTP framing, pinned SSH-before-auth,
immutable APK handling, conflicts, monotonic versions and unchanged Windows files.

Only after the complete exact-APK validation is accepted, prepare one signed
bundle with `prepare-update.py`. Publish it to the Android candidate endpoint,
verify the actual app flow and then publish that **same directory** to Android
dev using `publish-update.py`. See the [receipt schema and commands](docs/ANDROID_UPDATES.md#preparing-one-immutable-bundle).
Neither script rebuilds the APK. A docs commit is not the APK's build commit;
record source, build, validation and channel publication separately. Never use a
private instrumented fixture, replace published bytes or silently reuse an old
validation receipt for changed code.

GitHub access restoration is confirmed; ordinary publication still requires
repository/default/workflow preflight and CI for the exact source revision.
Public download/release-page URLs remain prohibited. Build tooling does not
replace these publication checks. Windows,
Publisher and Staging are separate products and are not updated by this Android
build. Final completed checks and remaining limits belong in PROJECT_STATE,
not an assumed total inferred from the available test classes.
