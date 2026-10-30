# Android 0.1.7-dev/code9 — locally verified, 30 October 2026

Exact nondebuggable APK: 12,076,782 bytes, SHA-256
3ac755a52d010587e0405ab761c344a5f1a6ab26a62e37f4c54ec3c8fc6e4403.
Original development signer retained. Host: 143 core passed / 1 opt-in skip,
28 app JVM, 6 Helper Python and 18 publication Python passed; lint 0 errors,
58 warnings. Fake-state Compose: 48 passed on each API 26/36. Exact release
native suites: 19/API26 and 20/API36 passed, with 6 opt-in skips each. Original
official 0.1.6/code8 -> exact9 retained encrypted settings, local secret and
device key on both. Partial cleanup, background/service/update guards, actual
27-file Helper load and post-UI exact-production restore/hash/profile checks
passed. Owned AVDs stopped, userdata retained. Both installed base APK hashes
match the delivery hash above. This is local evidence, not GitHub CI/publication.

The updater origin/signature/implementation are unchanged and independently
compared with preserved prior source. A public code9 update check/download and
real PackageInstaller UI E2E were not repeated in this task. Physical Xiaomi/
Samsung, Telegram account/media speed and long Doze were not tested. Root assigns
the initial source commit and performs any separately authorized publication.
No agent email or shutdown was performed here.

Active source is this new project's android/ directory. The selected version
is0.1.7-dev/code9, minAPI26/target36. Runtime/package/signer/profile identity,
signed Android update origin and security keys stay unchanged. The embedded
27-file Helper is generated from the matching new project root, including
proxy/route_policy.py, and points to byShadow64/tg-proxy. Preserve inherited
Telegram-only/redirect guards. Validation and source snapshots are recorded
separately; later documentation changes do not identify different APK bytes.
Original0.1.6/code8 build3ab6aaf84fe909c51da40293ee4d0928d76c59c2/APK
538f9bdbc2353ca904b867da84626238aa12cbf640011322dc39c09631e80335 remains
the immutable previous release, not the code9 build.
See ../docs/PROJECT_STATE.md, BUILDING.md and docs/ANDROID_UPDATES.md.
Integration/docs commits do not identify new binary bytes.

Keep the original signer and profiles. PRIVATE instrumented/lowered-version
clients must not be published. Changed bytes need a higher versionCode.
Same-code local hardening APKs are not eligible replacements. The first upgrade
from0.1.5 is manual; later updates need Android confirmation.

Preserve owner logo, green launcher, dev notice, screenshots, RU/EN, themes,
chooser and Copy link. Use the applied RUNNING profile; secrets never enter
logs, saved UI state or public docs. Helper is IP + explicit Connect.
SSH is an explicit owner action with exact host key before password and
unchecked public-access consent. Installation keys do not establish identity.

Use the isolated toolchain in BUILDING.md. No global SDK/JDK, VPN changes or
arbitrary device/data wipe. Distinguish host, fake UI, exact release, installer,
transport and physical account/media evidence. Never repeat historical sends
or shutdowns.
