# Android security review

The selected source is Android 0.1.7-dev / code 9. Artifact validation is recorded
separately and must not be inferred from the source version. The 27-file Helper
payload includes the Telegram destination policy and fail-closed redirect guard;
the Android relay rejects foreign ingress and unsupported DCs before a network
or lease lookup. These bounds do not inspect encrypted Telegram messages or act
as a device firewall. Package identity, original signer, device key, encrypted
profile and signed update origin are retained. Shared security mechanisms,
completed checks and limits are documented in the [project review](../../docs/SECURITY_AUDIT.md)
and [project state](../../docs/PROJECT_STATE.md). The updater protocol and
installation boundary are described in [ANDROID_UPDATES](ANDROID_UPDATES.md).

Native system installation requires user confirmation, original APK signer,
package/version checks, exact size/hash and signed metadata. Private updater
fixtures are excluded from the published APK. Emulator checks do not establish
physical-device media performance or long Doze behavior.
