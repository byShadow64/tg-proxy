"""Prepare one verified Android dev APK for the separate signed update channel.

No APK is built here. The private receipt must contain validation_passed=true,
version, versionCode, sha256, size, buildSourceCommit and completedUtc (or pass
--published-at). Neither the receipt nor private signing material enters the bundle.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import sys
import time
import zipfile

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
PACKAGE = "io.github.byshadow64.tgproxy"
CHANNEL = "dev"
KEY_ID = "tgproxy-2026-01"
TRUSTED_KEY = base64.b64decode("/JUuGMEQXZSPxtFaxPZO0W6js51c+ocOXq1WL9Qe1z8=")
SIGNER = "266924f2558b9a81571376f37d21c59310028d810fd6f1e0b2c4e064a0fc71c0"
DOMAIN = b"TGPROXY_ANDROID_UPDATE_V1\0"
ORIGIN = "https://217.177.34.28"
MAX_METADATA = 16 * 1024
MAX_APK = 64 * 1024 * 1024
FIELDS = {"v", "package_name", "channel", "version_code", "version_name",
          "min_sdk", "apk_path", "size", "sha256", "signer_sha256",
          "notes_ru", "notes_en", "published_at"}
BUNDLE_FILES = {"manifest.json", "app.apk", "SHA256SUMS.txt"}


class UpdateError(RuntimeError):
    def __init__(self, code, *, committed=False):
        self.code, self.committed = code, committed
        super().__init__(code)


def require(condition, code="invalid_metadata"):
    if not condition:
        raise UpdateError(code)


def canonical(value):
    # RegistryJson.canonical emits ASCII, including lowercase \uXXXX for RU text.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def strict_json(data, limit=MAX_METADATA):
    require(isinstance(data, bytes) and 0 < len(data) <= limit)
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result)
            result[key] = value
        return result
    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(UpdateError("invalid_metadata")))
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("invalid_metadata") from None
    require(isinstance(result, dict))
    return result


def safe_string(value, maximum):
    require(isinstance(value, str) and 1 <= len(value) <= maximum)
    require(all(32 <= ord(c) < 0x10000 and not 0x7f <= ord(c) <= 0x9f
                and not 0xd800 <= ord(c) <= 0xdfff and not 0x202a <= ord(c) <= 0x202e
                and not 0x2066 <= ord(c) <= 0x2069 for c in value))
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)
    return value


def validate_payload(data, now=None):
    require(isinstance(data, dict) and set(data) == FIELDS)
    require(type(data["v"]) is int and data["v"] == 1 and data["package_name"] == PACKAGE
            and data["channel"] == CHANNEL)
    code = integer(data["version_code"], 1, 2**31 - 1)
    require(re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}-dev(?:\.[0-9]{1,3})?",
                         safe_string(data["version_name"], 40)) is not None)
    integer(data["min_sdk"], 26, 100)
    integer(data["size"], 1, MAX_APK)
    require(re.fullmatch("[0-9a-f]{64}", safe_string(data["sha256"], 64)) is not None)
    require(safe_string(data["signer_sha256"], 64) == SIGNER)
    require(safe_string(data["apk_path"], 140) ==
            f"/android-dev/releases/{code}/{data['sha256']}.apk")
    published = integer(data["published_at"], 1, 2**63 - 1)
    require(published <= (int(time.time()) if now is None else now) + 86400)
    safe_string(data["notes_ru"], 1500)
    safe_string(data["notes_en"], 1500)
    return data


def decode64(value, maximum):
    require(isinstance(value, str) and len(value) <= ((maximum + 2) // 3) * 4)
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception:
        raise UpdateError("invalid_metadata") from None
    require(len(decoded) <= maximum and base64.b64encode(decoded).decode("ascii") == value)
    return decoded


def verify_manifest(encoded, *, trusted_key=TRUSTED_KEY, now=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    outer = strict_json(encoded)
    require(set(outer) == {"v", "key_id", "payload", "signature"})
    require(type(outer["v"]) is int and outer["v"] == 1 and outer["key_id"] == KEY_ID)
    payload = decode64(outer["payload"], MAX_METADATA)
    signature = decode64(outer["signature"], 64)
    require(len(signature) == 64)
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(signature, DOMAIN + payload)
    except Exception:
        raise UpdateError("signature") from None
    data = strict_json(payload)
    require(canonical(data) == payload)
    return validate_payload(data, now)


def sign_manifest(payload, key, key_id):
    from cryptography.hazmat.primitives import serialization
    require(key_id == KEY_ID, "signing_key")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(public == TRUSTED_KEY, "signing_key")
    data = canonical(validate_payload(payload))
    encoded = canonical({"v": 1, "key_id": key_id,
                         "payload": base64.b64encode(data).decode("ascii"),
                         "signature": base64.b64encode(key.sign(DOMAIN + data)).decode("ascii")}) + b"\n"
    require(len(encoded) <= 8192, "prepared_metadata_size")
    verify_manifest(encoded, trusted_key=TRUSTED_KEY)
    return encoded


def regular_bytes(path, maximum, code="input_file"):
    path = Path(path)
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
                and not getattr(path, "is_junction", lambda: False)(), code)
        require(0 < info.st_size <= maximum, code)
        with path.open("rb") as source:
            data = source.read(maximum + 1)
        require(len(data) == info.st_size and len(data) <= maximum, code)
        return data
    except UpdateError:
        raise
    except Exception:
        raise UpdateError(code) from None


def checksums(manifest, apk):
    return (hashlib.sha256(apk).hexdigest() + "  app.apk\n" +
            hashlib.sha256(manifest).hexdigest() + "  manifest.json\n").encode("ascii")


def load_bundle(folder, *, trusted_key=TRUSTED_KEY):
    folder = Path(folder)
    require(folder.is_dir() and not folder.is_symlink()
            and not getattr(folder, "is_junction", lambda: False)(), "bundle")
    require({p.name for p in folder.iterdir()} == BUNDLE_FILES, "bundle")
    encoded = regular_bytes(folder / "manifest.json", MAX_METADATA, "bundle")
    data = verify_manifest(encoded, trusted_key=trusted_key)
    apk = regular_bytes(folder / "app.apk", MAX_APK, "bundle")
    require(len(apk) == data["size"] and hashlib.sha256(apk).hexdigest() == data["sha256"], "apk_hash")
    require(regular_bytes(folder / "SHA256SUMS.txt", 512, "bundle") == checksums(encoded, apk), "checksums")
    return data, encoded, apk


def _tool(command):
    try:
        result = subprocess.run(command, capture_output=True, timeout=45, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 1024 * 1024, "apk_inspection")
        return result.stdout.decode("utf-8", "replace")
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("apk_inspection") from None


def inspect_apk(apk, sdk, java=None):
    sdk = Path(sdk)
    tools = sdk / "build-tools" / "35.0.0"
    aapt = tools / ("aapt.exe" if os.name == "nt" else "aapt")
    jar = tools / "lib" / "apksigner.jar"
    require(aapt.is_file() and jar.is_file(), "sdk")
    if java is None:
        home = os.environ.get("JAVA_HOME")
        java = str(Path(home) / "bin" / ("java.exe" if os.name == "nt" else "java")) if home else shutil.which("java")
    require(java and Path(java).is_file(), "java")
    text = _tool([str(aapt), "dump", "badging", str(apk)])
    match = re.search(r"^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'", text, re.M)
    minimum = re.search(r"^sdkVersion:'([0-9]+)'", text, re.M)
    require(match is not None and minimum is not None and "application-debuggable" not in text, "apk_identity")
    require(match[1] == PACKAGE and int(minimum[1]) == 26, "apk_identity")
    xml = _tool([str(aapt), "dump", "xmltree", str(apk), "AndroidManifest.xml"])
    test_only = re.findall(r"android:testOnly(?:\(0x[0-9a-fA-F]+\))?=(.*)", xml)
    require("application-testOnly" not in text and
            all(re.fullmatch(r"\(type 0x12\)0x0|false", value.strip()) for value in test_only), "apk_test_only")
    certs = _tool([str(java), "-jar", str(jar), "verify", "--verbose", "--print-certs",
                   "--min-sdk-version", "26", str(apk)])
    signers = re.findall(r"^Signer #[0-9]+ certificate SHA-256 digest: ([0-9a-fA-F]+)\r?$", certs, re.M)
    require(len(signers) == 1 and signers[0].lower() == SIGNER, "apk_signer")
    require("Verified using v2 scheme (APK Signature Scheme v2): true" in certs
            or "Verified using v3 scheme (APK Signature Scheme v3): true" in certs, "apk_signer")
    return {"version": match[3], "versionCode": int(match[2]), "minSdk": 26,
            "signerSha256": SIGNER, "nondebuggable": True}


def reject_private_fixture(apk):
    require(not any("private" in part.lower() or "fixture" in part.lower() for part in Path(apk).parts), "private_fixture")
    try:
        with zipfile.ZipFile(apk) as zipped:
            names = zipped.namelist()
            require(len(names) == len(set(names)) and len(names) < 10000, "apk_archive")
            require(sum(item.file_size for item in zipped.infolist()) <= 256 * 1024 * 1024, "apk_archive")
            require(not any(n.startswith("/") or ".." in n.split("/") or "\\" in n for n in names), "apk_archive")
            for name in names:
                lowered = name.lower()
                require(not any(word in lowered for word in ["private_do_not_publish", ".jks", ".keystore", "local.properties"]), "private_fixture")
                if re.fullmatch(r"classes[0-9]*\.dex", name):
                    info = zipped.getinfo(name)
                    require(info.file_size <= MAX_APK, "apk_archive")
                    dex = zipped.read(name)
                    require(b"PRIVATE_DO_NOT_PUBLISH" not in dex and b"private-update-client" not in dex, "private_fixture")
                    tests = REPO / "android/app/src/androidTest/java/io/github/byshadow64/tgproxy"
                    for source in tests.rglob("*.kt"):
                        marker = b"Lio/github/byshadow64/tgproxy/" + source.relative_to(tests).with_suffix("").as_posix().encode() + b";"
                        require(marker not in dex, "private_fixture")
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("apk_archive") from None


def validated_receipt(receipt, metadata, apk):
    require(receipt.get("validation_passed") is True, "validation_required")
    require(receipt.get("version") == metadata["version"] and type(receipt.get("versionCode")) is int
            and receipt["versionCode"] == metadata["versionCode"], "receipt_identity")
    require(type(receipt.get("size")) is int and receipt["size"] == len(apk)
            and receipt.get("sha256") == hashlib.sha256(apk).hexdigest(), "receipt_hash")
    require(isinstance(receipt.get("buildSourceCommit"), str)
            and re.fullmatch("[0-9a-f]{40}", receipt["buildSourceCommit"]) is not None, "receipt_identity")
    for name in ["minSdk", "signerSha256", "nondebuggable"]:
        if name in receipt:
            require(type(receipt[name]) is type(metadata[name]) and receipt[name] == metadata[name], "receipt_identity")


def published_time(receipt, explicit):
    if explicit is not None:
        return integer(explicit, 1, 2**63 - 1)
    from datetime import datetime
    try:
        value = datetime.fromisoformat(receipt["completedUtc"].replace("Z", "+00:00"))
        require(value.tzinfo is not None, "receipt_time")
        return int(value.timestamp())
    except UpdateError:
        raise
    except Exception:
        raise UpdateError("receipt_time") from None


def prepare(args):
    output = Path(args.output)
    require(not output.exists() and not output.is_symlink() and output.parent.is_dir(), "output_exists")
    apk_path = Path(args.apk).resolve(strict=True)
    require(not any("private" in part.lower() or "fixture" in part.lower() for part in apk_path.parts), "private_fixture")
    apk = regular_bytes(args.apk, MAX_APK)
    receipt = strict_json(regular_bytes(args.receipt, 128 * 1024), 128 * 1024)
    sdk = args.sdk or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    require(sdk is not None, "sdk")
    # Verify a captured byte snapshot, not a path another process might replace
    # between aapt, signer inspection and the final bundle copy.
    with tempfile.TemporaryDirectory(prefix="tgproxy-android-inspection-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        inspected = Path(temporary) / "app.apk"
        with inspected.open("xb") as target:
            target.write(apk)
        reject_private_fixture(inspected)
        metadata = inspect_apk(inspected, sdk, args.java)
        validated_receipt(receipt, metadata, apk)
    if args.notes_file:
        notes = strict_json(regular_bytes(args.notes_file, 32 * 1024), 32 * 1024)
        require(set(notes) == {"ru", "en"}, "notes")
        ru, en = notes["ru"], notes["en"]
    else:
        ru, en = args.notes_ru, args.notes_en
    digest = hashlib.sha256(apk).hexdigest()
    payload = dict(v=1, package_name=PACKAGE, channel=CHANNEL, version_code=metadata["versionCode"],
                   version_name=metadata["version"], min_sdk=26,
                   apk_path=f"/android-dev/releases/{metadata['versionCode']}/{digest}.apk",
                   size=len(apk), sha256=digest, signer_sha256=SIGNER,
                   notes_ru=safe_string(ru, 400), notes_en=safe_string(en, 400),
                   published_at=published_time(receipt, args.published_at))
    validate_payload(payload)
    # Only the explicit prepare command reaches DPAPI. No key enters CLI/stdout/bundle.
    from publisher.profiles import ServerCredentials
    from publisher.server import load_signing_key
    key, key_id = load_signing_key(ServerCredentials())
    manifest = sign_manifest(payload, key, key_id)
    output.mkdir(mode=0o700)
    for name, data in [("app.apk", apk), ("manifest.json", manifest), ("SHA256SUMS.txt", checksums(manifest, apk))]:
        with (output / name).open("xb") as target:
            target.write(data)
    load_bundle(output)
    return {"status": "prepared", "version": metadata["version"], "version_code": metadata["versionCode"],
            "sha256": digest, "size": len(apk), "output": str(output.resolve())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--java", type=Path)
    parser.add_argument("--notes-file", type=Path)
    parser.add_argument("--notes-ru")
    parser.add_argument("--notes-en")
    parser.add_argument("--published-at", type=int)
    args = parser.parse_args(argv)
    try:
        require(bool(args.notes_file) != bool(args.notes_ru or args.notes_en), "notes")
        print(json.dumps(prepare(args), ensure_ascii=False))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled"}), file=sys.stderr)
        return 130
    except Exception as error:
        code = getattr(error, "code", "prepare_failed")
        code = code if isinstance(code, str) and re.fullmatch("[a-z_]{1,64}", code) else "prepare_failed"
        print(json.dumps({"error": code}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
