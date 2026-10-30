"""Publisher-only server profiles; secrets are optional and Windows-DPAPI scoped."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets as random_secrets
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path

from publisher.legacy import publication_core
from utils.secure_storage import protect_token, unprotect_token


class ProfileError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__("Publisher profile failed (" + code + ")")


def data_directory() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
    return (base / "TGProxyPublisher").resolve()


def default_keys_path() -> Path:
    home = Path(os.environ.get("USERPROFILE") or Path.home()).resolve()
    primary = data_directory() / "publisher.dpapi.json"
    # A test/another user profile must never inherit the real user's legacy
    # keys merely because LOCALAPPDATA was not changed alongside USERPROFILE.
    if not primary.resolve().is_relative_to(home):
        primary = home / "AppData/Local/TGProxyPublisher/publisher.dpapi.json"
    if not primary.resolve().is_relative_to(home):
        raise ProfileError("legacy_profile")
    if primary.exists() or primary.is_symlink():
        return primary
    # Codex MSIX can redirect the original publisher configuration into this
    # fixed per-user cache. Discover it read-only, without scanning accounts,
    # copying credentials, changing the old file or following a link outside
    # the current profile. Normal desktop installations keep priority.
    fallback = home / ("AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0/"
                       "LocalCache/Local/TGProxyPublisher/publisher.dpapi.json")
    try:
        meta = fallback.lstat()
        if (stat.S_ISREG(meta.st_mode) and 0 < meta.st_size <= 128 * 1024
                and not fallback.is_symlink() and not getattr(fallback, "is_junction", lambda: False)()
                and fallback.resolve().is_relative_to(home)):
            return fallback.resolve()
    except OSError:
        pass
    return primary


@dataclass(frozen=True)
class ServerProfile:
    profile_id: str = "default"
    name: str = "Сервер по умолчанию"
    host: str = "217.177.34.28"
    port: int = 22
    username: str = "tgupdates"
    webroot: str = "/updates"
    base_url: str = "https://217.177.34.28"
    host_key: str = ""
    host_key_type: str = "ssh-ed25519"
    host_key_data: str = ""
    auth_method: str = "legacy"


@dataclass(frozen=True, repr=False)
class ServerCredentials:
    password: str = field(default="", repr=False)
    key_passphrase: str = field(default="", repr=False)
    private_key_path: str = field(default="", repr=False)
    legacy_key_path: str = field(default_factory=lambda: str(default_keys_path()), repr=False)


def validate_profile(profile: ServerProfile, *, require_pin=True) -> ServerProfile:
    if not isinstance(profile, ServerProfile):
        raise ProfileError("profile")
    from utils.ssh_setup import SSHOptions, _validate_options
    try:
        _validate_options(SSHOptions(profile.host, username=profile.username, port=profile.port))
        publication_core()._https_url(profile.base_url, base=True)
        publication_core()._remote_root(profile.webroot)
        if (re.fullmatch(r"[A-Za-z0-9_-]{1,64}", profile.profile_id) is None
                or not isinstance(profile.name, str) or not 1 <= len(profile.name) <= 100
                or any(ord(c) < 32 for c in profile.name)
                or profile.auth_method not in {"legacy", "key", "password"}):
            raise ValueError
        if profile.host_key or require_pin:
            if re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", profile.host_key) is None:
                raise ValueError
        if profile.host_key_data:
            data = base64.b64decode(profile.host_key_data, validate=True)
            pin = "SHA256:" + base64.b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
            if (not 16 <= len(data) <= 16384 or pin != profile.host_key
                    or profile.host_key_type not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
                                                     "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}):
                raise ValueError
    except Exception:
        raise ProfileError("profile") from None
    return profile


def load_default_profile(keys_path=None) -> ServerProfile:
    """Read public legacy configuration only; never decrypt or alter its keys."""
    path = Path(keys_path) if keys_path else default_keys_path()
    if not path.exists():
        return ServerProfile()
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError
        saved = json.loads(path.read_text(encoding="utf-8"))
        data = base64.b64decode(saved["host_key"], validate=True)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        from proxy.update_channel import UPDATE_MANIFEST_URL
        return validate_profile(ServerProfile(host=saved["host"],
                                base_url=UPDATE_MANIFEST_URL.rsplit("/", 1)[0],
                                host_key=fingerprint, host_key_data=saved["host_key"]))
    except Exception:
        raise ProfileError("legacy_profile") from None


def credentials_to_dict(credentials: ServerCredentials):
    if not isinstance(credentials, ServerCredentials):
        raise ProfileError("credentials")
    return asdict(credentials)


def credentials_from_dict(value=None):
    try:
        if value is None:
            return ServerCredentials()
        if not isinstance(value, dict) or set(value) - set(ServerCredentials.__dataclass_fields__):
            raise ValueError
        if any(not isinstance(v, str) or len(v) > 64 * 1024 for v in value.values()):
            raise ValueError
        return ServerCredentials(**value)
    except Exception:
        raise ProfileError("credentials") from None


class ProfileStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else data_directory() / "profiles.json"
        if self.path.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
            raise ProfileError("store_inside_project")

    def load(self):
        """Return (profiles, decrypted optional secret mapping, active profile ID)."""
        if not self.path.exists():
            return [load_default_profile()], {}, "default"
        try:
            if self.path.is_symlink() or not self.path.is_file() or self.path.stat().st_size > 512 * 1024:
                raise ValueError
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(saved, dict) or saved.get("schema") != 1:
                raise ValueError
            profiles = [validate_profile(ServerProfile(**v), require_pin=False) for v in saved["profiles"]]
            if (not 1 <= len(profiles) <= 50 or len({p.profile_id for p in profiles}) != len(profiles)
                    or saved["active_profile"] not in {p.profile_id for p in profiles}):
                raise ValueError
            private = {}
            if saved.get("secrets_dpapi"):
                try:
                    private = json.loads(unprotect_token(saved["secrets_dpapi"]))
                except Exception:
                    raise ProfileError("secret_store") from None
                if not isinstance(private, dict):
                    raise ProfileError("secret_store")
            return profiles, private, saved["active_profile"]
        except ProfileError:
            raise
        except Exception:
            raise ProfileError("profile_store") from None

    def save(self, profiles, secrets=None, active_id="default"):
        """Atomically save public metadata and optionally DPAPI-encrypted secrets.

        Pass an empty mapping to forget remembered credentials. Secrets=None
        retains the existing ciphertext without decrypting it.
        """
        temporary = None
        try:
            profiles = list(profiles)
            if (not 1 <= len(profiles) <= 50 or len({p.profile_id for p in profiles}) != len(profiles)
                    or active_id not in {p.profile_id for p in profiles}):
                raise ValueError
            public = [asdict(validate_profile(p, require_pin=False)) for p in profiles]
            cipher = ""
            if secrets is None and self.path.exists():
                if self.path.is_symlink() or self.path.stat().st_size > 512 * 1024:
                    raise ValueError
                cipher = json.loads(self.path.read_text(encoding="utf-8")).get("secrets_dpapi", "")
            elif secrets:
                if not isinstance(secrets, dict):
                    raise ValueError
                plain = json.dumps(secrets, ensure_ascii=False, allow_nan=False)
                if len(plain.encode("utf-8")) > 128 * 1024:
                    raise ValueError
                try:
                    cipher = protect_token(plain)
                except Exception:
                    raise ProfileError("secret_store") from None
            data = json.dumps({"schema": 1, "profiles": public, "active_profile": active_id,
                               "secrets_dpapi": cipher}, ensure_ascii=False, indent=2)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.is_symlink():
                raise ValueError
            temporary = self.path.with_name(".profiles." + random_secrets.token_hex(12) + ".tmp")
            with temporary.open("x", encoding="utf-8") as target:
                target.write(data)
            os.replace(temporary, self.path)
        except ProfileError:
            raise
        except Exception:
            raise ProfileError("profile_store") from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass


def load_profiles(path=None):
    return ProfileStore(path).load()


def save_profiles(profiles, secrets=None, active_id="default", path=None):
    return ProfileStore(path).save(profiles, secrets, active_id)
