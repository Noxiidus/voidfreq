"""Security hardening — credential encryption, file permissions, audit logging."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .logger import get_logger

log = get_logger("security")

AUDIT_DIR = Path.home() / ".voidfreq" / "audit"


@dataclass
class AuditEntry:
    timestamp: str
    operation: str
    module: str
    target: str = ""
    details: str = ""
    user: str = ""


class AuditLog:
    def __init__(self, audit_dir: Path | None = None) -> None:
        self._dir = audit_dir or AUDIT_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._entries: list[AuditEntry] = []
        self._log_path = self._dir / f"audit_{time.strftime('%Y%m%d')}.jsonl"

    def record(
        self,
        operation: str,
        module: str,
        target: str = "",
        details: str = "",
    ) -> None:
        entry = AuditEntry(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
            operation=operation,
            module=module,
            target=target,
            details=details,
            user=os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        )
        self._entries.append(entry)

        try:
            with open(self._log_path, "a") as f:
                f.write(json.dumps({
                    "ts": entry.timestamp,
                    "op": entry.operation,
                    "mod": entry.module,
                    "target": entry.target,
                    "details": entry.details,
                    "user": entry.user,
                }) + "\n")
        except OSError as e:
            log.warning("Failed to write audit log: %s", e)

    def get_entries(self, limit: int = 50) -> list[AuditEntry]:
        return self._entries[-limit:]

    def search(self, query: str) -> list[AuditEntry]:
        q = query.lower()
        return [
            e for e in self._entries
            if q in e.operation.lower()
            or q in e.module.lower()
            or q in e.target.lower()
            or q in e.details.lower()
        ]


def enforce_permissions(path: str | Path, mode: int = 0o600) -> None:
    path = Path(path)
    if not path.exists():
        return

    try:
        if os.name == "posix":
            os.chmod(path, mode)
            log.debug("Set permissions %o on %s", mode, path)
    except OSError as e:
        log.warning("Cannot set permissions on %s: %s", path, e)


def enforce_dir_permissions(dir_path: str | Path, mode: int = 0o700) -> None:
    dir_path = Path(dir_path)
    if not dir_path.exists():
        return

    try:
        if os.name == "posix":
            os.chmod(dir_path, mode)
            for item in dir_path.iterdir():
                if item.is_file():
                    enforce_permissions(item, 0o600)
    except OSError as e:
        log.warning("Cannot set dir permissions on %s: %s", dir_path, e)


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return key, salt


def encrypt_data(data: str, password: str) -> str:
    key, salt = derive_key(password)

    data_bytes = data.encode("utf-8")
    if not data_bytes:
        encrypted = b""
    else:
        xor_stream = hashlib.pbkdf2_hmac(
            "sha256", key, salt + b"stream", 1, dklen=len(data_bytes),
        )
        encrypted = bytes(a ^ b for a, b in zip(data_bytes, xor_stream, strict=True))

    payload = {
        "v": 1,
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(encrypted).decode(),
        "hmac": base64.b64encode(
            hashlib.pbkdf2_hmac("sha256", key, encrypted, 1)
        ).decode(),
    }
    return json.dumps(payload)


def decrypt_data(encrypted_json: str, password: str) -> str | None:
    try:
        payload = json.loads(encrypted_json)
    except (json.JSONDecodeError, TypeError):
        return None

    if payload.get("v") != 1:
        return None

    salt = base64.b64decode(payload["salt"])
    encrypted = base64.b64decode(payload["data"])
    stored_hmac = base64.b64decode(payload["hmac"])

    key, _ = derive_key(password, salt)

    expected_hmac = hashlib.pbkdf2_hmac("sha256", key, encrypted, 1)
    if expected_hmac != stored_hmac:
        return None

    if not encrypted:
        return ""

    xor_stream = hashlib.pbkdf2_hmac(
        "sha256", key, salt + b"stream", 1, dklen=len(encrypted),
    )
    decrypted = bytes(a ^ b for a, b in zip(encrypted, xor_stream, strict=True))

    return decrypted.decode("utf-8")


def secure_temp_file(prefix: str = "voidfreq_") -> str:
    import tempfile
    fd, path = tempfile.mkstemp(prefix=prefix)
    os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path
