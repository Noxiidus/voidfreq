"""Tests for security hardening module."""

import json
import os
import tempfile
from pathlib import Path

from voidfreq.core.security import (
    AuditEntry,
    AuditLog,
    decrypt_data,
    derive_key,
    encrypt_data,
    enforce_permissions,
    secure_temp_file,
)


class TestAuditLog:
    def test_record_and_retrieve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(audit_dir=Path(tmpdir))
            audit.record("scan", "recon", target="192.168.1.0/24")
            audit.record("capture", "attack", target="AA:BB:CC:DD:EE:FF")

            entries = audit.get_entries()
            assert len(entries) == 2
            assert entries[0].operation == "scan"
            assert entries[1].module == "attack"

    def test_search(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(audit_dir=Path(tmpdir))
            audit.record("scan", "recon", target="192.168.1.0/24")
            audit.record("deauth", "attack", target="AA:BB:CC:DD:EE:FF")
            audit.record("scan", "scanner", target="10.0.0.0/8")

            results = audit.search("scan")
            assert len(results) == 2

            results = audit.search("deauth")
            assert len(results) == 1

    def test_audit_file_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(audit_dir=Path(tmpdir))
            audit.record("test_op", "test_mod")

            files = list(Path(tmpdir).glob("audit_*.jsonl"))
            assert len(files) == 1

            with open(files[0]) as f:
                line = f.readline()
                data = json.loads(line)
                assert data["op"] == "test_op"
                assert data["mod"] == "test_mod"

    def test_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            audit = AuditLog(audit_dir=Path(tmpdir))
            for i in range(100):
                audit.record(f"op_{i}", "mod")

            entries = audit.get_entries(limit=10)
            assert len(entries) == 10
            assert entries[0].operation == "op_90"


class TestAuditEntry:
    def test_defaults(self):
        entry = AuditEntry(
            timestamp="2024-01-01T00:00:00",
            operation="scan",
            module="recon",
        )
        assert entry.target == ""
        assert entry.details == ""


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        original = "super_secret_password_123!"
        password = "my_encryption_key"

        encrypted = encrypt_data(original, password)
        assert encrypted != original
        assert isinstance(encrypted, str)

        decrypted = decrypt_data(encrypted, password)
        assert decrypted == original

    def test_wrong_password(self):
        encrypted = encrypt_data("secret data", "correct_password")
        result = decrypt_data(encrypted, "wrong_password")
        assert result is None

    def test_corrupted_data(self):
        assert decrypt_data("not json", "password") is None
        assert decrypt_data('{"v": 2}', "password") is None

    def test_empty_data(self):
        encrypted = encrypt_data("", "password")
        decrypted = decrypt_data(encrypted, "password")
        assert decrypted == ""

    def test_unicode_data(self):
        original = "Jelszó: tesztelés 🔐"
        encrypted = encrypt_data(original, "kulcs")
        decrypted = decrypt_data(encrypted, "kulcs")
        assert decrypted == original

    def test_large_data(self):
        original = "x" * 10000
        encrypted = encrypt_data(original, "key")
        decrypted = decrypt_data(encrypted, "key")
        assert decrypted == original


class TestDeriveKey:
    def test_deterministic_with_salt(self):
        key1, salt = derive_key("password")
        key2, _ = derive_key("password", salt)
        assert key1 == key2

    def test_different_passwords(self):
        key1, salt = derive_key("password1")
        key2, _ = derive_key("password2", salt)
        assert key1 != key2

    def test_key_length(self):
        key, salt = derive_key("password")
        assert len(key) == 32
        assert len(salt) == 16


class TestSecureTempFile:
    def test_creates_file(self):
        path = secure_temp_file()
        try:
            assert os.path.exists(path)
            assert os.path.isfile(path)
        finally:
            os.unlink(path)

    def test_prefix(self):
        path = secure_temp_file(prefix="vf_test_")
        try:
            assert "vf_test_" in os.path.basename(path)
        finally:
            os.unlink(path)


class TestEnforcePermissions:
    def test_nonexistent_file(self):
        enforce_permissions("/nonexistent/file/path")

    def test_existing_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            enforce_permissions(path, 0o600)
        finally:
            os.unlink(path)
