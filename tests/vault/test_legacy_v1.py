"""Tests for the isolated legacy v1 reader (FEAT-099, TASK-075)."""
import base64
import json
import os
import pickle
from pathlib import Path

import pytest

import navigator_session.vault as vault_pkg
import navigator_session.vault.migrate as migrate_pkg
from navigator_session.vault import UnknownKeyVersionError
from navigator_session.vault.crypto import deserialize_value
from navigator_session.vault.migrate.legacy_v1 import LegacyV1Error, LegacyV1Reader

from .v1_helpers import encrypt_v1_db

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def v1():
    return json.loads((FIXTURES / "v1_blobs.json").read_text())


@pytest.fixture
def v1_keys(v1):
    return {int(k): base64.b64decode(v) for k, v in v1["master_keys_b64"].items()}


def expected_value(record):
    if "plaintext_bytes_b64" in record:
        return base64.b64decode(record["plaintext_bytes_b64"])
    return record["plaintext"]


class TestLegacyReader:
    @pytest.mark.parametrize("backend", ["aesgcm", "chacha20"])
    def test_decrypts_frozen_v1_fixture(self, v1, v1_keys, backend):
        """Real v1 blobs (both algorithms) decrypt regardless of the configured backend."""
        reader = LegacyV1Reader(v1_keys, backend)
        db_records = [r for r in v1["records"] if r["layer"] == "db"]
        assert {r["cipher_backend"] for r in db_records} == {"aesgcm", "chacha20"}
        for record in db_records:
            plaintext = reader.decrypt(base64.b64decode(record["blob_b64"]))
            assert deserialize_value(plaintext) == expected_value(record)

    def test_helper_matches_v1_format(self, v1_keys):
        reader = LegacyV1Reader(v1_keys)
        assert reader.decrypt(encrypt_v1_db(b'"x"', 2, v1_keys[2], "chacha20")) == b'"x"'

    def test_from_env(self, master_key_env):
        blob = encrypt_v1_db(b"1", 1, master_key_env[1])
        assert LegacyV1Reader.from_env().decrypt(blob) == b"1"

    def test_unknown_key(self, v1_keys):
        with pytest.raises(UnknownKeyVersionError):
            LegacyV1Reader(v1_keys).decrypt(encrypt_v1_db(b"1", 7, os.urandom(32)))

    def test_tampered_and_short(self, v1_keys):
        reader = LegacyV1Reader(v1_keys)
        blob = encrypt_v1_db(b"secret", 1, v1_keys[1])
        with pytest.raises(LegacyV1Error):
            reader.decrypt(blob[:-1] + bytes([blob[-1] ^ 1]))
        with pytest.raises(LegacyV1Error):
            reader.decrypt(b"\x00\x01" + b"x" * 10)

    def test_wrong_master_key(self, v1_keys):
        blob = encrypt_v1_db(b"secret", 1, os.urandom(32))
        with pytest.raises(LegacyV1Error):
            LegacyV1Reader(v1_keys).decrypt(blob)

    def test_no_key_material_exposed(self, v1_keys):
        reader = LegacyV1Reader(v1_keys)
        assert v1_keys[1].hex() not in repr(reader)
        with pytest.raises(TypeError):
            pickle.dumps(reader)


def test_legacy_reader_not_exported():
    assert not hasattr(vault_pkg, "LegacyV1Reader")
    assert "LegacyV1Reader" not in migrate_pkg.__all__
    assert "LegacyV1Reader" not in vault_pkg.__all__
