"""Tests for envelope v2 seal/open (FEAT-099, TASK-071)."""
import base64
import json
import os
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import navigator_session.vault.envelope as envelope_mod
from navigator_session.vault import (
    KeyRing,
    UnknownKeyVersionError,
    UnsupportedFormatError,
    VaultContext,
    VaultCryptoError,
    VaultIntegrityError,
    open_sealed,
    open_value,
    read_header,
    seal,
    seal_value,
)

FIXTURES = Path(__file__).parent / "fixtures"


def lp(raw: bytes) -> bytes:
    return struct.pack("!I", len(raw)) + raw


def ctx(user_id=1, key="api", layer="db", purpose="user-vault") -> VaultContext:
    return VaultContext(purpose=purpose, layer=layer, fields=(("user_id", user_id), ("key", key)))


def flip(blob: bytes, index: int, value: int) -> bytes:
    data = bytearray(blob)
    data[index] = value
    return bytes(data)


class TestRoundTrip:
    @pytest.mark.parametrize("backend,alg_id", [("aesgcm", 1), ("chacha20", 2)])
    def test_roundtrip_both_algorithms(self, master_keys, backend, alg_id):
        ring = KeyRing(master_keys, 1, cipher_backend=backend)
        blob = seal(b"secret", ctx(), ring)
        header = read_header(blob)
        assert blob[0] == 0xA2 and header.alg_id == alg_id and header.key_id == 1
        assert len(blob) == 16 + len(b"secret") + 16
        assert open_sealed(blob, ctx(), ring) == b"secret"

    def test_nonce_is_random(self, keyring):
        assert seal(b"secret", ctx(), keyring) != seal(b"secret", ctx(), keyring)

    def test_open_after_backend_change(self, master_keys):
        aes_ring = KeyRing(master_keys, 1, cipher_backend="aesgcm")
        chacha_ring = KeyRing(master_keys, 1, cipher_backend="chacha20")
        blob = seal(b"secret", ctx(), aes_ring)
        assert open_sealed(blob, ctx(), chacha_ring) == b"secret"

    def test_open_after_backend_change_via_env(self, master_key_env, monkeypatch):
        blob = seal(b"secret", ctx(), KeyRing.from_env())
        monkeypatch.setenv("VAULT_CIPHER_BACKEND", "chacha20")
        assert open_sealed(blob, ctx(), KeyRing.from_env()) == b"secret"

    def test_explicit_key_id(self, keyring):
        blob = seal(b"secret", ctx(), keyring, key_id=2)
        assert read_header(blob).key_id == 2
        assert open_sealed(blob, ctx(), keyring) == b"secret"

    def test_bytes_like_inputs(self, keyring):
        blob = seal(bytearray(b"secret"), ctx(), keyring)
        assert open_sealed(memoryview(blob), ctx(), keyring) == b"secret"

    def test_empty_plaintext(self, keyring):
        blob = seal(b"", ctx(), keyring)
        assert len(blob) == 32
        assert open_sealed(blob, ctx(), keyring) == b""

    @pytest.mark.parametrize(
        "value", ["text", {"a": [1, 2]}, 12345, 1.5, True, None, [1, "x"], b"\x00\xff"]
    )
    def test_value_roundtrip(self, keyring, value):
        assert open_value(seal_value(value, ctx(), keyring), ctx(), keyring) == value


class TestContextBinding:
    @pytest.mark.parametrize(
        "other",
        [
            ctx(user_id=2),
            ctx(key="other"),
            ctx(purpose="identity"),
            VaultContext(purpose="user-vault", layer="db", fields=(("key", "api"), ("user_id", 1))),
            VaultContext(
                purpose="user-vault", layer="db",
                fields=(("user_id", 1), ("key", "api"), ("field", "x")),
            ),
            VaultContext(purpose="user-vault", layer="db", fields=(("user_id", "1"), ("key", "api"))),
        ],
        ids=["user", "key", "purpose", "order", "extra-field", "int-vs-str"],
    )
    def test_wrong_context(self, keyring, other):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, other, keyring)

    def test_db_blob_not_openable_as_session(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, ctx(layer="session"), keyring, session_uuid="sid")


class TestSessionLayer:
    def test_roundtrip(self, keyring):
        blob = seal(b"secret", ctx(layer="session"), keyring, session_uuid="sid-1")
        assert open_sealed(blob, ctx(layer="session"), keyring, session_uuid="sid-1") == b"secret"

    def test_wrong_session(self, keyring):
        blob = seal(b"secret", ctx(layer="session"), keyring, session_uuid="sid-1")
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, ctx(layer="session"), keyring, session_uuid="sid-2")

    def test_session_id_alone_is_not_enough(self, keyring):
        """F1: a different master key with the same session id cannot open the blob."""
        blob = seal(b"secret", ctx(layer="session"), keyring, session_uuid="sid-1")
        attacker = KeyRing({1: os.urandom(32), 2: os.urandom(32)}, 1)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob, ctx(layer="session"), attacker, session_uuid="sid-1")

    def test_session_uuid_required(self, keyring):
        with pytest.raises(ValueError, match="session_uuid is required"):
            seal(b"x", ctx(layer="session"), keyring)
        with pytest.raises(ValueError, match="session_uuid is required"):
            open_sealed(b"\x00" * 40, ctx(layer="session"), keyring)

    def test_session_uuid_forbidden_for_db(self, keyring):
        with pytest.raises(ValueError, match="must not be given"):
            seal(b"x", ctx(), keyring, session_uuid="sid")


class TestTampering:
    def test_key_id_flip_to_existing_key(self, keyring):
        blob = seal(b"secret", ctx(), keyring)  # key_id 1
        with pytest.raises(VaultIntegrityError):
            open_sealed(flip(blob, 3, 2), ctx(), keyring)

    def test_key_id_flip_to_unknown_key(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(UnknownKeyVersionError):
            open_sealed(flip(blob, 3, 9), ctx(), keyring)

    def test_alg_flip_to_other_algorithm(self, keyring):
        blob = seal(b"secret", ctx(), keyring)  # alg 1
        with pytest.raises(VaultIntegrityError):
            open_sealed(flip(blob, 1, 2), ctx(), keyring)

    def test_alg_flip_to_unknown(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(UnsupportedFormatError):
            open_sealed(flip(blob, 1, 7), ctx(), keyring)

    def test_version_flip(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(UnsupportedFormatError):
            open_sealed(flip(blob, 0, 0xA1), ctx(), keyring)

    def test_key_id_zero(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(UnsupportedFormatError):
            open_sealed(flip(blob, 3, 0), ctx(), keyring)

    @pytest.mark.parametrize("index", [4, 15, 16, -1])
    def test_nonce_ciphertext_tag_flip(self, keyring, index):
        blob = seal(b"secret", ctx(), keyring)
        pos = index % len(blob)
        with pytest.raises(VaultIntegrityError):
            open_sealed(flip(blob, pos, blob[pos] ^ 0x01), ctx(), keyring)

    def test_truncated(self, keyring):
        blob = seal(b"secret", ctx(), keyring)
        with pytest.raises(VaultIntegrityError):
            open_sealed(blob[:-1], ctx(), keyring)

    @pytest.mark.parametrize("size", [0, 1, 16, 31])
    def test_short_blob(self, keyring, size):
        with pytest.raises(UnsupportedFormatError):
            open_sealed(b"\xa2" * size, ctx(), keyring)


class TestErrors:
    def test_unknown_key_on_seal(self, keyring):
        with pytest.raises(UnknownKeyVersionError):
            seal(b"x", ctx(), keyring, key_id=9)
        with pytest.raises(UnknownKeyVersionError):
            seal(b"x", ctx(), keyring, key_id=70000)

    def test_unknown_key_error_is_key_error_with_clean_message(self, keyring):
        blob = flip(seal(b"x", ctx(), keyring), 3, 9)
        with pytest.raises(KeyError) as info:
            open_sealed(blob, ctx(), keyring)
        assert isinstance(info.value, VaultCryptoError)
        assert str(info.value) == "master key version 9 not found in key ring"

    def test_type_errors(self, keyring):
        with pytest.raises(TypeError):
            seal("text", ctx(), keyring)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            open_sealed("text", ctx(), keyring)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            seal(b"x", {"purpose": "p"}, keyring)  # type: ignore[arg-type]

    def test_errors_not_value_errors(self):
        """Handlers map ValueError to 400; crypto failures must not be caught by that."""
        for exc in (VaultIntegrityError, UnsupportedFormatError, UnknownKeyVersionError):
            assert not issubclass(exc, ValueError)


class TestKnownAnswer:
    """Independent construction of the wire format from spec §2."""

    MASTER = bytes(range(32))
    NONCE = bytes(range(100, 112))

    def _expected(self, alg_id: int, info_label: bytes, aead_cls, context_bytes: bytes) -> bytes:
        key = HKDF(hashes.SHA256(), 32, None, info_label).derive(self.MASTER)
        header = bytes([0xA2, alg_id]) + struct.pack("!H", 1) + self.NONCE
        aad = b"NAVVAULT-AAD" + header + context_bytes
        return header + aead_cls(key).encrypt(self.NONCE, b"secret", aad)

    def test_db_layer_aesgcm(self, monkeypatch):
        monkeypatch.setattr(envelope_mod, "_random_nonce", lambda: self.NONCE)
        ring = KeyRing({1: self.MASTER}, 1)
        context_bytes = (
            lp(b"user-vault") + lp(b"db") + b"\x00\x02"
            + lp(b"user_id") + b"\x02" + lp(b"42") + lp(b"key") + b"\x01" + lp(b"api")
        )
        expected = self._expected(1, b"navigator-vault/v2/db\x01", AESGCM, context_bytes)
        assert seal(b"secret", ctx(user_id=42), ring) == expected

    def test_session_layer_chacha20(self, monkeypatch):
        monkeypatch.setattr(envelope_mod, "_random_nonce", lambda: self.NONCE)
        ring = KeyRing({1: self.MASTER}, 1, cipher_backend="chacha20")
        context_bytes = (
            lp(b"user-vault") + lp(b"session") + b"\x00\x02"
            + lp(b"user_id") + b"\x02" + lp(b"42") + lp(b"key") + b"\x01" + lp(b"api")
        )
        info = b"navigator-vault/v2/session\x02" + lp(b"sid-9")
        expected = self._expected(2, info, ChaCha20Poly1305, context_bytes)
        assert seal(b"secret", ctx(user_id=42, layer="session"), ring, session_uuid="sid-9") == expected


@pytest.fixture
def v1():
    return json.loads((FIXTURES / "v1_blobs.json").read_text())


@pytest.fixture
def v1_ring(v1):
    keys = {int(k): base64.b64decode(v) for k, v in v1["master_keys_b64"].items()}
    return KeyRing(keys, 1)


class TestLegacyV1Rejected:
    def test_all_v1_blobs_rejected(self, v1, v1_ring):
        for record in v1["records"]:
            blob = base64.b64decode(record["blob_b64"])
            context = ctx(user_id=record["user_id"], key=record["key"], layer=record["layer"])
            kwargs = {"session_uuid": v1["session_uuid"]} if record["layer"] == "session" else {}
            with pytest.raises(VaultCryptoError):
                open_sealed(blob, context, v1_ring, **kwargs)

    def test_v1_db_blobs_are_unsupported_format(self, v1, v1_ring):
        for record in (r for r in v1["records"] if r["layer"] == "db"):
            blob = base64.b64decode(record["blob_b64"])
            with pytest.raises(UnsupportedFormatError):
                open_sealed(blob, ctx(user_id=record["user_id"], key=record["key"]), v1_ring)


class TestPublicApi:
    @pytest.mark.parametrize(
        "name",
        ["encrypt_for_db", "decrypt_for_db", "encrypt_for_session", "decrypt_for_session",
         "derive_key", "CIPHER_CLS"],
    )
    def test_v1_functions_removed_from_crypto(self, name):
        with pytest.raises(ImportError):
            exec(f"from navigator_session.vault.crypto import {name}", {})

    def test_v1_functions_not_exported_from_package(self):
        import navigator_session.vault as vault

        for name in ("encrypt_for_db", "decrypt_for_db", "encrypt_for_session", "decrypt_for_session"):
            assert not hasattr(vault, name)
