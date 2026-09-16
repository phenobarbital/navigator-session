"""Tests for VaultContext validation and canonical encoding (FEAT-099, TASK-071)."""
import struct
from uuid import UUID

import pytest
from pydantic import ValidationError

from navigator_session.vault import VaultContext


def lp(raw: bytes) -> bytes:
    return struct.pack("!I", len(raw)) + raw


def ctx(*fields, purpose="user-vault", layer="db") -> VaultContext:
    return VaultContext(purpose=purpose, layer=layer, fields=fields)


class TestValidation:
    def test_valid_and_list_normalized(self):
        c = VaultContext(purpose="user-vault", layer="db", fields=[["user_id", 1], ("key", "k")])
        assert c.fields == (("user_id", 1), ("key", "k"))
        assert c.get("key") == "k" and c.get("missing", "d") == "d"

    def test_frozen(self):
        c = ctx(("user_id", 1))
        with pytest.raises(ValidationError):
            c.purpose = "other"  # type: ignore[misc]

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            VaultContext(purpose="p", layer="db", fields=(), extra=1)  # type: ignore[call-arg]

    @pytest.mark.parametrize("purpose", ["", "User-Vault", "has space", "-lead", "x" * 65])
    def test_invalid_purpose(self, purpose):
        with pytest.raises(ValidationError):
            ctx(("user_id", 1), purpose=purpose)

    def test_invalid_layer(self):
        with pytest.raises(ValidationError):
            ctx(("user_id", 1), layer="memory")

    @pytest.mark.parametrize(
        "fields",
        [
            (("user_id", 1), ("user_id", 2)),  # duplicate
            (("1bad", 1),),  # name pattern
            (("user_id",),),  # not a pair
            "user_id",  # not a sequence of pairs
        ],
    )
    def test_invalid_fields(self, fields):
        with pytest.raises(ValidationError):
            VaultContext(purpose="p", layer="db", fields=fields)

    @pytest.mark.parametrize("value", [True, 1.5, b"bytes", {"a": 1}, ["a"]])
    def test_invalid_value_types(self, value):
        with pytest.raises(ValidationError):
            ctx(("v", value))

    def test_types_preserved(self):
        uid = UUID("12345678-1234-5678-1234-567812345678")
        c = ctx(("i", 5), ("s", "5"), ("u", uid), ("n", None))
        assert c.fields == (("i", 5), ("s", "5"), ("u", uid), ("n", None))
        assert isinstance(c.get("u"), UUID)


class TestCanonicalEncoding:
    def test_known_answer(self):
        uid = UUID("12345678-1234-5678-1234-567812345678")
        c = ctx(("user_id", 42), ("key", "api"), ("chatbot_id", uid), ("provider_user_id", None))
        expected = (
            lp(b"user-vault") + lp(b"db") + b"\x00\x04"
            + lp(b"user_id") + b"\x02" + lp(b"42")
            + lp(b"key") + b"\x01" + lp(b"api")
            + lp(b"chatbot_id") + b"\x03" + lp(b"12345678-1234-5678-1234-567812345678")
            + lp(b"provider_user_id") + b"\x00" + lp(b"")
        )
        assert c.canonical_bytes() == expected

    def test_null_vs_empty_string(self):
        assert ctx(("v", None)).canonical_bytes() != ctx(("v", "")).canonical_bytes()

    def test_no_concatenation_ambiguity(self):
        a = ctx(("x", "a:b"), ("y", "c")).canonical_bytes()
        b = ctx(("x", "a"), ("y", "b:c")).canonical_bytes()
        assert a != b

    def test_int_vs_str(self):
        assert ctx(("v", 1)).canonical_bytes() != ctx(("v", "1")).canonical_bytes()

    def test_uuid_vs_str(self):
        uid = UUID("12345678-1234-5678-1234-567812345678")
        assert ctx(("v", uid)).canonical_bytes() != ctx(("v", str(uid))).canonical_bytes()

    def test_order_matters(self):
        a = ctx(("user_id", 1), ("key", "k")).canonical_bytes()
        b = ctx(("key", "k"), ("user_id", 1)).canonical_bytes()
        assert a != b

    def test_purpose_and_layer_encoded(self):
        base = ctx(("v", 1)).canonical_bytes()
        assert ctx(("v", 1), purpose="identity").canonical_bytes() != base
        assert ctx(("v", 1), layer="session").canonical_bytes() != base

    def test_negative_int_and_unicode(self):
        c = ctx(("n", -7), ("s", "ñandú"))
        assert lp(b"-7") in c.canonical_bytes()
        assert lp("ñandú".encode()) in c.canonical_bytes()
