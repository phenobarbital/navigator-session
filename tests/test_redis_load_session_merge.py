"""RedisStorage.load_session userdata merge (navigator-auth FEAT-103 Module 9).

1.1.0 discarded the caller's `userdata` whenever Redis already held a payload
(`storages/redis.py` built SessionData from the stored data alone).
1.1.1 adds an opt-in merge; the default path is unchanged.
"""
import json
import pytest

from navigator_session.conf import SESSION_KEY
from navigator_session.storages import redis as redis_mod
from navigator_session.storages.redis import RedisStorage


class FakeRedis:
    """Minimal async Redis double backed by a dict."""

    store: dict = {}

    def __init__(self, connection_pool=None):  # same ctor shape as aioredis.Redis
        pass

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, key):
        self.store.pop(key, None)
        return 1


class FakeRequest(dict):
    remote = "127.0.0.1"
    path_qs = "/"
    path = "/"
    headers: dict = {}
    rel_url = "/"


@pytest.fixture
def storage(monkeypatch):
    FakeRedis.store = {}
    monkeypatch.setattr(redis_mod.aioredis, "Redis", FakeRedis)
    st = RedisStorage(max_age=60, secure=False)
    st._redis = object()
    return st


def _seed(session_id="sid-1", **extra):
    payload = {SESSION_KEY: "user-1", "auth_token": "OLD", **extra}
    FakeRedis.store[f"session:{session_id}"] = json.dumps(payload)
    return session_id


@pytest.mark.asyncio
class TestLoadSessionMerge:
    async def test_load_session_merges_fresh_userdata(self, storage):
        sid = _seed()
        userdata = {"session_id": sid, SESSION_KEY: "user-1", "auth_token": "NEW"}
        session = await storage.load_session(
            FakeRequest(), userdata, merge_userdata=True
        )
        assert session["auth_token"] == "NEW"

    async def test_load_session_default_path_is_unchanged(self, storage):
        sid = _seed()
        userdata = {"session_id": sid, SESSION_KEY: "user-1", "auth_token": "NEW"}
        session = await storage.load_session(FakeRequest(), userdata)
        # 1.1.0 behaviour: the stored value wins, userdata is discarded.
        assert session["auth_token"] == "OLD"

    async def test_load_session_no_payload_still_seeds_new_session(
        self, storage, monkeypatch
    ):
        seen = []

        async def fake_new_session(request, data=None, response=None):
            seen.append(data)
            return "NEW-SESSION"

        monkeypatch.setattr(storage, "new_session", fake_new_session)
        userdata = {"session_id": "missing", SESSION_KEY: "user-1", "auth_token": "X"}
        for flag in (False, True):
            result = await storage.load_session(
                FakeRequest(), userdata, new=True, merge_userdata=flag
            )
            assert result == "NEW-SESSION"
        assert seen == [userdata, userdata]
