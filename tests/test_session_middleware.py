"""session_middleware saves a changed session onto a raised HTTPException too.

Up to 1.1.2 the middleware re-raised an ``HTTPException`` straight out of its
``except`` block, so its ``save_session`` call (and the trailing re-raise meant
to follow it) never ran for a raised response: a handler that created a session
and then *raised* its redirect sent the redirect without the session cookie.
"""
from typing import Optional

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from navigator_session.conf import SESSION_OBJECT
from navigator_session.data import SessionData
from navigator_session.middleware import session_middleware
from navigator_session.storages.abstract import AbstractStorage

COOKIE = "TEST_SESSION"

# The middleware indexes the request with plain string keys (SESSION_STORAGE,
# SESSION_OBJECT) that navigator-auth reads back; aiohttp 3.14 advises
# web.RequestKey for those, and filterwarnings=error would turn that advice
# into a 500 here.
pytestmark = pytest.mark.filterwarnings("ignore::aiohttp.web_exceptions.NotAppKeyWarning")


class RecordingStorage(AbstractStorage):
    """Cookie-writing storage double that records every save_session call."""

    def __init__(self) -> None:
        super().__init__(name=COOKIE, max_age=60, secure=False, use_cookies=True)
        self.saved: list = []
        self.sessions: list = []

    async def on_startup(self, app: web.Application):
        return None

    async def on_cleanup(self, app: web.Application):
        return None

    async def new_session(self, request: web.Request, data: dict = None) -> SessionData:
        session = SessionData(None, data=data or {}, new=True, max_age=self.max_age)
        request[SESSION_OBJECT] = session
        self.sessions.append(session)
        return session

    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        response: web.StreamResponse = None,
        new: bool = False,
        ignore_cookie: bool = True,
    ) -> SessionData:
        return await self.new_session(request, userdata)

    async def get_session(self, request: web.Request) -> SessionData:
        return request.get(SESSION_OBJECT)

    async def save_session(
        self,
        request: web.Request,
        response: Optional[web.StreamResponse],
        session: SessionData,
    ) -> None:
        self.saved.append(response)
        if response is not None:
            self.save_cookie(response, cookie_data=session.session_id, max_age=60)

    async def invalidate(self, request: web.Request, session: SessionData) -> None:
        return None


async def _with_session(request: web.Request, storage: RecordingStorage) -> SessionData:
    session = await storage.new_session(request, {"user": "u-1"})
    assert session.is_changed
    return session


def _app(storage: RecordingStorage) -> web.Application:
    app = web.Application()
    app.middlewares.append(session_middleware(app, storage))

    async def returns_ok(request):
        await _with_session(request, storage)
        return web.Response(text="ok")

    async def raises_redirect(request):
        await _with_session(request, storage)
        raise web.HTTPFound("/home")

    async def raises_forbidden(request):
        await _with_session(request, storage)
        raise web.HTTPForbidden(reason="nope")

    async def raises_redirect_unchanged(request):
        session = await _with_session(request, storage)
        session.is_changed = False
        raise web.HTTPFound("/home")

    async def raises_redirect_no_session(request):
        raise web.HTTPFound("/home")

    async def raises_runtime_error(request):
        await _with_session(request, storage)
        raise RuntimeError("boom")

    for path, handler in {
        "/ok": returns_ok,
        "/redirect": raises_redirect,
        "/forbidden": raises_forbidden,
        "/redirect-unchanged": raises_redirect_unchanged,
        "/redirect-no-session": raises_redirect_no_session,
        "/error": raises_runtime_error,
    }.items():
        app.router.add_get(path, handler)
    return app


@pytest_asyncio.fixture
async def client():
    storage = RecordingStorage()
    test_client = TestClient(TestServer(_app(storage)))
    await test_client.start_server()
    try:
        yield test_client, storage
    finally:
        await test_client.close()


@pytest.mark.asyncio
class TestSessionMiddleware:
    async def test_returned_response_gets_the_session_cookie(self, client):
        test_client, storage = client
        resp = await test_client.get("/ok")
        assert resp.status == 200
        assert COOKIE in resp.cookies
        assert len(storage.saved) == 1

    async def test_raised_redirect_gets_the_session_cookie(self, client):
        test_client, storage = client
        resp = await test_client.get("/redirect", allow_redirects=False)
        assert resp.status == 302
        assert resp.headers["Location"] == "/home"
        assert COOKIE in resp.cookies
        assert len(storage.saved) == 1
        assert isinstance(storage.saved[0], web.HTTPFound)

    async def test_saving_resets_the_changed_flag_without_a_data_key(self, client):
        test_client, storage = client
        await test_client.get("/redirect", allow_redirects=False)
        (session,) = storage.sessions
        assert session.is_changed is False
        assert "is_changed" not in session.session_data()

    async def test_raised_error_still_saves_a_changed_session(self, client):
        test_client, storage = client
        resp = await test_client.get("/forbidden")
        assert resp.status == 403
        assert COOKIE in resp.cookies
        assert len(storage.saved) == 1

    async def test_unchanged_session_is_not_saved_on_a_raised_redirect(self, client):
        test_client, storage = client
        resp = await test_client.get("/redirect-unchanged", allow_redirects=False)
        assert resp.status == 302
        assert COOKIE not in resp.cookies
        assert storage.saved == []

    async def test_raised_redirect_without_a_session_passes_through(self, client):
        test_client, storage = client
        resp = await test_client.get("/redirect-no-session", allow_redirects=False)
        assert resp.status == 302
        assert storage.saved == []

    async def test_other_exceptions_propagate_without_saving(self, client):
        test_client, storage = client
        resp = await test_client.get("/error")
        assert resp.status == 500
        assert storage.saved == []
