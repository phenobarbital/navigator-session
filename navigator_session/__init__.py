"""
User sessions for Navigator and aiohttp.web server.
"""
from typing import Optional
from aiohttp import web

from .version import (
    __title__, __description__, __version__, __author__
)
from .conf import (
    SESSION_STORAGE,
    SESSION_OBJECT,
    AUTH_SESSION_OBJECT,
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_ID,
    SESSION_REQUEST_KEY,
    SESSION_URL,
    SESSION_PREFIX,
    SESSION_USER_PROPERTY
)
from .data import SessionData
from .session import SessionHandler

__all__ = (
    'SessionData',
    'AUTH_SESSION_OBJECT',
    'SESSION_TIMEOUT',
    'SESSION_URL',
    'SESSION_PREFIX',
    'SESSION_KEY',
    'SESSION_ID',
    'SESSION_USER_PROPERTY',
)


async def new_session(request: web.Request, userdata: dict = None) -> SessionData:
    """new_session.
        Creates a new User Session based on request and optional user Data.
    """
    storage = request.get(SESSION_STORAGE)
    if storage is None:
        raise RuntimeError(
            "Missing Configuration for NAV Session Middleware."
        )
    session = await storage.new_session(request, userdata)
    if not isinstance(session, SessionData):
        raise RuntimeError(
            f"Installed {storage!r} storage should return session instance "
            "on .load_session() call, got {session!r}.")
    request[SESSION_OBJECT] = session
    return session


async def get_session(
        request: web.Request,
        userdata: dict = None,
        new: bool = False,
        ignore_cookie: bool = True
) -> Optional[SessionData]:
    """get_session.

    Getting User session data from request.

    Args:
        request (web.Request): AIOhttp request object.
        userdata (Dict, optional): Optional User data.
        new (bool, optional): if true, a new session is created instead of return error.
        ignore_cookie (bool, optional): if true, session cookie is ignored.

    Raises:
        RuntimeError: Session Middleware is not installed.

    Returns:
        Optional[SessionData]: Dict-like Object with persistent storage of User Data,
        or None when no session is found and ``new`` is False.
    """
    session = request.get(SESSION_OBJECT)
    if session is None:
        storage = request.get(SESSION_STORAGE)
        if storage is None:
            raise RuntimeError(
                "Missing Configuration of Session Storage, please install it."
            )
        # using the storage session for Load an existing Session
        try:
            session = await storage.load_session(
                request=request,
                userdata=userdata,
                new=new,
                ignore_cookie=ignore_cookie
            )
        except Exception as err:
            if new is True:
                return await storage.new_session(request, userdata)
            raise RuntimeError(
                f"Error Loading user Session: {err!s}"
            ) from err
        if session is None:
            return None
        if not isinstance(session, SessionData):
            raise RuntimeError(
                f"Installed {storage!r} storage should return a SessionData "
                f"instance on .load_session() call, got {session!r}."
            )
        request[SESSION_OBJECT] = session
        request[SESSION_REQUEST_KEY] = session
    return session
