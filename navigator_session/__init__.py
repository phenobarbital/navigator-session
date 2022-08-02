"""
User sessions for Navigator and aiohttp.web server.
"""
from aiohttp import web
from typing import (
    Dict
)
from .version import (
    __title__, __description__, __version__, __author__
)
from .conf import (
    SESSION_STORAGE,
    SESSION_OBJECT,
    AUTH_SESSION_OBJECT,
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_URL,
    SESSION_PREFIX,
    SESSION_USER_PROPERTY
)
from .storages import SessionData
from .storages.redis import RedisStorage

__all__ = (
    'RedisStorage',
    'SessionData',
    'AUTH_SESSION_OBJECT',
    'SESSION_TIMEOUT',
    'SESSION_URL',
    'SESSION_PREFIX',
    'SESSION_KEY',
    'SESSION_USER_PROPERTY',
)


async def new_session(request: web.Request, userdata: Dict = None) -> SessionData:
    """new_session.
        Creates a new User Session based on request and optional user Data.
    """
    storage = request.get(SESSION_STORAGE)
    if storage is None:
        raise RuntimeError(
            "Missing Configuration for Session Middleware, please install on Aiohttp Middlewares"
        )
    session = await storage.new_session(request, userdata)
    if not isinstance(session, SessionData):
        raise RuntimeError(
            "Installed {!r} storage should return session instance "
            "on .load_session() call, got {!r}.".format(storage, session))
    request[SESSION_OBJECT] = session
    return session


async def get_session(
        request: web.Request,
        userdata: Dict = None,
        new: bool = False
) -> SessionData:
    """get_session.

    Getting User session data from request.

    Args:
        request (web.Request): AIOhttp request object.
        userdata (Dict, optional): Optional User data.
        new (bool, optional): if true, a new session is created instead of return error.

    Raises:
        RuntimeError: Session Middleware is not installed.

    Returns:
        SessionData: Dict-like Object with persistent storage of User Data.
    """
    session = request.get(SESSION_OBJECT)
    if session is None:
        storage = request.get(SESSION_STORAGE)
        if storage is None:
            raise RuntimeError(
                "Missing Configuration for Session Storage, please install Session Middleware."
            )
        # using the storage session for Load an existing Session
        try:
            session = await storage.load_session(
                request=request,
                userdata=userdata,
                new=new
            )
        except Exception as err:
            raise RuntimeError(
                f"Error Loading user Session: {err!s}"
            )
        request[SESSION_OBJECT] = session
        request['session'] = session
        if new is True and not isinstance(session, SessionData):
            raise RuntimeError(
                "Installed {!r} storage should return session instance "
                "on .load_session() call, got {!r}.".format(storage, session))
    return session
