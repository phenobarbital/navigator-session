from typing import cast
from collections.abc import Callable, Awaitable
from aiohttp import web
from aiohttp.web_middlewares import Handler
from navconfig.logging import logging
from .conf import (
    SESSION_OBJECT,
    SESSION_STORAGE
)
from .storages.abstract import AbstractStorage
from .data import SessionData


Middleware = Callable[[web.Request, Handler], Awaitable[web.StreamResponse]]


### Basic Middleware for Session System
def session_middleware(
        app: web.Application,  # pylint: disable=W0613
        storage: AbstractStorage
) -> Middleware:
    """Middleware to attach Session Storage to every Request."""
    if not isinstance(storage, AbstractStorage):
        raise RuntimeError(
            f"Expected an AbstractStorage got {storage!s}"
        )

    @web.middleware
    async def middleware(
            request: web.Request,
            handler: Handler
    ) -> web.StreamResponse:

        ## adding storage to every request:
        request[SESSION_STORAGE] = storage
        raise_response = None
        try:
            response = await handler(request)
        except web.HTTPException as exc:
            raise_response = exc
            raise exc
        if not isinstance(response, (web.StreamResponse, web.HTTPException)):
            # likely got websocket or streaming
            return response
        session = request.get(SESSION_OBJECT)
        if isinstance(session, SessionData):
            if session.is_changed:
                if response.prepared:
                    # Response already prepared (headers sent):
                    # save session to backend storage but skip
                    # cookie operations (cannot modify headers).
                    logging.debug(
                        "Response already prepared: saving session "
                        "to backend storage without cookie update."
                    )
                    await storage.save_session(request, None, session)
                else:
                    await storage.save_session(request, response, session)
                session.is_changed = False
        if raise_response:
            raise cast(web.HTTPException, raise_response)
        return response

    return middleware
