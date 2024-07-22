"""Using Redis for Saving Session Storage."""
import time
from typing import Optional
from collections.abc import Callable
from aiohttp import web
from redis import asyncio as aioredis
from ..conf import (
    SESSION_URL,
    SESSION_KEY,
    SESSION_ID,
    SESSION_OBJECT,
    SESSION_REQUEST_KEY,
    SESSION_STORAGE
)
from .abstract import AbstractStorage, SessionData


class RedisStorage(AbstractStorage):
    """Redis JSON storage for User Sessions."""
    def __init__(
            self,
            *,
            max_age: int = None,
            secure: bool = None,
            domain: Optional[str] = None,
            path: str = "/",
            **kwargs
    ) -> None:
        self._redis: Callable = None
        super(
            RedisStorage, self
        ).__init__(
            max_age=max_age,
            secure=secure,
            domain=domain,
            path=path,
            **kwargs
        )

    async def on_startup(self, app: web.Application):
        try:
            self._redis = aioredis.ConnectionPool.from_url(
                SESSION_URL,
                decode_responses=True,
                encoding='utf-8'
            )
        except Exception as err:  # pylint: disable=W0703
            self._logger.exception(err, stack_info=True)
            return False

    async def on_cleanup(self, app: web.Application):
        try:
            await self._redis.disconnect(inuse_connections=True)
        except Exception as ex:  # pylint: disable=W0703
            self._logger.warning(ex)

    async def get_session(
        self,
        request: web.Request,
        userdata: dict = None
    ) -> SessionData:
        try:
            session = request.get(SESSION_OBJECT)
        except Exception as err:  # pylint: disable=W0703
            self._logger.debug(
                f'Redis Storage: Error on get Session: {err!s}'
            )
            session = None
        if session is None:
            storage = request.get(SESSION_STORAGE)
            if storage is None:
                raise RuntimeError(
                    "Missing Configuration for Session Middleware."
                )
            session = await self.load_session(request, userdata)
        request[SESSION_OBJECT] = session
        request[SESSION_REQUEST_KEY] = session
        return session

    async def invalidate(self, request: web.Request, session: SessionData) -> None:
        conn = aioredis.Redis(connection_pool=self._redis)
        if not session:
            data = None
            session_id = request.get(SESSION_ID, None)
            if session_id:
                _id_ = f"session:{session_id}"
                data = await conn.get(_id_)
            if data is None:
                # nothing to forgot
                return True
        try:
            # delete the ID of the session
            await conn.delete(f"session:{session.session_id}")
            session.invalidate()  # invalidate this session object
        except Exception as err:  # pylint: disable=W0703
            self._logger.error(err)
            return False
        return True

    async def get_session_id(self, conn: aioredis.Redis, identity: str) -> str:
        """Get Session ID from Redis."""
        try:
            session_id = await conn.get(f"user:{identity}")
        except Exception as err:
            self._logger.error(
                f'Redis Storage: Error Getting Session ID: {err!s}'
            )
            session_id = None
        return session_id

    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        response: web.StreamResponse = None,
        new: bool = False,
        ignore_cookie: bool = True
    ) -> SessionData:
        """
        Load Session.

        Load User session from backend storage, or create one if
        doesnt exists.

        ---
        new: if False, new session is not created.
        """
        # first: for security, check if cookie csrf_secure exists
        session_id = None
        if ignore_cookie is False and self._use_cookies is True:
            cookie = self.load_cookie(request)
            try:
                session_id = cookie['session_id']
            except (TypeError, KeyError):
                session_id = None
        # if not, session is missed, expired, bad session, etc
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
        except Exception as err:
            self._logger.exception(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            )
            raise RuntimeError(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            ) from err
        if session_id is None:
            session_id = request.get(SESSION_ID, None)
        if not session_id:
            session_id = userdata.get(SESSION_ID, None) if userdata else None
        # get session id from redis using identity:
        session_identity = userdata.get(
            SESSION_KEY, None) if userdata else request.get(SESSION_KEY, None)
        if not session_id:
            session_id = await self.get_session_id(conn, session_identity)
        print('SESSION IDENTITY IS:', session_identity, session_id)
        if session_id is None and new is False:
            # No Session was found, returning false:
            return False
        # we need to load session data from redis
        self._logger.debug(
            f':::::: LOAD SESSION FOR {session_id} ::::: '
        )
        _id_ = f"session:{session_id}"
        try:
            data = await conn.get(_id_)
        except Exception as err:  # pylint: disable=W0703
            self._logger.error(
                f'Redis Storage: Error Getting Session: {err!s}'
            )
            data = None
        if data is None:
            if new is True:
                # create a new session if not exists:
                return await self.new_session(request, userdata)
            else:
                # No Session Was Found
                return False
        try:
            data = self._decoder(data)
            session = SessionData(
                id=session_id,
                identity=session_identity,
                data=data,
                new=False,
                max_age=self.max_age
            )
        except Exception as err:  # pylint: disable=W0703
            self._logger.warning(
                f"Error creating Session Data: {err}"
            )
            session = SessionData(
                id=session_id,
                identity=session_identity,
                data=None,
                new=True,
                max_age=self.max_age
            )
        ## add other options to session:
        self.session_info(session, request)
        session[SESSION_KEY] = session_id
        request[SESSION_KEY] = session_identity
        request[SESSION_ID] = session_id
        request[SESSION_OBJECT] = session
        request[SESSION_REQUEST_KEY] = session
        if self._use_cookies is True and response is not None:
            cookie_data = {
                "session_id": session_id
            }
            cookie_data = self._encoder(cookie_data)
            self.save_cookie(
                response,
                cookie_data=cookie_data,
                max_age=self.max_age
            )
        return session

    async def save_session(
        self,
        request: web.Request,
        response: web.StreamResponse,
        session: SessionData
    ) -> None:
        """Save the whole session in the backend Storage."""
        session_id = session.session_id if session else request.get(SESSION_ID, None)
        if not session_id:
            session_id = session.get(SESSION_ID, None)
        if not session_id:
            session_id = self.id_factory()
        if session.empty:
            data = {}
        data = self._encoder(session.session_data())
        max_age = session.max_age
        expire = max_age if max_age is not None else 0
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
            _id_ = f"session:{session_id}"
            await conn.set(
                _id_, data, expire
            )
        except Exception as err:  # pylint: disable=W0703
            self._logger.exception(err, stack_info=True)
            return False

    async def new_session(
        self,
        request: web.Request,
        data: dict = None,
        response: web.StreamResponse = None
    ) -> SessionData:
        """Create a New Session Object for this User."""
        session_identity = request.get(SESSION_KEY, None)
        session_id = request.get(SESSION_ID, None)
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
        except Exception as err:
            self._logger.error(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            )
            raise RuntimeError(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            ) from err
        if not session_id:
            session_id = await self.get_session_id(conn, session_identity)
        if not session_id:
            try:
                session_id = data[SESSION_ID]
            except KeyError:
                session_id = self.id_factory()
        self._logger.debug(
            f':::::: CREATING A NEW SESSION FOR {session_id} ::::: '
        )
        if not data:
            data = {}
        # saving this new session on DB
        try:
            t = time.time()
            data['created'] = t
            data['last_visit'] = t
            data[SESSION_KEY] = session_identity
            data[SESSION_ID] = session_id
            dt = self._encoder(data)
            _id_ = f'session:{session_id}'
            result = await conn.set(
                _id_, dt, self.max_age
            )
            self._logger.debug(
                f'Session Creation: {result}'
            )
            # Saving the Session ID on redis:
            await conn.set(
                f"user:{session_identity}",
                session_id,
                self.max_age
            )
        except Exception as err:  # pylint: disable=W0703
            self._logger.exception(err)
            return False
        try:
            session = SessionData(
                id=session_id,
                identity=session_identity,
                data=data,
                new=True,
                max_age=self.max_age
            )
            if self._use_cookies is True and response is not None:
                cookie_data = {
                    "last_visit": t,
                    "session_id": session_id
                }
                # TODO: adding crypt
                cookie_data = self._encoder(cookie_data)
                self.save_cookie(
                    response,
                    cookie_data=cookie_data,
                    max_age=self.max_age
                )
        except Exception as err:  # pylint: disable=W0703
            self._logger.exception(
                f'Error creating Session Data: {err!s}'
            )
            return False
        # Saving Session Object:
        ## add other options to session:
        self.session_info(session, request)
        session[SESSION_KEY] = session_identity
        request[SESSION_ID] = session_id
        request[SESSION_OBJECT] = session
        request[SESSION_KEY] = session_identity
        request[SESSION_REQUEST_KEY] = session
        return session
