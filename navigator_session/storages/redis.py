"""Using Redis for Saving Session Storage."""
import time
import logging
from typing import Optional
from collections.abc import Callable
from aiohttp import web
import aioredis
from datamodel.parsers.encoders import DefaultEncoder
from navigator_session.conf import (
    SESSION_URL,
    SESSION_KEY,
    SESSION_OBJECT,
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
        self._objencoder = DefaultEncoder()
        self._encoder = self._objencoder.dumps
        self._decoder = self._objencoder.loads
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
        except Exception as err: # pylint: disable=W0703
            logging.exception(err, stack_info=True)
            return False

    async def on_cleanup(self, app: web.Application):
        try:
            await self._redis.disconnect(inuse_connections = True)
        except Exception as ex: # pylint: disable=W0703
            logging.warning(ex)

    async def get_session(self, request: web.Request, userdata: dict = None) -> SessionData:
        try:
            session = request.get(SESSION_OBJECT)
        except Exception as err: # pylint: disable=W0703
            logging.debug(f'Redis Storage: Error on get Session: {err!s}')
            session = None
        if session is None:
            storage = request.get(SESSION_STORAGE)
            if storage is None:
                raise RuntimeError(
                    "Missing Configuration for Session Middleware."
                )
            session = await self.load_session(request, userdata)
        request[SESSION_OBJECT] = session
        request["session"] = session
        return session

    async def invalidate(self, request: web.Request, session: SessionData) -> None:
        conn = aioredis.Redis(connection_pool=self._redis)
        if not session:
            data = None
            session_id = request.get(SESSION_KEY, None)
            if session_id:
                data = await conn.get(session_id)
            if data is None:
                # nothing to forgot
                return True
        try:
            # delete the ID of the session
            await conn.delete(session.identity)
            session.invalidate() # invalidate this session object
        except Exception as err: # pylint: disable=W0703
            logging.error(err)
            return False
        return True

    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        new: bool = False
    ) -> SessionData:
        """
        Load Session.

        Load User session from backend storage, or create one if
        doesnt exists.

        ---
        new: if False, new session is not created.
        """
        # TODO: first: for security, check if cookie csrf_secure exists
        # if not, session is missed, expired, bad session, etc
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
        except Exception as err:
            logging.exception(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            )
            raise RuntimeError(
                f'Redis Storage: Error loading Redis Session: {err!s}'
            ) from err
        session_id = request.get(SESSION_KEY, None)
        if not session_id:
            session_id = userdata.get(SESSION_KEY, None) if userdata else None
            # TODO: getting from cookie
        if session_id is None and new is False:
            return False
        # we need to load session data from redis
        logging.debug(f':::::: LOAD SESSION FOR {session_id} ::::: ')
        try:
            data = await conn.get(session_id)
        except Exception as err: # pylint: disable=W0703
            logging.error(
                f'Redis Storage: Error Getting Session data: {err!s}'
            )
            data = None
        if data is None:
            if new is True:
                # create a new session if not exists:
                return await self.new_session(request, userdata)
            else:
                return False
        try:
            data = self._decoder(data)
            session = SessionData(
                identity=session_id,
                data=data,
                new=False,
                max_age=self.max_age
            )
        except Exception as err: # pylint: disable=W0703
            logging.warning(err)
            session = SessionData(
                identity=None,
                data=None,
                new=True,
                max_age=self.max_age
            )
        ## add other options to session:
        self.session_info(session, request)
        request[SESSION_KEY] = session_id
        session[SESSION_KEY] = session_id
        request[SESSION_OBJECT] = session
        request["session"] = session
        return session

    async def save_session(self,
        request: web.Request,
        response: web.StreamResponse,
        session: SessionData
    ) -> None:
        """Save the whole session in the backend Storage."""
        session_id = session.identity
        if not session_id:
            session_id = session.get(SESSION_KEY, None)
        if not session_id:
            session_id = self.id_factory()
        if session.empty:
            data = {}
        data = self._encoder(session.session_data())
        max_age = session.max_age
        expire = max_age if max_age is not None else 0
        # TODO: add expiration on redis to value
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
            result = await conn.set(
                session_id, data, expire
            )
            print('SESSION ', result)
        except Exception as err: # pylint: disable=W0703
            print('Error Saving Session: ', err)
            logging.exception(err, stack_info=True)
            return False

    async def new_session(
        self,
        request: web.Request,
        data: dict = None
    ) -> SessionData:
        """Create a New Session Object for this User."""
        session_id = request.get(SESSION_KEY, None)
        if not session_id:
            try:
                session_id = data[SESSION_KEY]
            except KeyError:
                session_id = self.id_factory()
        logging.debug(f':::::: START CREATING A NEW SESSION FOR {session_id} ::::: ')
        if not data:
            data = {}
        # saving this new session on DB
        try:
            conn = aioredis.Redis(connection_pool=self._redis)
            t = time.time()
            data['created'] = t
            data['last_visit'] = t
            data["last_visited"] = f"Last visited: {t!s}"
            data[SESSION_KEY] = session_id
            dt = self._encoder(data)
            result = await conn.set(
                session_id, dt, self.max_age
            )
            logging.info(f'Creation of New Session: {result}')
        except Exception as err: # pylint: disable=W0703
            logging.exception(err)
            return False
        try:
            session = SessionData(
                identity=session_id,
                data=data,
                new=True,
                max_age=self.max_age
            )
        except Exception as err: # pylint: disable=W0703
            print(err)
            logging.exception(f'Error creating Session Data: {err!s}')
        # Saving Session Object:
        ## add other options to session:
        self.session_info(session, request)
        session[SESSION_KEY] = session_id
        request[SESSION_OBJECT] = session
        request[SESSION_KEY] = session_id
        request["session"] = session
        return session
