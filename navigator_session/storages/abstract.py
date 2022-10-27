"""Base Class for all Session Storages."""
import abc
import uuid
import time
import logging
from typing import Optional
from aiohttp import web
from navigator_session.conf import (
    SESSION_NAME,
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_OBJECT
)
from navigator_session.data import SessionData

class AbstractStorage(metaclass=abc.ABCMeta):

    use_cookie: bool = False

    def __init__(
            self,
            *,
            max_age: int = None,
            secure: bool = None,
            domain: Optional[str] = None,
            path: str = "/",
            **kwargs
        ) -> None:
        if not max_age:
            self.max_age = SESSION_TIMEOUT
        else:
            self.max_age = max_age
        # Storage Name
        self.__name__: str = SESSION_NAME
        self._domain: Optional[str] = domain
        self._path: str = path
        self._secure = secure
        self._kwargs = kwargs

    def id_factory(self) -> str:
        return uuid.uuid4().hex

    @property
    def cookie_name(self) -> str:
        return self.__name__

    @abc.abstractmethod
    async def on_startup(self, app: web.Application):
        pass

    @abc.abstractmethod
    async def on_cleanup(self, app: web.Application):
        pass

    @abc.abstractmethod
    async def new_session(
        self,
        request: web.Request,
        data: dict = None
    ) -> SessionData:
        pass

    @abc.abstractmethod
    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        new: bool = False
    ) -> SessionData:
        pass

    @abc.abstractmethod
    async def get_session(self, request: web.Request) -> SessionData:
        pass

    def empty_session(self) -> SessionData:
        return SessionData(None, data=None, new=True, max_age=self.max_age)

    @abc.abstractmethod
    async def save_session(self,
        request: web.Request,
        response: web.StreamResponse,
        session: SessionData
    ) -> None:
        pass

    @abc.abstractmethod
    async def invalidate(
        self,
        request: web.Request,
        session: SessionData
    ) -> None:
        """Try to Invalidate the Session in the Storage."""

    async def forgot(self, request):
        """Delete a User Session."""
        session = await self.get_session(request)
        await self.invalidate(request, session)
        request["session"] = None
        try:
            del request[SESSION_KEY]
            del request[SESSION_OBJECT]
        except Exception as err: # pylint: disable=W0703
            logging.warning(
                f'Session: Error on Forgot Method: {err}'
            )

    def load_cookie(self, request: web.Request) -> str:
        """Getting Cookie from User (if needed)"""
        if self.use_cookie is True:
            return request.cookies.get(self.__name__, None)
        else:
            return None

    def forgot_cooke(self, response: web.StreamResponse) -> None:
        if self.use_cookie is True:
            response.del_cookie(
                self.__name__, domain=self._domain, path=self._path
            )

    def save_cookie(
        self,
        response: web.StreamResponse,
        cookie_data: str,
        *,
        max_age: Optional[int] = None,
    ) -> None:
        if self.use_cookie is True:
            params = {}
            if max_age is not None:
                params["max_age"] = max_age
                t = time.gmtime(time.time() + max_age)
                params["expires"] = time.strftime("%a, %d-%b-%Y %T GMT", t)
            else:
                params['max_age'] = self.max_age
            if not cookie_data:
                response.del_cookie(
                    self.__name__, domain=self._domain, path=self._path
                )
            else:
                response.set_cookie(self.__name__, cookie_data, **params)


    def session_info(self, session: SessionData, request: web.Request) -> SessionData:
        """session_info.
            Session Helper for adding more information extracted from Request.
        Args:
            session (SessionData): Session Object.
            request (web.Request): aiohttp Web Request.

        Returns:
            SessionData: Session object with more attributes.
        """
        try:
            session.ip_addr = request.remote
            session.path_qs = request.path_qs
            session.path = request.path
            session.headers = request.headers
            session.rel_url = request.rel_url
        except (TypeError, AttributeError, ValueError) as ex:
            logging.warning(f'Unable to read Request info: {ex}')
        ### modified Session Object:
        return session
