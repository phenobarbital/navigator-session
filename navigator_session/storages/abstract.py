"""Base Class for all Session Storages."""
import sys
from abc import ABCMeta, abstractmethod
import uuid
import time
import logging
from typing import Optional
from aiohttp import web
from datamodel.parsers.encoders import DefaultEncoder
from datamodel.parsers.json import (  # pylint: disable=C0411
    json_encoder,
    json_decoder
)
from ..conf import (
    SESSION_TIMEOUT,
    SESSION_KEY,
    SESSION_ID,
    SESSION_OBJECT,
    SESSION_REQUEST_KEY,
    SESSION_COOKIE_SECURE
)
from ..data import SessionData


if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

class _CookieParams(TypedDict, total=False):
    domain: Optional[str]
    max_age: Optional[int]
    path: str
    secure: Optional[bool]
    httponly: bool
    samesite: Optional[str]
    expires: str

class AbstractStorage(metaclass=ABCMeta):

    _use_cookies: bool = False

    def __init__(
            self,
            *,
            logger: Optional[logging.Logger] = None,
            max_age: int = None,
            secure: bool = True,
            domain: Optional[str] = None,
            path: str = "/",
            httponly: bool = True,
            samesite: Optional[str] = 'Lax',
            **kwargs
    ) -> None:
        if logger is not None:
            self._logger = logger
        else:
            self._logger = logging.getLogger('Nav_Session.Storage')
        if not max_age:
            self.max_age = SESSION_TIMEOUT
        else:
            self.max_age = max_age
        # Using session cookies:
        self._use_cookies = kwargs.get('use_cookies', False)
        # Storage Name
        self.__name__: str = SESSION_COOKIE_SECURE
        self._domain: Optional[str] = domain
        self._path: str = path
        self._secure = secure
        self._kwargs = kwargs
        self._httponly = httponly
        self._samesite = samesite
        self._objencoder = DefaultEncoder()
        self._encoder = json_encoder
        self._decoder = json_decoder

    def id_factory(self) -> str:
        return uuid.uuid4().hex

    @property
    def cookie_name(self) -> str:
        return self.__name__

    @abstractmethod
    async def on_startup(self, app: web.Application):
        pass

    @abstractmethod
    async def on_cleanup(self, app: web.Application):
        pass

    @abstractmethod
    async def new_session(
        self,
        request: web.Request,
        data: dict = None
    ) -> SessionData:
        pass

    @abstractmethod
    async def load_session(
        self,
        request: web.Request,
        userdata: dict = None,
        response: web.StreamResponse = None,
        new: bool = False,
        ignore_cookie: bool = True
    ) -> SessionData:
        pass

    @abstractmethod
    async def get_session(self, request: web.Request) -> SessionData:
        pass

    def empty_session(self) -> SessionData:
        return SessionData(
            None,
            data=None,
            new=True,
            max_age=self.max_age
        )

    @abstractmethod
    async def save_session(
        self,
        request: web.Request,
        response: web.StreamResponse,
        session: SessionData
    ) -> None:
        pass

    @abstractmethod
    async def invalidate(
        self,
        request: web.Request,
        session: SessionData
    ) -> None:
        """Try to Invalidate the Session in the Storage."""
        pass

    async def forgot(self, request: web.Request, response: web.StreamResponse = None):
        """forgot.

        Forgot (delete) a user session.
        """
        session = await self.get_session(request)
        await self.invalidate(request, session)
        request[SESSION_REQUEST_KEY] = None
        try:
            del request[SESSION_KEY]
            del request[SESSION_ID]
            del request[SESSION_OBJECT]
        except Exception as err:  # pylint: disable=W0703
            self._logger.warning(
                f'Session: Error on Forgot Method: {err}'
            )
        if response is not None:
            # also, forgot the secure Cookie:
            self.forgot_cookie(response)

    def load_cookie(self, request: web.Request) -> str:
        """Getting Cookie from User (if needed)"""
        if self._use_cookies is True:
            cookie = request.cookies.get(self.__name__, None)
            if cookie:
                return self._decoder(cookie)
        return None

    def forgot_cookie(self, response: web.StreamResponse) -> None:
        if self._use_cookies is True:
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
        if self._use_cookies is True:
            expires = None
            if max_age is not None:
                t = time.gmtime(time.time() + max_age)
                expires = time.strftime("%a, %d-%b-%Y %T GMT", t)
            else:
                max_age = self.max_age
            params = _CookieParams(
                domain=self._domain,
                max_age=max_age,
                path=self._path,
                secure=self._secure,
                httponly=self._httponly,
                samesite=self._samesite,
                expires=expires
            )
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
            self._logger.warning(f'Unable to read Request info: {ex}')
        ### modified Session Object:
        return session
