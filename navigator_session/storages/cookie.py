"""Encrypted JSON Cookie Storage."""
import base64
from typing import (
    Optional,
    Union
)
from aiohttp import web
from cryptography import fernet
from navigator_session.conf import (
    SESSION_NAME,
    SECRET_KEY
)
from .abstract import AbstractStorage, SessionData

class CookieStorage(AbstractStorage):
    def __init__(
            self,
            *,
            name: str = SESSION_NAME,
            http_only: bool = True,
            max_age: int = None,
            secure: bool = None,
            domain: Optional[str] = None,
            path: str = "/",
            secret_key: Union[str, bytes, bytearray, fernet.Fernet] = None,
            **kwargs
        ) -> None:
        super(
            CookieStorage, self
        ).__init__(
            max_age=max_age,
            secure=secure,
            domain=domain,
            path=path,
            **kwargs
        )
        self.__name__ = name
        self._http_only = http_only
        if not secret_key:
            if isinstance(SECRET_KEY, fernet.Fernet):
                self._secret = SECRET_KEY
            else:
                # generate a new one:
                fernet_key = fernet.Fernet.generate_key()
                self._secret = base64.urlsafe_b64decode(fernet_key)
        elif isinstance(secret_key, fernet.Fernet):
            self._secret = secret_key
        elif isinstance(secret_key, (bytes, bytearray)):
            secret_key = base64.urlsafe_b64encode(secret_key)
            self._secret = fernet.Fernet(secret_key)

    async def on_startup(self, app: web.Application):
        pass

    async def on_cleanup(self, app: web.Application):
        pass

    async def new_session(
        self,
        request: web.Request,
        data: dict = None
    ) -> SessionData:
        pass

    async def load_session(
        self,
        request: web.Request,
        new: bool = False
    ) -> SessionData:
        pass

    async def get_session(self, request: web.Request) -> SessionData:
        pass

    async def save_session(self,
        request: web.Request,
        response: web.StreamResponse,
        session: SessionData
    ) -> None:
        pass

    async def invalidate(
        self,
        request: web.Request,
        session: SessionData
    ) -> None:
        """Try to Invalidate the Session in the Storage."""
