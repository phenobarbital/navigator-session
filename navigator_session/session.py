from collections.abc import Callable
from aiohttp import web
from navconfig.logging import logging
from .storages.redis import RedisStorage
from .middleware import session_middleware

class SessionHandler:
    """Authentication Backend for Navigator."""
    storage: Callable = None

    def __init__(self, storage: str = 'redis', **kwargs) -> None:
        # TODO: Session Support with parametrization (other storages):
        self._session_object: str = kwargs.get('session_object', 'nav_session')
        # Logging Object:
        self.logger = logging.getLogger(self.__class__.__name__)
        if storage == 'redis':
            self.storage = RedisStorage(logger=self.logger, **kwargs)
        else:
            raise NotImplementedError(
                f"Cannot load a Session Storage {storage}"
            )

    def setup(self, app: web.Application) -> None:
        if isinstance(app, web.Application):
            self.app = app  # register the app into the Extension
        else:
            self.app = app.get_app()  # Nav Application
        ## Configure the Middleware for NAV Session.
        self.app.middlewares.append(
            session_middleware(app, self.storage)
        )
        # startup operations over extension backend
        self.app.on_startup.append(
            self.session_startup
        )
        # cleanup operations over Auth backend
        self.app.on_cleanup.append(
            self.session_cleanup
        )
        self.logger.debug(':::: Session Handler Loaded ::::')
        # register the Auth extension into the app
        self.app[self._session_object] = self

    async def session_startup(self, app: web.Application):
        """
        Calling Session (and Storage) Startup.
        """
        try:
            await self.storage.on_startup(app)
        except Exception as ex:
            self.logger.exception(f'{ex}')
            raise RuntimeError(
                f"Session Storage Error: cannot start Storage Backend {ex}"
            ) from ex

    async def session_cleanup(self, app: web.Application):
        """
        Cleanup Session Processes.
        """
        try:
            await self.storage.on_cleanup(app)
        except Exception as ex:
            self.logger.exception(f'{ex}')
            raise RuntimeError(
                f"Session Storage Error: cannot start Storage Backend {ex}"
            ) from ex
