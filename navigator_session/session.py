from collections.abc import Callable
from aiohttp import web
from navconfig.logging import logging
from .storages.redis import RedisStorage
from .middleware import session_middleware

class SessionHandler:
    """Authentication Backend for Navigator."""
    storage: Callable = None

    def __init__(self,storage: str = 'redis') -> None:
        # TODO: Session Support with parametrization (other storages):
        if storage == 'redis':
            self.storage = RedisStorage()
        else:
            raise NotImplementedError(
                f"Cannot load a Session Storage {storage}"
            )

    def setup(self, app: web.Application) -> None:
        if isinstance(app, web.Application):
            self.app = app # register the app into the Extension
        else:
            self.app = app.get_app() # Nav Application
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
        logging.debug(':::: Session Handler Loaded ::::')
        # register the Auth extension into the app
        self.app['nav_session'] = self


    async def session_startup(self, app: web.Application):
        """
        Calling Session (and Storage) Startup.
        """
        try:
            await self.storage.on_startup(app)
        except Exception as ex:
            logging.exception(f'{ex}')
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
            logging.exception(f'{ex}')
            raise RuntimeError(
                f"Session Storage Error: cannot start Storage Backend {ex}"
            ) from ex
