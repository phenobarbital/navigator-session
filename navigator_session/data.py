import uuid
import time
from typing import Union, Optional, Any
from datetime import datetime
from collections.abc import Iterator, Mapping, MutableMapping
import pendulum
import jsonpickle
from jsonpickle.unpickler import loadclass
from aiohttp import web
from datamodel import BaseModel
from .conf import (
    SESSION_KEY,
    SESSION_ID,
    SESSION_STORAGE
)

class ModelHandler(jsonpickle.handlers.BaseHandler):
    """ModelHandler.
    This class can handle with serializable Data Models.
    """
    def flatten(self, obj, data):
        data['__dict__'] = self.context.flatten(obj.__dict__, reset=False)
        return data

    def restore(self, obj):
        module_and_type = obj['py/object']
        mdl = loadclass(module_and_type)
        if hasattr(mdl, '__new__'):
            cls = mdl.__new__(mdl)
        else:
            cls = object.__new__(mdl)

        cls.__dict__ = self.context.restore(obj['__dict__'], reset=False)
        return cls

jsonpickle.handlers.registry.register(BaseModel, ModelHandler, base=True)

class SessionData(MutableMapping[str, Any]):
    """Session dict-like object.
    """

    _data: Union[str, Any] = {}

    def __init__(
        self,
        *args,
        data: Optional[Mapping[str, Any]] = None,
        new: bool = False,
        id: Optional[str] = None,
        identity: Optional[Any] = None,
        max_age: Optional[int] = None
    ) -> None:
        self._changed = False
        self._data = {}
        # Unique ID:
        self._id_ = data.get(SESSION_ID, None) if data else id
        if not self._id_:
            self._id_ = uuid.uuid4().hex
        # Session Identity
        self._identity = data.get(SESSION_KEY, None) if data else identity
        if not self._identity:
            self._identity = self._id_
        self._new = new if data != {} else True
        self._max_age = max_age if max_age else None
        created = data.get('created', None) if data else None
        self._now = pendulum.now('UTC')  # time for this instance creation
        self.__created__ = self._now
        now = int(self._now.int_timestamp)
        self._now = now  # time for this instance creation
        age = now - created if created else now
        if max_age is not None and age > max_age:
            data = None
        if self._new or created is None:
            self._created = now
        else:
            self._created = created
        ## Data updating.
        if data is not None:
            self._data.update(data)
        # Other mark timestamp for this session:
        dt = pendulum.now('UTC')
        self._dow = dt.day_of_week
        self._time = dt.time()
        self.args = args

    def __repr__(self) -> str:
        return f'<NAV-Session [new:{self.new}, created:{self.created}] {self._data!r}>'

    @property
    def new(self) -> bool:
        return self._new

    @property
    def logon_time(self) -> datetime:
        return self.__created__

    @property
    def session_id(self) -> str:
        return self._id_

    @property
    def identity(self) -> Optional[Any]:  # type: ignore[misc]
        return self._identity

    @property
    def created(self) -> int:
        return self._created

    @property
    def dow(self) -> int:
        return self._dow

    @property
    def session_time(self) -> time:
        return self._time

    @property
    def empty(self) -> bool:
        return not bool(self._data)

    @property
    def max_age(self) -> Optional[int]:
        return self._max_age

    @max_age.setter
    def max_age(self, value: Optional[int]) -> None:
        self._max_age = value

    @property
    def is_changed(self) -> bool:
        return self._changed

    @is_changed.setter
    def is_changed(self, value: bool) -> None:
        self._changed = value

    def changed(self) -> None:
        self._changed = True

    def session_data(self) -> dict:
        return self._data

    def invalidate(self) -> None:
        self._changed = True
        self._data = {}

    # Magic Methods
    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._changed = True
        # TODO: also, saved into redis automatically

    def __delitem__(self, key: str) -> None:
        del self._data[key]
        self._changed = True

    def __getattr__(self, key: str) -> Any:
        return self._data[key]

    def encode(self, obj: Any) -> str:
        """encode

            Encode an object using jsonpickle.
        Args:
            obj (Any): Object to be encoded using jsonpickle

        Raises:
            RuntimeError: Error converting data to json.

        Returns:
            str: json version of the data
        """
        try:
            return jsonpickle.encode(obj)
        except Exception as err:
            raise RuntimeError(err) from err

    def decode(self, key: str) -> Any:
        """decode.

            Decoding a Session Key using jsonpickle.
        Args:
            key (str): key name.

        Raises:
            RuntimeError: Error converting data from json.

        Returns:
            Any: object converted.
        """
        try:
            value = self._data[key]
            return jsonpickle.decode(value)
        except KeyError:
            # key is missing
            return None
        except Exception as err:
            raise RuntimeError(err) from err

    async def save_encoded_data(self, request: web.Request, key: str, obj: Any) -> None:
        storage = request[SESSION_STORAGE]
        try:
            data = jsonpickle.encode(obj)
        except RuntimeError:
            return False
        self._data[key] = data
        self._changed = False
        await storage.save_session(request, None, self)
