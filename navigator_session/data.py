import uuid
import time
from typing import Union, Optional, Any
from datetime import datetime, timezone
from collections.abc import Iterator, Mapping, MutableMapping
import jsonpickle
from jsonpickle.unpickler import loadclass
from aiohttp import web
from datamodel import BaseModel
from .conf import (
    SESSION_KEY,
    SESSION_ID,
    SESSION_STORAGE
)
try:
    from pydantic import BaseModel as PydanticBaseModel
except ImportError:
    PydanticBaseModel = None


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
        cls = mdl.__new__(mdl) if hasattr(mdl, '__new__') else object.__new__(mdl)
        cls.__dict__ = self.context.restore(obj['__dict__'], reset=False)
        return cls

jsonpickle.handlers.registry.register(BaseModel, ModelHandler, base=True)

if PydanticBaseModel:
    class PydanticHandler(jsonpickle.handlers.BaseHandler):
        """PydanticHandler.
        This class can handle with serializable Pydantic Models.
        """
        def flatten(self, obj, data):
            data['__dict__'] = self.context.flatten(obj.__dict__, reset=False)
            return data

        def restore(self, obj):
            module_and_type = obj['py/object']
            mdl = loadclass(module_and_type)
            cls = mdl.__new__(mdl) if hasattr(mdl, '__new__') else object.__new__(mdl)
            cls.__dict__ = self.context.restore(obj['__dict__'], reset=False)
            return cls

    jsonpickle.handlers.registry.register(PydanticBaseModel, PydanticHandler, base=True)


class SessionData(MutableMapping[str, Any]):
    """Session dict-like object.

    Supports both serializable data (stored in _data and persisted) and
    in-memory objects (stored in _objects, not persisted).

    Non-serializable objects (class instances, etc.) are automatically
    stored in _objects when assigned via session.key = value or session['key'] = value.
    """

    _data: Union[str, Any] = {}
    _objects: dict[str, Any] = {}

    # Internal attributes that should not be stored in _data or _objects
    _internal_attrs = frozenset({
        '_data', '_objects', '_changed', '_id_', '_identity', '_new',
        '_max_age', '_now', '__created__', '_created', '_dow', '_doy',
        '_time', 'args'
    })

    def __init__(
        self,
        *args,
        data: Optional[Mapping[str, Any]] = None,
        new: bool = False,
        id: Optional[str] = None,
        identity: Optional[Any] = None,
        max_age: Optional[int] = None
    ) -> None:
        # Initialize internal storage first (before any attribute access)
        object.__setattr__(self, '_data', {})
        object.__setattr__(self, '_objects', {})
        # If new, mark as changed so it gets saved
        object.__setattr__(self, '_changed', True if new else False)
        # Unique ID:
        self._id_ = (data.get(SESSION_ID, None) if data else id) or uuid.uuid4().hex
        # Session Identity
        self._identity = (
            data.get(SESSION_KEY, None) if data else identity
        ) or self._id_
        self._new = new if data != {} else True
        self._max_age = max_age or None
        created = data.get('created', None) if data else None
        self._now = datetime.now(timezone.utc)
        self.__created__ = self._now
        now = int(self._now.timestamp())
        self._now = now  # time for this instance creation
        age = now - created if created else now
        if max_age is not None and age > max_age:
            data = None
        self._created = now if self._new or created is None else created
        ## Data updating.
        if data is not None:
            self._data.update(data)
        # Other mark timestamp for this session:
        dt = datetime.now(timezone.utc)
        self._dow = dt.weekday()
        self._doy = dt.timetuple().tm_yday
        self._time = dt.time()
        self.args = args

    def __repr__(self) -> str:
        return (
            f'<NAV-Session [new:{self.new}, created:{self.created}] '
            f'data={self._data!r}, objects={list(self._objects.keys())}>'
        )

    # --- Serialization helpers ---

    def _is_serializable(self, value: Any) -> bool:
        """Check if a value can be reliably serialized and restored with jsonpickle.

        Returns True for primitive types, dicts, lists, and known serializable models.
        Returns False for arbitrary class instances that may not restore properly
        in a different process/context.
        """
        # Primitive types are always serializable
        if value is None or isinstance(value, (bool, int, float, str, bytes)):
            return True

        # Dicts and lists need recursive check
        if isinstance(value, dict):
            return all(self._is_serializable(v) for v in value.values())
        if isinstance(value, (list, tuple, set, frozenset)):
            return all(self._is_serializable(v) for v in value)

        # BaseModel (datamodel) instances are handled by ModelHandler
        if isinstance(value, BaseModel):
            return True

        # Pydantic models are handled by PydanticHandler
        if PydanticBaseModel and isinstance(value, PydanticBaseModel):
            return True

        # datetime types are serializable
        if isinstance(value, (datetime,)):
            return True

        # Any other type (class instances, functions, etc.) is NOT reliably serializable
        # These should be stored in-memory only
        return False

    def _get_value(self, key: str) -> Any:
        """Unified getter that checks both _objects and _data."""
        if key in self._objects:
            return self._objects[key]
        if key in self._data:
            return self._data[key]
        raise KeyError(key)

    def _set_value(self, key: str, value: Any) -> None:
        """Unified setter that routes to _objects or _data based on serializability."""
        if self._is_serializable(value):
            # Remove from _objects if it was there before
            self._objects.pop(key, None)
            self._data[key] = value
            self._changed = True
        else:
            # Store in _objects (in-memory only, not persisted)
            # Remove from _data if it was there before
            self._data.pop(key, None)
            self._objects[key] = value
            # Note: _objects changes don't set _changed since they're not persisted

    def _del_value(self, key: str) -> None:
        """Unified delete that removes from both _objects and _data."""
        deleted = False
        if key in self._objects:
            del self._objects[key]
            deleted = True
        if key in self._data:
            del self._data[key]
            self._changed = True
            deleted = True
        if not deleted:
            raise KeyError(key)

    def _has_value(self, key: str) -> bool:
        """Check if key exists in either _objects or _data."""
        return key in self._objects or key in self._data

    # --- Properties ---

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
        return not bool(self._data) and not bool(self._objects)

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
        """Return only serializable data (for persistence)."""
        return self._data

    def session_objects(self) -> dict:
        """Return in-memory objects (not persisted)."""
        return self._objects

    def invalidate(self) -> None:
        """Clear all session data and in-memory objects."""
        self._changed = True
        self._data = {}
        self._objects = {}

    # --- Magic Methods ---

    def __len__(self) -> int:
        return len(self._data) + len(self._objects)

    def __iter__(self) -> Iterator[str]:
        # Iterate over both _data and _objects keys
        seen = set()
        for key in self._data:
            seen.add(key)
            yield key
        for key in self._objects:
            if key not in seen:
                yield key

    def __contains__(self, key: object) -> bool:
        return self._has_value(str(key))

    def __getitem__(self, key: str) -> Any:
        return self._get_value(key)

    def __setitem__(self, key: str, value: Any) -> None:
        self._set_value(key, value)

    def __delitem__(self, key: str) -> None:
        self._del_value(key)

    def __getattr__(self, key: str) -> Any:
        # Avoid infinite recursion for internal attributes
        if key.startswith('_'):
            raise AttributeError(key)
        try:
            return self._get_value(key)
        except KeyError:
            raise AttributeError(key) from None

    def __setattr__(self, key: str, value: Any) -> None:
        # Handle internal attributes normally
        if key in self._internal_attrs or key.startswith('_'):
            object.__setattr__(self, key, value)
        else:
            self._set_value(key, value)

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
