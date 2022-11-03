import uuid
import time
from typing import Union, Optional, Any
from collections.abc import Iterator, Mapping, MutableMapping
import pendulum
import jsonpickle
from jsonpickle.unpickler import loadclass
from asyncdb.models import Model
from navigator_session.conf import SESSION_KEY


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

jsonpickle.handlers.registry.register(Model, ModelHandler)

class SessionData(MutableMapping[str, Any]):
    """Session dict-like object.
    """

    _data: Union[str, Any] = {}

    def __init__(
        self,
        *args,
        data: Optional[Mapping[str, Any]] = None,
        new: bool = False,
        identity: Optional[Any] = None,
        max_age: Optional[int] = None
    ) -> None:
        self._changed = False
        self._data = {}
        self._identity = data.get(SESSION_KEY, None) if data else identity
        if not self._identity:
            self._identity = uuid.uuid4().hex
        self._new = new if data != {} else True
        self._max_age = max_age if max_age else None
        created = data.get('created', None) if data else None
        self._now = pendulum.now('UTC') # time for this instance creation
        now = int(self._now.int_timestamp)
        self._now = now # time for this instance creation
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
        return '<{} [new:{}, created:{}] {!r}>'.format( # pylint: disable=C0209
            'NAV-Session ', self.new, self.created, self._data
        )

    @property
    def new(self) -> bool:
        return self._new

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
