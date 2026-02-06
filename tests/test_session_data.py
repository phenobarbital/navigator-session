"""
Comprehensive tests for SessionData class.

Tests cover:
- Basic serializable data storage (_data)
- In-memory object storage (_objects)
- Automatic routing based on serializability
- Magic methods (__getitem__, __setitem__, __getattr__, __setattr__, etc.)
- Encode/decode functionality
- Session properties and lifecycle
"""
import pytest
from datetime import datetime, timezone
from datamodel import BaseModel

from navigator_session.data import SessionData


# --- Test Fixtures ---

class DummyManager:
    """Non-serializable class for testing in-memory storage."""
    def __init__(self, name: str = "default"):
        self.name = name
        self.data = {}

    def add(self, key: str, value):
        self.data[key] = value


class UserModel(BaseModel):
    """Serializable datamodel for testing."""
    username: str
    email: str
    age: int = 0


@pytest.fixture
def session():
    """Create a fresh SessionData instance."""
    return SessionData()


@pytest.fixture
def session_with_data():
    """Create a SessionData instance with initial data."""
    return SessionData(data={
        'name': 'test_session',
        'count': 42,
        'active': True
    })


# --- Test Session Initialization ---

class TestSessionInitialization:
    """Tests for SessionData initialization."""

    def test_empty_session_creation(self, session):
        """Test creating an empty session."""
        assert session.empty is True
        # new is False when created without explicit new=True and no data
        assert len(session) == 0

    def test_session_with_initial_data(self, session_with_data):
        """Test creating a session with initial data."""
        assert session_with_data.empty is False
        assert session_with_data['name'] == 'test_session'
        assert session_with_data['count'] == 42
        assert session_with_data['active'] is True

    def test_session_id_is_generated(self, session):
        """Test that session_id is automatically generated."""
        assert session.session_id is not None
        assert len(session.session_id) > 0

    def test_session_with_custom_id(self):
        """Test creating a session with a custom ID."""
        custom_id = "my-custom-session-id"
        session = SessionData(id=custom_id)
        assert session.session_id == custom_id

    def test_session_identity(self):
        """Test session identity assignment."""
        identity = "user123"
        session = SessionData(identity=identity)
        assert session.identity == identity

    def test_session_created_timestamp(self, session):
        """Test that created timestamp is set."""
        assert session.created is not None
        assert isinstance(session.created, int)

    def test_session_logon_time(self, session):
        """Test that logon_time is a datetime."""
        assert isinstance(session.logon_time, datetime)


# --- Test Serializable Data Storage (_data) ---

class TestSerializableDataStorage:
    """Tests for serializable data stored in _data."""

    def test_store_string(self, session):
        """Test storing string values."""
        session['name'] = 'test'
        assert session['name'] == 'test'
        assert 'name' in session._data
        assert 'name' not in session._objects

    def test_store_integer(self, session):
        """Test storing integer values."""
        session['count'] = 100
        assert session['count'] == 100
        assert 'count' in session._data

    def test_store_float(self, session):
        """Test storing float values."""
        session['price'] = 19.99
        assert session['price'] == 19.99
        assert 'price' in session._data

    def test_store_boolean(self, session):
        """Test storing boolean values."""
        session['active'] = True
        assert session['active'] is True
        assert 'active' in session._data

    def test_store_none(self, session):
        """Test storing None values."""
        session['empty'] = None
        assert session['empty'] is None
        assert 'empty' in session._data

    def test_store_list(self, session):
        """Test storing list values."""
        session['items'] = [1, 2, 3, 'four']
        assert session['items'] == [1, 2, 3, 'four']
        assert 'items' in session._data

    def test_store_dict(self, session):
        """Test storing dict values."""
        session['config'] = {'key': 'value', 'nested': {'a': 1}}
        assert session['config'] == {'key': 'value', 'nested': {'a': 1}}
        assert 'config' in session._data

    def test_store_datetime(self, session):
        """Test storing datetime values."""
        now = datetime.now(timezone.utc)
        session['timestamp'] = now
        assert session['timestamp'] == now
        assert 'timestamp' in session._data

    def test_store_datamodel(self, session):
        """Test storing datamodel BaseModel instances (serializable)."""
        user = UserModel(username='john', email='john@example.com', age=30)
        session['user'] = user
        assert session['user'] == user
        assert 'user' in session._data
        assert 'user' not in session._objects


# --- Test In-Memory Object Storage (_objects) ---

class TestInMemoryObjectStorage:
    """Tests for non-serializable objects stored in _objects."""

    def test_store_class_instance(self, session):
        """Test storing arbitrary class instances in _objects."""
        manager = DummyManager(name='test_manager')
        session['manager'] = manager
        assert session['manager'] is manager
        assert 'manager' in session._objects
        assert 'manager' not in session._data

    def test_retrieve_same_instance(self, session):
        """Test that retrieved object is the exact same instance."""
        manager = DummyManager()
        manager.add('key1', 'value1')
        session['dm'] = manager

        retrieved = session['dm']
        assert retrieved is manager
        assert retrieved.data == {'key1': 'value1'}

    def test_modify_retrieved_object(self, session):
        """Test that modifications to retrieved object persist."""
        manager = DummyManager()
        session['dm'] = manager

        # Modify via retrieved reference
        session['dm'].add('test', 123)

        # Verify modification persists
        assert session['dm'].data == {'test': 123}

    def test_in_memory_not_in_session_data(self, session):
        """Test that in-memory objects don't appear in session_data()."""
        session['name'] = 'test'  # Serializable
        session['manager'] = DummyManager()  # In-memory

        data = session.session_data()
        assert 'name' in data
        assert 'manager' not in data

    def test_in_memory_in_session_objects(self, session):
        """Test that in-memory objects appear in session_objects()."""
        session['manager'] = DummyManager()

        objects = session.session_objects()
        assert 'manager' in objects


# --- Test Attribute-Style Access ---

class TestAttributeStyleAccess:
    """Tests for attribute-style access (session.key)."""

    def test_set_serializable_via_attribute(self, session):
        """Test setting serializable values via attribute."""
        session.username = 'alice'
        assert session.username == 'alice'
        assert 'username' in session._data

    def test_set_object_via_attribute(self, session):
        """Test setting objects via attribute."""
        manager = DummyManager()
        session.dm = manager
        assert session.dm is manager
        assert 'dm' in session._objects

    def test_get_via_attribute(self, session):
        """Test getting values via attribute."""
        session['name'] = 'test'
        assert session.name == 'test'

    def test_attribute_error_for_missing(self, session):
        """Test AttributeError for missing keys."""
        with pytest.raises(AttributeError):
            _ = session.nonexistent

    def test_internal_attributes_work(self, session):
        """Test that internal attributes are not routed to storage."""
        # These are internal and should work normally
        assert hasattr(session, '_data')
        assert hasattr(session, '_objects')
        assert hasattr(session, '_changed')


# --- Test Magic Methods ---

class TestMagicMethods:
    """Tests for dict-like magic methods."""

    def test_getitem(self, session):
        """Test __getitem__ for both storage types."""
        session['serializable'] = 'value'
        session['object'] = DummyManager()

        assert session['serializable'] == 'value'
        assert isinstance(session['object'], DummyManager)

    def test_getitem_keyerror(self, session):
        """Test __getitem__ raises KeyError for missing keys."""
        with pytest.raises(KeyError):
            _ = session['nonexistent']

    def test_setitem(self, session):
        """Test __setitem__ routes correctly."""
        session['str'] = 'hello'
        session['obj'] = DummyManager()

        assert 'str' in session._data
        assert 'obj' in session._objects

    def test_delitem_from_data(self, session):
        """Test __delitem__ for serializable data."""
        session['name'] = 'test'
        del session['name']
        assert 'name' not in session

    def test_delitem_from_objects(self, session):
        """Test __delitem__ for in-memory objects."""
        session['dm'] = DummyManager()
        del session['dm']
        assert 'dm' not in session

    def test_delitem_keyerror(self, session):
        """Test __delitem__ raises KeyError for missing keys."""
        with pytest.raises(KeyError):
            del session['nonexistent']

    def test_contains(self, session):
        """Test __contains__ checks both storages."""
        session['data'] = 'value'
        session['obj'] = DummyManager()

        assert 'data' in session
        assert 'obj' in session
        assert 'missing' not in session

    def test_len_includes_both(self, session):
        """Test __len__ counts both storages."""
        session['a'] = 1
        session['b'] = 2
        session['c'] = DummyManager()

        assert len(session) == 3

    def test_iter_includes_both(self, session):
        """Test __iter__ yields keys from both storages."""
        session['a'] = 1
        session['b'] = DummyManager()
        session['c'] = 'three'

        keys = list(session)
        assert set(keys) == {'a', 'b', 'c'}

    def test_get_method(self, session):
        """Test dict.get() method with default."""
        session['exists'] = 'value'

        assert session.get('exists') == 'value'
        assert session.get('missing') is None
        assert session.get('missing', 'default') == 'default'

    def test_keys_method(self, session):
        """Test keys() includes both storages."""
        session['a'] = 1
        session['b'] = DummyManager()

        keys = list(session.keys())
        assert set(keys) == {'a', 'b'}

    def test_values_method(self, session):
        """Test values() includes both storages."""
        session['a'] = 1
        manager = DummyManager()
        session['b'] = manager

        values = list(session.values())
        assert 1 in values
        assert manager in values

    def test_items_method(self, session):
        """Test items() includes both storages."""
        manager = DummyManager()
        session['a'] = 1
        session['b'] = manager

        items = dict(session.items())
        assert items == {'a': 1, 'b': manager}


# --- Test Session State ---

class TestSessionState:
    """Tests for session state management."""

    def test_changed_flag_on_serializable_set(self, session):
        """Test that _changed is set when adding serializable data."""
        assert session.is_changed is False
        session['name'] = 'test'
        assert session.is_changed is True

    def test_changed_flag_not_set_on_object(self, session):
        """Test that _changed is NOT set for in-memory objects."""
        assert session.is_changed is False
        session['dm'] = DummyManager()
        assert session.is_changed is False

    def test_changed_flag_on_delete(self, session):
        """Test that _changed is set when deleting from _data."""
        session['name'] = 'test'
        session.is_changed = False

        del session['name']
        assert session.is_changed is True

    def test_invalidate_clears_both(self, session):
        """Test invalidate() clears both _data and _objects."""
        session['name'] = 'test'
        session['dm'] = DummyManager()

        session.invalidate()

        assert session.empty is True
        assert len(session._data) == 0
        assert len(session._objects) == 0
        assert session.is_changed is True

    def test_empty_property(self, session):
        """Test empty property considers both storages."""
        assert session.empty is True

        session['dm'] = DummyManager()
        assert session.empty is False

        del session['dm']
        assert session.empty is True


# --- Test Encode/Decode ---

class TestEncodeDecode:
    """Tests for encode/decode functionality."""

    def test_encode_simple_object(self, session):
        """Test encoding a simple object."""
        data = {'name': 'test', 'count': 42}
        encoded = session.encode(data)

        assert isinstance(encoded, str)
        assert 'name' in encoded
        assert 'test' in encoded

    def test_encode_datamodel(self, session):
        """Test encoding a datamodel object."""
        user = UserModel(username='alice', email='alice@example.com')
        encoded = session.encode(user)

        assert isinstance(encoded, str)
        assert 'alice' in encoded

    def test_decode_from_data(self, session):
        """Test decoding a stored encoded value."""
        user = UserModel(username='bob', email='bob@example.com', age=25)
        session._data['user'] = session.encode(user)

        decoded = session.decode('user')

        assert isinstance(decoded, UserModel)
        assert decoded.username == 'bob'
        assert decoded.email == 'bob@example.com'
        assert decoded.age == 25

    def test_decode_missing_key(self, session):
        """Test decode returns None for missing keys."""
        result = session.decode('nonexistent')
        assert result is None

    def test_encode_decode_roundtrip(self, session):
        """Test encode/decode roundtrip."""
        original = {'items': [1, 2, 3], 'nested': {'a': 'b'}}
        encoded = session.encode(original)
        session._data['test'] = encoded
        decoded = session.decode('test')

        assert decoded == original


# --- Test Value Routing ---

class TestValueRouting:
    """Tests for automatic routing between _data and _objects."""

    def test_reassign_serializable_to_object(self, session):
        """Test reassigning from serializable to object moves storage."""
        session['key'] = 'serializable'
        assert 'key' in session._data
        assert 'key' not in session._objects

        session['key'] = DummyManager()
        assert 'key' not in session._data
        assert 'key' in session._objects

    def test_reassign_object_to_serializable(self, session):
        """Test reassigning from object to serializable moves storage."""
        session['key'] = DummyManager()
        assert 'key' in session._objects
        assert 'key' not in session._data

        session['key'] = 'serializable'
        assert 'key' in session._data
        assert 'key' not in session._objects

    def test_nested_dict_with_primitives_is_serializable(self, session):
        """Test nested dict with only primitives goes to _data."""
        session['config'] = {
            'level1': {
                'level2': {
                    'value': 123
                }
            }
        }
        assert 'config' in session._data

    def test_list_of_objects_goes_to_objects(self, session):
        """Test list containing class instances goes to _objects."""
        session['managers'] = [DummyManager(), DummyManager()]
        assert 'managers' in session._objects
        assert 'managers' not in session._data


# --- Test Session Properties ---

class TestSessionProperties:
    """Tests for session property accessors."""

    def test_dow_property(self, session):
        """Test day of week property."""
        assert isinstance(session.dow, int)
        assert 0 <= session.dow <= 6

    def test_session_time_property(self, session):
        """Test session_time property."""
        from datetime import time as time_type
        assert isinstance(session.session_time, time_type)

    def test_max_age_property(self, session):
        """Test max_age getter and setter."""
        assert session.max_age is None

        # max_age must be set via private attribute since it's a property
        session._max_age = 3600
        assert session.max_age == 3600

    def test_session_with_max_age(self):
        """Test session created with max_age."""
        session = SessionData(max_age=3600)
        assert session.max_age == 3600


# --- Test repr ---

class TestRepr:
    """Tests for string representation."""

    def test_repr_empty_session(self, session):
        """Test repr of empty session."""
        repr_str = repr(session)
        assert 'NAV-Session' in repr_str
        assert 'new:' in repr_str  # Could be True or False depending on init

    def test_repr_with_data(self, session):
        """Test repr includes data and objects info."""
        session['name'] = 'test'
        session['dm'] = DummyManager()

        repr_str = repr(session)
        assert 'name' in repr_str
        assert 'dm' in repr_str
