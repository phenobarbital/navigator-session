"""Tests for vault target discovery (FEAT-099, TASK-072)."""
import importlib
import logging
from pathlib import Path

import pytest

import navigator_session.vault.registry as registry
from navigator_session.vault.registry import (
    ENTRY_POINT_GROUP,
    ProtectedTarget,
    TargetRow,
    VaultRow,
    discover_targets,
)
from navigator_session.vault.targets.user_vault import UserVaultTarget, factory

from .fake_pg import FakeDatabase, FakePool

ROOT = Path(__file__).resolve().parents[2]


class FakeEntryPoint:
    def __init__(self, name, loader):
        self.name = name
        self._loader = loader

    def load(self):
        return self._loader()


def _named_target(name):
    target = UserVaultTarget(FakePool(FakeDatabase()))
    target.name = name  # instance override for duplicate-name tests
    return target


@pytest.fixture
def patch_entry_points(monkeypatch):
    def apply(eps):
        def fake_entry_points(*, group):
            assert group == ENTRY_POINT_GROUP
            return eps
        monkeypatch.setattr(registry, "entry_points", fake_entry_points)
    return apply


class TestDiscovery:
    def test_loads_targets_in_name_order_with_resources(self, patch_entry_points):
        seen_resources = {}

        def make(name):
            def f(resources):
                seen_resources[name] = resources
                return _named_target(name)
            return lambda: f

        patch_entry_points([FakeEntryPoint("zeta", make("zeta")), FakeEntryPoint("alpha", make("alpha"))])
        targets = discover_targets(db_pool="pool", redis=None)
        assert [t.name for t in targets] == ["alpha", "zeta"]
        assert seen_resources["alpha"] == {"db_pool": "pool", "redis": None}

    def test_skips_unconfigured_broken_and_invalid(self, patch_entry_points, caplog):
        def broken_factory(resources):
            raise RuntimeError("boom")

        def load_error():
            raise ImportError("missing module")

        patch_entry_points([
            FakeEntryPoint("good", lambda: lambda r: _named_target("good")),
            FakeEntryPoint("none", lambda: lambda r: None),
            FakeEntryPoint("broken", lambda: broken_factory),
            FakeEntryPoint("unloadable", load_error),
            FakeEntryPoint("invalid", lambda: lambda r: object()),
        ])
        with caplog.at_level(logging.WARNING, logger="navigator.vault"):
            targets = discover_targets()
        assert [t.name for t in targets] == ["good"]
        assert "'broken' failed to load: RuntimeError" in caplog.text
        assert "'unloadable' failed to load: ImportError" in caplog.text
        assert "'invalid' returned object" in caplog.text

    def test_duplicate_names_rejected(self, patch_entry_points):
        patch_entry_points([
            FakeEntryPoint("a", lambda: lambda r: _named_target("same")),
            FakeEntryPoint("b", lambda: lambda r: _named_target("same")),
        ])
        with pytest.raises(ValueError, match="Duplicate vault target name 'same'"):
            discover_targets()


class TestDeclaration:
    def test_pyproject_registers_user_vault(self):
        tomllib = pytest.importorskip("tomllib")  # Python >= 3.11
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        spec = data["project"]["entry-points"][ENTRY_POINT_GROUP]["user_vault"]
        module_name, attr = spec.split(":")
        assert getattr(importlib.import_module(module_name), attr) is factory

    def test_factory_requires_db_pool(self):
        assert factory({}) is None
        assert isinstance(factory({"db_pool": FakePool(FakeDatabase())}), UserVaultTarget)

    def test_protocol_conformance(self):
        target = UserVaultTarget(FakePool(FakeDatabase()))
        assert isinstance(target, ProtectedTarget)
        row = VaultRow(ref="r", pk=1, identity={}, values={})
        assert isinstance(row, TargetRow)
