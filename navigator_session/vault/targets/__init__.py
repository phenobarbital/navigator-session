"""Built-in vault protected targets (PostgreSQL)."""
from .postgres import PostgresTarget
from .user_vault import UserVaultTarget

__all__ = ["PostgresTarget", "UserVaultTarget"]
