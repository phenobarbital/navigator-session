"""Vault data models exposed to callers (never carry secret values)."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class VaultSecretMetadata(BaseModel):
    """What APIs and UIs may see about a stored secret.

    Attributes:
        key: Secret name.
        updated_at: Last write time (UTC).
        key_version: Master key version the database copy is sealed with.
    """

    model_config = ConfigDict(frozen=True)

    key: str
    updated_at: datetime
    key_version: int = Field(ge=1)
