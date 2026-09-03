"""Runtime configuration, read from the environment.

Nothing here carries a default that would work in production. A missing
variable is a startup failure, not a silent fallback to something insecure.
"""

import os


class ConfigError(RuntimeError):
    """Raised when required configuration is absent."""


def require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"{name} is not set")
    return value


def database_url() -> str:
    return require("DATABASE_URL")


def pool_size() -> int:
    return int(os.environ.get("DB_POOL_SIZE", "8"))
