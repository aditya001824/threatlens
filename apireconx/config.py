from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "APIRECON-X"
    database_path: Path = Field(default=Path("data/apireconx.sqlite3"))
    request_timeout_seconds: float = 8.0
    max_scan_requests: int = 2500
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"])

    model_config = SettingsConfigDict(env_prefix="APIRECONX_", env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    return Settings()
