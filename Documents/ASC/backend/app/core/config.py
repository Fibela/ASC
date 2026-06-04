from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    # App
    APP_NAME: str = "ASC PremosCorp"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "changeme-generate-a-strong-key-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://asc_user:asc_pass@localhost:5432/asc_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "https://premoscorp.com"]

    # SOC Thresholds
    ALERT_CRITICAL_THRESHOLD: float = 0.85
    ALERT_HIGH_THRESHOLD: float = 0.65
    ALERT_MEDIUM_THRESHOLD: float = 0.40

    # Analysis
    MAX_FILE_SIZE_MB: int = 50
    SANDBOX_TIMEOUT_SECONDS: int = 120
    IOC_FEEDS_UPDATE_HOURS: int = 6

    # Reports
    REPORT_COMPANY_NAME: str = "PremosCorp"
    REPORT_LOGO_PATH: str = "assets/logo.png"

    # External feeds (optional)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTXALIEN_API_KEY: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
