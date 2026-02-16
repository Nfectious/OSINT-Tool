from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://valkyrie:changeme@osint-db:5432/osint"

    # API Keys
    NUMVERIFY_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""

    # Ollama
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "mistral"

    # PhoneInfoga
    PHONEINFOGA_URL: str = "http://phoneinfoga:8080"

    # Auth
    ADMIN_USERNAME: str = "valkyrie"
    ADMIN_PASSWORD: str = "madison0231"
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    # App
    DEBUG: bool = False
    API_PORT: int = 8400

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
