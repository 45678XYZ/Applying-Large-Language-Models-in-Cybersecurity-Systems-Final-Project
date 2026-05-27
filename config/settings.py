"""Application-wide configuration loaded from environment / .env."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Centralized config — Azure OpenAI, paths, scan thresholds."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    azure_openai_api_key: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_version: str = "2024-08-01-preview"
    azure_openai_chat_deployment: str = ""
    azure_openai_embedding_deployment: str = "text-embedding-3-small"

    nvd_api_key: str = ""

    vector_db_path: Path = Path("./data/vector_db")
    knowledge_base_path: Path = Path("./data/knowledge_base")

    log_level: str = "INFO"

    nmap_top_ports: int = 100
    nmap_timeout_sec: int = 300
    rag_top_k: int = Field(default=5, ge=1, le=20)


settings = Settings()
