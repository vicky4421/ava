from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ava.config.paths import ROOT_DIR

ENV_PATH = ROOT_DIR / ".env"


class Settings(BaseSettings):
    llm_model: str = "gemini-3.1-flash-lite"
    gemini_api_key: str = Field(default="")
    tavily_api_key: str = Field(default="")
    huggingface_embedding_model_directory: str = Field(default="")
    huggingface_embedding_model_name: str = "google/embeddinggemma-300m"
    chroma_persist_directory: str = "./data/chroma"
    hf_token: str = Field(default="")

    model_config = SettingsConfigDict(
        env_file=ENV_PATH, env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
