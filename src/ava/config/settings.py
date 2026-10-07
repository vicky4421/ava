from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from ava.config.paths import ROOT_DIR

ENV_PATH = ROOT_DIR / ".env"

# Load variables into os.environ so LangSmith tracer picks them up automatically
load_dotenv(ENV_PATH)


class Settings(BaseSettings):
    llm_model: str = "gemini-3.1-flash-lite"
    gemini_api_key: str = Field(default="")
    tavily_api_key: str = Field(default="")
    huggingface_embedding_model_directory: str = Field(default="")
    huggingface_embedding_model_name: str = "google/embeddinggemma-300m"
    chroma_persist_directory: str = "./data/chroma"
    hf_token: str = Field(default="")
    langchain_tracing_v2: str = Field(default="false")
    langchain_api_key: str = Field(default="")
    langchain_project: str = Field(default="ava-scanner")

    model_config = SettingsConfigDict(
        env_file=ENV_PATH, env_file_encoding="utf-8", extra="ignore"
    )


settings = Settings()
