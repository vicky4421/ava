from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    gemini_api_key: str
    tavily_api_key: str
    hf_embedding_model_name: str = "google/embeddinggemma-300m"
    chroma_persist_directory: str = "./data/chroma"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


settings = Settings()
