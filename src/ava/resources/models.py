from functools import lru_cache

from langchain.chat_models import init_chat_model
from langchain_huggingface import HuggingFaceEmbeddings

from ava.config.logger import get_logger
from ava.config.settings import settings

logger = get_logger(log_name="app.log")


# initiate llm
@lru_cache(maxsize=1)
def get_llm(model: str = "google_genai:gemini-3.1-flash-lite", temp: float = 0.0):
    """Provides the shared Gemini LLM instance for synthesis and analysis nodes."""

    try:
        llm = init_chat_model(model=model, temperature=temp)
        logger.info(f"LLM initiated successfully: {model}")
        return llm
    except Exception as e:
        logger.critical(f"Unexpected error initializing llm: {e}")
        raise


# initiate embedding model
@lru_cache(maxsize=1)
def load_hf_embedding_model(
    *,
    model_kwargs: dict | None = None,
    encode_kwargs: dict | None = None,
    model_name: str | None = None,
    cache_folder: str | None = None,
) -> HuggingFaceEmbeddings:
    """Loads the Hugging Face embedding model using the mounted Windows cache."""

    emb_model = settings.huggingface_embedding_model_name or model_name
    cache_dir = settings.huggingface_embedding_model_directory or cache_folder

    try:
        logger.info(f"Loading embedding model: {emb_model}")
        embeddings = HuggingFaceEmbeddings(
            model_name=emb_model,
            model_kwargs={"device": "cpu", "token": settings.hf_token or None},
            encode_kwargs={"normalize_embeddings": True},
            cache_folder=cache_dir,
        )
        return embeddings
    except Exception as e:
        logger.critical(f"Unexpected error initializing embedding model: {e}")
        raise
