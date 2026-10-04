from functools import lru_cache

from langchain.chat_models import init_chat_model
from langchain_huggingface import HuggingFaceEmbeddings

from config.logger import get_logger
from config.settings import settings

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
        embeddings = HuggingFaceEmbeddings(
            model_name=emb_model,
            model_kwargs=model_kwargs,
            encode_kwargs=encode_kwargs,
            cache_folder=cache_dir,
        )
        logger.info(f"Embedding model initiated successfully: {emb_model}")
        return embeddings
    except Exception as e:
        logger.critical(f"Unexpected error initializing embedding model: {e}")
        raise
