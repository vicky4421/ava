from anyio import Path
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

from config.logger import get_logger
from resources.models import load_hf_embedding_model

logger = get_logger()

DATA_DIR = Path.home() / ".ava" / "vector_store"


def get_chroma_vector_store(
    *,
    collection_name: str = "chroma_db",
    embedding_func: HuggingFaceEmbeddings,
    persist_directory: str = str(DATA_DIR),
) -> Chroma:
    """Initializes or connects to a local Chroma vector store instance."""

    Path(persist_directory).mkdir(parents=True, exist_ok=True)
    embedding_func = load_hf_embedding_model

    try:
        vs = Chroma(
            collection_name=collection_name,
            embedding_function=embedding_func,
            persist_directory=persist_directory,
        )
        logger.info(f"Vector store '{collection_name}' initialized successfully.")
        return vs
    except Exception as e:
        logger.critical(f"Unexpected error initializing llm: {e}")
        raise
