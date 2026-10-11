# Author: Vivek Sawant
# Date: 11-10-2026

from functools import lru_cache

from anyio import Path
from langchain_core.documents import Document
from sentence_transformers import CrossEncoder

from ava.config.logger import get_logger
from ava.rag.config import DEFAULT_RERANKER_MODEL, LOCAL_RERANKER_PATH

logger = get_logger()


@lru_cache(maxsize=1)
def get_reranker(model_path: Path | str = str(LOCAL_RERANKER_PATH)) -> CrossEncoder:
    """Loads and caches the local CrossEncoder reranking model."""

    model_str = str(model_path)

    logger.info(f"Loading local CrossEncoder reranker from: {model_str}")
    return CrossEncoder(model_str, device="cpu", max_length=512, local_files_only=True)


def rerank_documents(
    query: str,
    documents: list[Document],
    top_k: int = 4,
    model_name: str = DEFAULT_RERANKER_MODEL,
) -> list[Document]:
    """Re-scores candidate documents against the query and returns the top_k."""

    if not documents:
        return []

    reranker = get_reranker(model_name)

    # Prepare (query, passage) pairs
    pairs = [[query, doc.page_content] for doc in documents]
    scores = reranker.predict(pairs, show_progress_bar=False)

    # Attach score to document metadata and sort descending
    scored_docs: list[tuple[float, Document]] = []

    for score, doc in zip(scores, documents):
        # Extract scalar safely regardless of 1D vs 2D numpy array shape
        score_val = float(score.item() if hasattr(score, "item") else score)

        # Create a shallow copy of document with rerank score embedded
        scored_doc = Document(
            page_content=doc.page_content,
            metadata={**doc.metadata, "rerank_score": round(score_val, 4)},
        )
        scored_docs.append((score_val, scored_doc))

    scored_docs.sort(key=lambda x: x[0], reverse=True)

    return [doc for _, doc in scored_docs[:top_k]]
