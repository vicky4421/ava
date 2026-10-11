# Author: Vivek Sawant
# Date: 11-10-2026

import pickle
import re

from langchain_core.documents import Document
from rank_bm25 import BM25Okapi

from ava.config.logger import get_logger
from ava.rag.config import BM25_PERSIST_FILE, RAG_DATA_DIR

logger = get_logger()


def tokenize_code_and_text(text: str) -> list[str]:
    """Tokenize technical text, splitting both whitespace and code identifiers (camelCase/snake_case)."""

    # Lowercase and split on punctuation / whitespace, retaining alphanumerics
    tokens = re.findall(r"[A-Za-z0-9_]+", text.lower())
    return tokens


class BM25Retriever:
    """Manages the BM25 index lifecycle for lexical matching."""

    def __init__(
        self,
        bm25: BM25Okapi | None = None,
        docs: list[Document] | None = None,
    ):
        self.bm25 = bm25
        self.docs = docs or []

    @classmethod
    def from_documents(cls, documents: list[Document]) -> "BM25Retriever":
        """Builds a new BM25 index from chunked documents."""

        logger.info(f"Building BM25 index from {len(documents)} document chunks...")
        corpus_tokens = [
            tokenize_code_and_text(text=doc.page_content) for doc in documents
        ]
        bm25 = BM25Okapi(corpus_tokens)
        return cls(bm25=bm25, docs=documents)

    def save(self) -> None:
        """Persists BM25 model and chunk payload to disk."""
        RAG_DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(BM25_PERSIST_FILE, "wb") as f:
            pickle.dump({"bm25": self.bm25, "docs": self.docs}, f)
        logger.info(f"BM25 index successfully saved to: {BM25_PERSIST_FILE}")

    @classmethod
    def load(cls) -> "BM25Retriever":
        """Loads persistent BM25 index from disk."""

        if not BM25_PERSIST_FILE.exists():
            raise FileNotFoundError(
                f"BM25 index not found at {BM25_PERSIST_FILE}. Run ingestion first."
            )

        with open(BM25_PERSIST_FILE, "rb") as f:
            data = pickle.load(f)

        logger.info("BM25 index loaded successfully.")
        return cls(bm25=data["bm25"], docs=data["docs"])

    def search(self, query: str, top_k: int = 15) -> list[Document]:
        """Performs lexical search and returns top-k documents."""

        if not self.bm25 or not self.docs:
            return []

        tokens = tokenize_code_and_text(text=query)
        if not tokens:
            return []

        scores = self.bm25.get_scores(tokens)

        # Get top-k indices sorted by highest score
        top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[
            :top_k
        ]

        # Filter out 0.0 scores (no matching tokens at all)
        return [self.docs[i] for i in top_indices if scores[i] > 0.0]
