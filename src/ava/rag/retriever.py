# Author: Vivek Sawant
# Date: 11-10-2026

import hashlib
from collections import defaultdict

from langchain_core.documents import Document

from ava.config.logger import get_logger
from ava.rag.bm25 import BM25Retriever
from ava.rag.config import DEFAULT_BM25_K, DEFAULT_DENSE_K, FINAL_TOP_K, RRF_K
from ava.rag.reranker import rerank_documents
from ava.rag.store import get_chroma_vector_store

logger = get_logger()


def reciprocal_rank_fusion(
    ranked_lists: list[list[Document]], k: int = RRF_K
) -> list[Document]:
    """Merges multiple lists of documents using standard Reciprocal Rank Fusion (RRF)."""

    rrf_scores: dict[str, float] = defaultdict(float)
    doc_lookup: dict[str, Document] = {}

    for doc_list in ranked_lists:
        for rank, doc in enumerate(doc_list):
            # Unique identifier based on doc content and path to deduplicate
            doc_hash = hashlib.sha256(doc.page_content.encode("utf-8")).hexdigest()
            doc_key = f"{doc.metadata.get('source', '')}_{doc_hash}"
            doc_lookup[doc_key] = doc
            rrf_scores[doc_key] += 1.0 / (k + (rank + 1))

    # Sort documents by accumulated RRF score descending
    sorted_keys = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
    return [doc_lookup[key] for key in sorted_keys]


class HybridMASTGRetriever:
    """Hybrid Retriever for OWASP MASTG v2."""

    def __init__(self):
        self.vector_store = get_chroma_vector_store()
        self.bm25_retriever = BM25Retriever.load()

    def retrieve(
        self,
        query: str,
        top_k: int = FINAL_TOP_K,
        dense_k: int = DEFAULT_DENSE_K,
        bm25_k: int = DEFAULT_BM25_K,
    ) -> list[Document]:
        """Executes Hybrid search (Dense + BM25) -> RRF Fusion -> CrossEncoder Rerank."""

        logger.info(f"Executing hybrid retrieval for: '{query}'")

        # 1. Dense Semantic Retrieval
        dense_docs = self.vector_store.similarity_search(query, k=dense_k)

        # 2. BM25 Lexical Retrieval
        bm25_docs = self.bm25_retriever.search(query=query, top_k=bm25_k)

        # 3. Reciprocal Rank Fusion
        fused_candidates = reciprocal_rank_fusion([dense_docs, bm25_docs])
        if not fused_candidates:
            logger.warning(f"No matching candidates found for query: '{query}'")
            return []

        # 4. Cross-Encoder Reranking
        final_docs = rerank_documents(
            query=query, documents=fused_candidates, top_k=top_k
        )

        return final_docs
