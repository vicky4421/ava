# Author: Vivek Sawant
# Date: 11-10-2026

from ava.rag.retriever import HybridMASTGRetriever

retriever = HybridMASTGRetriever()

# Test 1: Exact code token match (BM25 excels here)
results = retriever.retrieve("MODE_WORLD_READABLE SharedPreferences", top_k=2)
for doc in results:
    print(
        f"[{doc.metadata.get('doc_id')}] Score: {doc.metadata.get('rerank_score'):.4f}"
    )
    print(doc.page_content[:200])
    print("-" * 50)

# Test 2: Conceptual vulnerability match (Dense + Reranker excels here)
results = retriever.retrieve(
    "Insecure cryptographic key storage in keystore hardware", top_k=2
)
for doc in results:
    print(
        f"[{doc.metadata.get('doc_id')}] Score: {doc.metadata.get('rerank_score'):.4f}"
    )
    print(doc.page_content[:200])
    print("-" * 50)
