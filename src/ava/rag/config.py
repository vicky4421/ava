# Author: Vivek Sawant
# Date: 11-10-2026

from pathlib import Path

# Base RAG root directory
RAG_DATA_DIR = Path.home() / ".ava" / "rag"

# Concrete storage targets
CHROMA_PERSIST_DIR = RAG_DATA_DIR / "chroma"
BM25_PERSIST_FILE = RAG_DATA_DIR / "bm25_index.pkl"

COLLECTION_NAME = "mastg_knowledge"

# Default models
LOCAL_RERANKER_PATH = Path("/mnt/hgfs/huggingface/bge-reranker-base")
DEFAULT_RERANKER_MODEL = str(LOCAL_RERANKER_PATH)

# Retrieval Hyperparameters
DEFAULT_DENSE_K = 15
DEFAULT_BM25_K = 15
RRF_K = 60  # Standard Reciprocal Rank Fusion constant
FINAL_TOP_K = 4
