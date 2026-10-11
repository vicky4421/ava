from pathlib import Path

from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)
from rich.console import Console

from ava.config.logger import get_logger
from ava.rag.config import CHROMA_PERSIST_DIR, COLLECTION_NAME
from ava.rag.parser import load_mastg_markdown_docs, load_mastg_rule_docs
from ava.resources.models import load_hf_embedding_model

logger = get_logger()
console = Console()

HEADERS_TO_SPLIT_ON = [
    ("#", "header_1"),
    ("##", "header_2"),
    ("###", "header_3"),
]


def split_mastg_documents(raw_docs: list[Document]) -> list[Document]:
    """Splits markdown and rule documents using a two-stage hybrid approach.

    1. Splits on Markdown headers (#, ##, ###) while preserving parent metadata.
    2. Sub-splits oversize sections with RecursiveCharacterTextSplitter to ensure
       chunks respect the embedding model's context window.
    """

    markdownsplitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=HEADERS_TO_SPLIT_ON, strip_headers=False
    )
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=150)

    final_chunks: list[Document] = []

    for doc in raw_docs:
        # Semantic split along headings
        header_splits = markdownsplitter.split_text(text=doc.page_content)

        # Fallback if the document has no matching markdown headers e.g. rules
        if not header_splits:
            sub_chunks = text_splitter.split_text(doc.page_content)
            for chunk_text in sub_chunks:
                clean_text = chunk_text.strip()
                if clean_text:
                    final_chunks.append(
                        Document(page_content=clean_text, metadata=doc.metadata)
                    )
            continue

        # Sub-chunk only when a section exceeds window boundaries
        for split in header_splits:
            combined_metadata = {**doc.metadata, **split.metadata}
            sub_chunks = text_splitter.split_text(split.page_content)

            for chunk_text in sub_chunks:
                clean_text = chunk_text.strip()
                if not clean_text:
                    continue
                final_chunks.append(
                    Document(page_content=clean_text, metadata=combined_metadata)
                )

    return final_chunks


def get_chroma_vector_store(
    *,
    collection_name: str = COLLECTION_NAME,
    embedding_func: HuggingFaceEmbeddings | None = None,
    persist_directory: Path | str = CHROMA_PERSIST_DIR,
) -> Chroma:
    """Retrieve or initialize persistent Chroma vector store."""

    persist_path = Path(persist_directory)
    persist_path.mkdir(parents=True, exist_ok=True)
    resolved_embedding = embedding_func or load_hf_embedding_model()

    try:
        vs = Chroma(
            collection_name=collection_name,
            embedding_function=resolved_embedding,
            persist_directory=str(persist_path),
        )
        logger.info(f"Vector store '{collection_name}' initialized successfully.")
        return vs
    except Exception as e:
        logger.critical(f"Unexpected error initializing vector store: {e}")
        raise


def ingest_mastg_to_chroma(repo_path: Path, force: bool = False) -> None:
    """Ingests and splits MASTG documents into the persistent Chroma DB."""
    vector_store = get_chroma_vector_store()

    existing_count = vector_store._collection.count()

    if existing_count > 0 and not force:
        console.print(
            f"[yellow]Chroma collection already contains {existing_count} chunks. "
            "Skipping ingestion. (Use --force to overwrite)[/yellow]"
        )
        return

    if existing_count > 0 and force:
        console.print("[yellow]Resetting existing Chroma collection...[/yellow]")
        vector_store.delete_collection()
        vector_store = get_chroma_vector_store()

    console.print(f"[cyan]Parsing MASTG files from:[/cyan] {repo_path}")
    docs = load_mastg_markdown_docs(repo_path=repo_path)
    rules = load_mastg_rule_docs(repo_path=repo_path)

    all_raw_docs = docs + rules
    console.print(
        f"[cyan]Loaded {len(all_raw_docs)} documents. Splitting into chunks...[/cyan]"
    )
    chunks = split_mastg_documents(raw_docs=all_raw_docs)

    console.print(f"[cyan]Indexing {len(chunks)} chunks into Chroma...[/cyan]")
    vector_store.add_documents(documents=chunks)

    final_count = vector_store._collection.count()
    console.print(
        f"[bold green]✔ Ingestion complete! Total chunks in Chroma: {final_count}[/bold green]"
    )
