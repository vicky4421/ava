# Author: Vivek Sawant
# Date: 10-10-2026

import os
from pathlib import Path
from typing import Any

import frontmatter
import yaml
from langchain_core.documents import Document

from ava.config.logger import get_logger

logger = get_logger()

# Default fallback if not passed directly or set in .env
DEFAULT_MASTG_PATH = Path(os.getenv("MASTG_PATH", Path.home() / "mastg_docs" / "mastg"))


def is_android_document(metadata: dict[str, Any], file_path: Path) -> bool:
    """Check if the document related to Android."""

    # check directory path
    path_parts = [p.lower() for p in file_path.parts]
    if "ios" in path_parts:
        return False
    if "android" in path_parts:
        return True

    # Fallback to frontmatter platform key
    platform = metadata.get("platform")
    if isinstance(platform, str):
        return "android" in platform.lower()
    if isinstance(platform, list):
        return any("android" in str(p).lower() for p in platform)

    return False


def load_mastg_markdown_docs(repo_path: Path) -> list[Document]:
    """Load best-practices, tests, and techniques into LangChain Document objects."""

    documents: list[Document] = []
    target_dirs = ["best-practices", "tests", "techniques"]

    for dir_name in target_dirs:
        base_dir = repo_path / dir_name

        if not base_dir.exists():
            continue

        for md_file in base_dir.rglob(pattern="*.md"):
            try:
                post = frontmatter.load(md_file)
            except Exception:  # noqa: BLE001
                logger.error(f"Failed to load markdown: {md_file}")
                continue

            metadata = post.metadata
            content = post.content.strip()

            # skip files without content
            if not content:
                continue

            # skip deprecated files
            status = str(metadata.get("status", "")).strip().lower()
            if status == "deprecated":
                continue

            # filter for android platform
            if not is_android_document(metadata, md_file):
                continue

            # resolve document id
            # Priority: Frontmatter 'id' -> Filename stem (e.g. MASTG-TEST-0017)
            doc_id = str(metadata.get("id") or md_file.stem)

            # resolve title
            title = str(metadata.get("title") or doc_id)

            # Normalize MASVS Category / IDs
            masvs_ids = metadata.get("masvs_v2_id") or metadata.get("masvs_v1_id") or []
            if isinstance(masvs_ids, list):
                masvs_id_str = ", ".join(str(m) for m in masvs_ids)
            else:
                masvs_id_str = str(masvs_ids)

            doc_metadata = {
                "doc_id": doc_id,
                "title": title,
                "category": dir_name,
                "platform": "android",
                "masvs_id": masvs_id_str,
                "source_path": str(md_file.relative_to(repo_path)),
            }

            documents.append(
                Document(page_content=f"# {title}\n\n{content}", metadata=doc_metadata)
            )

    return documents


def load_mastg_rule_docs(repo_path: Path) -> list[Document]:
    """Load Semgrep rules into LangChain Document objects."""

    rules_dir = repo_path / "rules"
    if not rules_dir.exists():
        return []

    documents: list[Document] = []

    # check both .yaml and .yml files
    for rule_file in list(rules_dir.rglob(pattern="*.yaml")) + list(
        rules_dir.rglob(pattern="*.yml")
    ):
        # Skip iOS-specific rule files if separated by directory
        if "ios" in [p.lower() for p in rule_file.parts]:
            continue

        try:
            with open(rule_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:  # noqa: BLE001
            logger.error(f"Failed to parse rule file: {rule_file}")
            continue

        if not isinstance(data, dict) or "rules" not in data:
            continue

        for rule in data.get("rules", []):
            rule_id = rule.get("id")
            if not rule_id:
                continue

            # Skip iOS-prefixed rules if named explicitly
            if "ios" in rule_id.lower() and "android" not in rule_id.lower():
                continue

            severity = rule.get("severity", "UNKNOWN")
            languages = ", ".join(rule.get("languages", []))

            # Extract metadata and descriptions
            metadata = rule.get("metadata", {})
            summary = metadata.get("summary", "")
            message = rule.get("message", "").strip()

            # Extract the code pattern for context
            pattern = rule.get("pattern") or rule.get("patterns") or ""
            if not isinstance(pattern, str):
                pattern = yaml.dump(pattern)

            # Construct clean, highly descriptive text for embedding
            content = (
                f"# Semgrep Rule: {rule_id}\n\n"
                f"**Severity**: {severity}\n"
                f"**Target Languages**: {languages}\n"
                f"**Summary**: {summary}\n\n"
                f"## Security Guidance & Remediation\n"
                f"{message}\n\n"
                f"## Detection Pattern\n"
                f"```\n{pattern.strip()}\n```"
            )

            doc_metadata = {
                "doc_id": rule_id,
                "title": summary or rule_id,
                "category": "rules",
                "platform": "android",
                "severity": severity,
                "languages": languages,
                "source_path": str(rule_file.relative_to(repo_path)),
            }

            documents.append(Document(page_content=content, metadata=doc_metadata))

    return documents


if __name__ == "__main__":
    repo_root = Path.home() / "mastg_docs" / "mastg"

    md_docs = load_mastg_markdown_docs(repo_root)

    rule_docs = load_mastg_rule_docs(repo_root)

    all_docs = md_docs + rule_docs
    print(
        f"Total documents prepared for Chroma: {len(all_docs)} "
        f"({len(md_docs)} docs, {len(rule_docs)} rules)"
    )
