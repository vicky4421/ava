# Author: Vivek Sawant
# Date: 12-10-2026

import logging
from typing import Any, cast

from langchain_core.prompts import ChatPromptTemplate

from ava.agent.schemas.audit import LeadAuditResult, TriageVerdict
from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.rag.retriever import HybridMASTGRetriever
from ava.resources.models import get_llm
from ava.tools.code_extractor import extract_method_context

# silent gemini warnings
logging.getLogger(name="google_genai.models").setLevel(level=logging.ERROR)

logger = get_logger()

# SYSTEM_PROMPT = """You are an expert Android Security Auditor.
# Your task is to analyze a candidate vulnerability lead identified by static analysis.

# Evaluate the provided Smali bytecode against the supplied MASTG (OWASP) security guidance and component exposure metadata.
# Determine whether the implementation represents a true vulnerability, an insecure configuration, or a false positive.

# Rules:
# 1. Examine if dangerous settings (e.g., JavaScript execution, universal file access, world-readable flags) are enabled with constant values (0x1 / true).
# 2. If this is a sink requiring input, determine whether external parameters reach it without validation.
# 3. Be precise: do not classify standard framework operations or benign defaults as vulnerabilities.

# *If the verdict is VULNERABLE,you must provide exploitation steps in numbered format and each step on new line and MUST construct a working* *adb shell am start* *command, custom URI deep link, or HTML/JS payload targeting the specific component and parameter parsed from the code. Write the appropriate malicious file just for proof without any harm if any.*
# """

SYSTEM_PROMPT = """
You are an expert Android Security Auditor. Your task is to analyze a candidate vulnerability lead identified by static analysis. 

Evaluate the provided Smali/Java bytecode against the supplied MASTG (OWASP) security guidance and component exposure metadata. Determine whether the implementation represents a true vulnerability, an insecure configuration, or a false positive.

 Evaluation Rules: 
 1. Examine if dangerous settings (e.g., JavaScript execution, universal file access, world-readable flags) are enabled with constant values (0x1 / true). 
 2. If this is a sink requiring input, determine whether external parameters reach it without validation. 
 3. Be precise: do not classify standard framework operations or benign defaults as vulnerabilities. 
 4. Extract the exact evidence code snippet showing the vulnerable API call and identify the standard CWE ID (e.g., 'CWE-749')

 Exploitation Requirements (When Verdict is VULNERABLE): If the verdict is VULNERABLE, you MUST generate structured proof-of-concept (POC) artifacts:
 1. Payload file generation (`payload_file`):
    - ONLY populate `payload_file` if a dedicated file artifact is strictly required to execute the attack (e.g., .html for webviews, .xml for XXE, or .json payload files.)
    - Do NOT generate python wrapper scripts (e.g. exploit.py using os.system) if a direct adb command is sufficient. Set `payload_file` to null in those cases.
    - You MUST populate `payload_file.content` with complete, non-empty code.
    - For WebViews: Always include complete HTML markup (`<!DOCTYPE html><html><body><script>...</script></body></html>`) and write stolen data directory to the DOM (`document.body.innerText = data`). Never use `alert()`, as Android WebViews suppress alerts by default.
2. Command Sequence (`poc_commands`):
    - Provide a list of clean, single-line terminal commands to execute sequentially.
    - If `payload_file` is generated include the command to push or execute it (e.g., `adb push exploit.html /sdcard/` or `python exploit.py`)
    - For direct triggers (BroadcastReceivers, Activities, Services), provide the direct `adb shell am start`, `adb shell am broadcast`, or `adb shell am startservice` command.
"""

USER_TEMPLATE = """### Candidate Lead Metadata
- Rule ID: {rule_id}
- Category: {category}
- Class: {class_name}
- Method: {method_name}
- Component Exported: {is_exported}

### Extracted Bytecode Context
```smali
{code_context}

### Relevant MASTG Security Standards
{mastg_context}

Provide your structured assessment.
"""


def _investigate_single_lead(
    lead: dict[str, Any], retriever: HybridMASTGRetriever, llm: Any
) -> LeadAuditResult:
    """Audits a single candidate lead using code context and RAG guidance."""

    # 1. Extract bytecode surrounding the sink line
    code_context = extract_method_context(
        file_path=lead["file_path"],
        target_line=lead["line_number"],
    ) or lead.get("code_snippet", "")

    # 2. Query Hybrid RAG for security context
    rag_query = f"{lead['category']} {lead['description']}"
    rag_docs = retriever.retrieve(rag_query, top_k=2)
    mastg_context = (
        "\n---\n".join([doc.page_content for doc in rag_docs])
        if rag_docs
        else "No specific standard retrieved."
    )

    # 3. Format prompt and invoke structured LLM
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("user", USER_TEMPLATE),
        ]
    )

    structured_llm = llm.with_structured_output(LeadAuditResult)
    chain = prompt | structured_llm

    raw_result = chain.invoke(
        {
            "rule_id": lead.get("rule_id", "UNKNOWN"),
            "category": lead.get("category", "General"),
            "class_name": lead.get("class_name", ""),
            "method_name": lead.get("method_name", ""),
            "is_exported": lead.get("is_exported", False),
            "code_context": code_context,
            "mastg_context": mastg_context,
        }
    )

    result: LeadAuditResult = cast(LeadAuditResult, raw_result)

    return result


def investigate_leads_node(state: AgentState) -> dict[str, Any]:
    """LangGraph Node: Processes in-scope candidate leads and accumulates verified audit findings."""

    candidate_leads = state.get("candidate_leads", [])

    llm = get_llm()

    if not candidate_leads:
        logger.info("No candidate leads available in state to investigate.")
        return {"audit_findings": []}

    logger.info(f"Starting audit loop across {len(candidate_leads)} candidate leads...")

    retriever = HybridMASTGRetriever()

    verified_findings: list[LeadAuditResult] = []

    for idx, lead in enumerate(candidate_leads, start=1):
        rule = lead.get("rule_id", "UNKNOWN")
        target = f"{lead.get('class_name')}::{lead.get('method_name')}"
        logger.info(
            f"[{idx}/{len(candidate_leads)}] Investigating {target} ({rule})..."
        )

        try:
            result = _investigate_single_lead(
                lead=dict(lead), retriever=retriever, llm=llm
            )

            # Accumulate actionable findings
            if result.verdict in (TriageVerdict.VULNERABLE, TriageVerdict.SUSPICIOUS):
                logger.info(
                    f"Result: [{result.verdict.value}] {result.rule_id} "
                    f"(Severity: {result.severity.value}, Conf: {result.confidence * 100:.0f}%)"
                )
                verified_findings.append(result)
            else:
                logger.debug(f"Lead classified as FALSE_POSITIVE: {result.rule_id}")

        except Exception:
            logger.exception(f"Failed to audit lead {rule} at {target}")

    logger.info(
        f"Investigation complete. Generated {len(verified_findings)} actionable findings."
    )
    return {"audit_findings": verified_findings}
