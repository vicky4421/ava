# Author: Vivek Sawant
# Date: 12-10-2026

import logging
from typing import Any, cast

from langchain_core.prompts import ChatPromptTemplate

from ava.agent.nodes.analyze_manifest import get_exported_entry_points
from ava.agent.schemas.audit import LeadAuditResult, TriageVerdict
from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.rag.retriever import HybridMASTGRetriever
from ava.resources.models import get_llm
from ava.resources.runtime import get_analysis_context
from ava.tools.callgraph import trace_upstream_callers
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


 Evaluate candidate leads discovered during static analysis by performing rigorous taint and reachability analysis.
 Evaluation Criteria:
1. Reachability & Entry Point:
   - Determine if the containing component is exported or accessible to untrusted third-party apps.
   - Inspect whether untrusted inputs (e.g., Intent extras, data URIs, SharedPreferences) flow into the target method.
2. Taint & Data Flow:
   - Identify the source of the parameter passed into the sensitive sink.
   - Check if an explicit sanitizer, domain allowlist, or permission check guards the sink.
   - If the sink is triggered purely by internal constant parameters (e.g., loading an internal hardcoded asset), classify sanitization accordingly.
3. Configuration Deficiencies:
   - For WebViews: Verify if dangerous flags (e.g., setAllowUniversalAccessFromFileURLs, setJavaScriptEnabled) are statically enabled.
   - For BroadcastReceivers / Activities: Check for intent redirection or unvalidated invocation of internal components.
4. False Positive Pruning:
   - Classify as FALSE_POSITIVE if the sink is guarded by rigorous input validation, is dead code, or requires unattainable local privileges.

"""

USER_TEMPLATE = """### Candidate Lead Metadata
- Rule ID: {rule_id}
- Category: {category}
- Class: {class_name}
- Method: {method_name}
- Component Exported: {is_exported}

### Extracted Bytecode Context
```smali
{code_context}```

### Relevant MASTG Security Standards
{mastg_context}

Provide your structured assessment.
"""


def _investigate_single_lead(
    lead: dict[str, Any],
    retriever: HybridMASTGRetriever,
    llm: Any,
    exported_components: set[str],
    dx: Any | None = None,
) -> LeadAuditResult:
    """Audits a single candidate lead using code context and RAG guidance."""

    # 1. Extract bytecode surrounding the sink line
    sink_context = extract_method_context(
        file_path=lead["file_path"],
        target_line=lead["line_number"],
    ) or lead.get("code_snippet", "")

    # 2. Use dx to trace upstream callers
    caller_sections: list[str] = []
    if dx is not None:
        callers = trace_upstream_callers(
            exported_components=exported_components,
            dx=dx,
            target_class_smali=lead.get("class_name", ""),
            target_method=lead.get("method_name", ""),
        )
        for caller in callers:
            tag = (
                "[Framework Lifecycle Entry Point]"
                if caller["is_lifecycle_entry"]
                else "[Internal Caller]"
            )
            caller_sections.append(
                f"### Caller: {caller['class_name']}->{caller['method_name']} {tag}\n"
                f"```smali\n{caller['instructions']}\n```"
            )

    # 3. Combine upstream callers with the target sink
    if caller_sections:
        caller_sections.append(
            f"### Target Sink Method:\n```smali\n{sink_context}\n```"
        )
        combined_code_context = "\n\n".join(caller_sections)
    else:
        combined_code_context = sink_context

    # 4. Query Hybrid RAG for security context
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
            "code_context": combined_code_context,
            "mastg_context": mastg_context,
        }
    )

    result: LeadAuditResult = cast(LeadAuditResult, raw_result)

    return result


def investigate_leads_node(state: AgentState) -> dict[str, Any]:
    """LangGraph Node: Processes in-scope candidate leads and accumulates verified audit findings."""

    candidate_leads = state.get("candidate_leads", [])
    target_apk = state.get("target_apk", "")

    if not candidate_leads:
        logger.info("No candidate leads available in state to investigate.")
        return {"audit_findings": []}

    llm = get_llm()
    retriever = HybridMASTGRetriever()

    # Retrieve cached Androguard Analysis context once for the entire batch
    dx = get_analysis_context(target_apk) if target_apk else None

    exported_components = {comp["name"] for comp in get_exported_entry_points(state)}

    logger.info(f"Starting audit loop across {len(candidate_leads)} candidate leads...")

    verified_findings: list[dict[str, Any]] = []

    for idx, lead in enumerate(candidate_leads, start=1):
        rule = lead.get("rule_id", "UNKNOWN")
        target = f"{lead.get('class_name')}::{lead.get('method_name')}"
        logger.info(
            f"[{idx}/{len(candidate_leads)}] Investigating {target} ({rule})..."
        )

        try:
            result = _investigate_single_lead(
                lead=dict(lead),
                retriever=retriever,
                llm=llm,
                dx=dx,
                exported_components=exported_components,
            )

            # Accumulate actionable findings
            if result.verdict in (TriageVerdict.VULNERABLE, TriageVerdict.SUSPICIOUS):
                logger.info(
                    f"Result: [{result.verdict.value}] {result.rule_id} "
                    f"(Severity: {result.severity.value}, Conf: {result.confidence * 100:.0f}%)"
                )
                verified_findings.append(result.model_dump())
            else:
                logger.debug(f"Lead classified as FALSE_POSITIVE: {result.rule_id}")

        except Exception:
            logger.exception(f"Failed to audit lead {rule} at {target}")

    logger.info(
        f"Investigation complete. Generated {len(verified_findings)} actionable findings."
    )
    return {"audit_findings": verified_findings}
