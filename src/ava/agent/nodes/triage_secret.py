from typing import Any, cast

from langchain_core.messages import HumanMessage, SystemMessage

from ava.agent.schemas.secret_finding import SecretAnalysisResponseSchema
from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.resources.models import get_llm

logger = get_logger()
llm = get_llm()

TRIAGE_SYSTEM_PROMPT = """
You are an expert mobile application security engineer analyzing hardcoded candidate secrets from a decompiled Android APK.

Evaluate each candidate string within its surrounding context:
1. Determine whether it is a legitimate high-risk secret, a public client-side identifier (e.g. non-restricted Google Maps key), or a dummy/test token.
2. Assign appropriate severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and confidence.
3. Provide a concise, professional risk summary.
"""


async def triage_secret_node(state: AgentState) -> dict[str, Any]:
    """Triage secrets found in decompiled apk and assign severity."""
    candidates = state.get("secret_candidates", [])

    if not candidates:
        logger.info("No candidates to triage.")
        return {"verified_secrets": []}

    logger.info(f"Triaging {len(candidates)} candidate secret(s) with LLM...")

    # Format candidates and their 7-line context snippets
    formatted_payload = []

    for idx, c in enumerate(candidates, start=1):
        locations = ", ".join(
            f"{loc['file']}:{loc['line']}" for loc in c["occurrences"]
        )
        item = (
            f"Candidate #{idx}:\n"
            f"  Value: {c['candidate']}\n"
            f"  Detected Rule: {c['type']}\n"
            f"  Entropy: {c['entropy']}\n"
            f"  Locations: {locations}\n"
            f"  Context Snippet:\n{c.get('context_snippet', 'N/A')}\n"
        )
        formatted_payload.append(item)

    user_prompt = "Analyze the following candidate secrets:\n\n" + "\n---\n".join(
        formatted_payload
    )

    # Initialize model with structured outputs
    structured_llm = llm.with_structured_output(schema=SecretAnalysisResponseSchema)

    response = cast(
        SecretAnalysisResponseSchema,
        await structured_llm.ainvoke(
            [
                SystemMessage(content=TRIAGE_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]
        ),
    )

    # Map candidates to their detected occurrences
    candidate_locations = {
        c["candidate"]: [
            f"{loc['file']}:{loc['line']}" for loc in c.get("occurrences", [])
        ]
        for c in candidates
    }

    # Attach locations directly to the verified dicts
    verified_list = []
    for f in response.findings:
        finding_dict = f.model_dump()
        finding_dict["locations"] = candidate_locations.get(
            finding_dict["candidate"], []
        )
        verified_list.append(finding_dict)

    return {"verified_secrets": verified_list}
