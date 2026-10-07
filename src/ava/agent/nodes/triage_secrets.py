from typing import Any, cast

from langchain_core.messages import HumanMessage, SystemMessage

from ava.agent.schemas.secret_finding import SecretAnalysisResponseSchema
from ava.agent.state import AgentState
from ava.config.logger import get_logger
from ava.resources.models import get_llm

logger = get_logger()


TRIAGE_SYSTEM_PROMPT = """
You are an expert mobile application security engineer analyzing hardcoded candidate secrets from a decompiled Android APK.

Evaluate each candidate string within its surrounding context:
1. Determine whether it is a legitimate high-risk secret, a public client-side identifier (e.g. non-restricted Google Maps key), or a dummy/test token.
2. Assign appropriate severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and confidence.
3. Provide a concise, professional risk summary.

Apply the following deterministic severity classification criteria:
- CRITICAL: Root/Admin credentials, unrestricted database passwords, private encryption master keys, service account private keys.
- HIGH: High-privilege backend API tokens (AWS secret keys, Stripe live secret keys, GitHub personal access tokens, Slack bot tokens).
- MEDIUM: Unrestricted cloud client tokens, storage bucket write tokens, or services with financial billing impact if abused.
- LOW: Standard client-side public tokens (Google Maps API keys, Firebase project IDs/keys intended for client SDKs) where client exposure is expected architecture.
- INFO: Static placeholders, mock values, format headers (e.g. PEM headers), dummy test strings, or false positives (Valid: No).
"""


async def triage_secret_node(state: AgentState) -> dict[str, Any]:
    """Triage secrets found in decompiled apk and assign severity."""
    candidates = state.get("secret_candidates", [])

    if not candidates:
        logger.info("No candidates to triage.")
        return {"verified_secrets": []}

    logger.info(f"Triaging {len(candidates)} candidate secret(s) with LLM...")

    llm = get_llm()

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

    # Map candidates to their detected occurrences and entropy
    candidate_meta = {
        c["candidate"]: {
            "locations": [
                f"{loc['file']}:{loc['line']}" for loc in c.get("occurrences", [])
            ],
            "entropy": c.get("entropy", 0.0),
        }
        for c in candidates
    }

    # Attach locations and entropy directly to the verified dicts
    verified_list = []
    for f in response.findings:
        finding_dict = f.model_dump()
        token = finding_dict.get("candidate", "")

        # Fetch metadata dict for this token
        meta = candidate_meta.get(token, {})

        # Extract locations list and entropy float
        finding_dict["locations"] = meta.get("locations", [])
        finding_dict["entropy"] = meta.get("entropy", 0.0)
        verified_list.append(finding_dict)

    return {"verified_secrets": verified_list}
