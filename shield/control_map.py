from __future__ import annotations

from collections.abc import Iterable

CONTROL_MAP: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "OWASP": "LLM01:2025 Prompt Injection",
        "NIST_AI_RMF": "MAP 1.5 / MEASURE 2.7",
        "NIST_CSF": "DE.CM-09 / PR.DS-02",
    },
    "hidden_text": {
        "OWASP": "LLM01:2025 Indirect Prompt Injection (Hidden Content)",
        "NIST_AI_RMF": "MEASURE 2.6 / GOVERN 1.2",
        "NIST_CSF": "DE.AE-02 / PR.DS-01",
    },
    "pii_high_risk": {
        "OWASP": "LLM02:2025 Sensitive Information Disclosure",
        "NIST_AI_RMF": "MANAGE 2.2 / MEASURE 2.11",
        "NIST_CSF": "PR.DS-01 / PR.DS-10",
    },
    "pii_contact": {
        "OWASP": "LLM02:2025 Sensitive Information Disclosure (PII)",
        "NIST_AI_RMF": "MANAGE 2.2 / MAP 3.4",
        "NIST_CSF": "PR.DS-01",
    },
    "pii_leak": {
        "OWASP": "LLM02:2025 Sensitive Information Disclosure (PII Leak)",
        "NIST_AI_RMF": "MANAGE 2.2 / MEASURE 2.11",
        "NIST_CSF": "PR.DS-01 / PR.DS-10",
    },
    "secret_exposed": {
        "OWASP": "LLM02:2025 Sensitive Information Disclosure (Secrets)",
        "NIST_AI_RMF": "MANAGE 2.2 / GOVERN 1.4",
        "NIST_CSF": "PR.DS-01 / PR.AA-05",
    },
    "sensitive_query": {
        "OWASP": "LLM02:2025 Sensitive Information Disclosure",
        "NIST_AI_RMF": "GOVERN 1.4 / MANAGE 4.1",
        "NIST_CSF": "PR.AA-05 / DE.CM-01",
    },
    "strict_block": {
        "OWASP": "LLM01:2025 Prompt Injection & LLM08:2025 Vector Weakness",
        "NIST_AI_RMF": "MANAGE 1.3 / MANAGE 2.4",
        "NIST_CSF": "RS.MI-01 / PR.DS-02",
    },
}


def get_framework_tags(categories: Iterable[str]) -> list[str]:
    """Return deduplicated OWASP, NIST AI RMF, and NIST CSF tags for given categories."""
    tags: list[str] = []
    seen: set[str] = set()
    for category in categories:
        mapping = CONTROL_MAP.get(category)
        if not mapping:
            continue
        entries = (
            f"OWASP: {mapping['OWASP']}",
            f"NIST AI RMF: {mapping['NIST_AI_RMF']}",
            f"NIST CSF: {mapping['NIST_CSF']}",
        )
        for tag in entries:
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


def extract_control_breakdowns(
    categories: Iterable[str],
    framework_tags: Iterable[str] = (),
) -> dict[str, list[str]]:
    """
    Extract structured NIST AI RMF functions (GOVERN/MAP/MEASURE/MANAGE),
    NIST CSF categories (e.g. DE.CM, PR.DS), and OWASP IDs (e.g. LLM01)
    for dashboard violation charts.
    """
    nist_ai_rmf: set[str] = set()
    nist_csf: set[str] = set()
    owasp: set[str] = set()

    tags_to_parse = list(framework_tags)
    if not tags_to_parse:
        tags_to_parse = get_framework_tags(categories)

    for tag in tags_to_parse:
        if tag.startswith("OWASP:"):
            for token in tag.split():
                if token.startswith("LLM") and ":" in token:
                    owasp.add(token.split(":")[0])
        elif tag.startswith("NIST AI RMF:"):
            for fn in ("GOVERN", "MAP", "MEASURE", "MANAGE"):
                if fn in tag:
                    nist_ai_rmf.add(fn)
        elif tag.startswith("NIST CSF:"):
            body = tag.split(":", 1)[1]
            for part in body.split("/"):
                code = part.strip()
                if "-" in code:
                    nist_csf.add(code.split("-")[0])
                elif code:
                    nist_csf.add(code)

    return {
        "nist_ai_rmf": sorted(nist_ai_rmf),
        "nist_csf": sorted(nist_csf),
        "owasp": sorted(owasp),
    }
