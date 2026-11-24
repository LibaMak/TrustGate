from __future__ import annotations

from collections.abc import Iterable

CLAUSE_URLS: dict[str, str] = {
    "LLM01": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    "LLM02": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
    "LLM08": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
    "NIST_AI_RMF": "https://www.nist.gov/itl/ai-risk-management-framework",
    "NIST_CSF": "https://www.nist.gov/cyberframework",
}

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


def risk_level_from_score(score: float | int) -> str:
    val = float(score)
    if val >= 90:
        return "Critical"
    if val >= 70:
        return "High"
    if val >= 40:
        return "Medium"
    if val > 0:
        return "Low"
    return "None"


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


def get_clause_links(
    categories: Iterable[str] = (),
    framework_tags: Iterable[str] = (),
) -> list[tuple[str, str]]:
    """Return clickable (label, url) pairs for OWASP, NIST AI RMF, and NIST CSF clauses."""
    tags = list(framework_tags) if framework_tags else get_framework_tags(categories)
    links: list[tuple[str, str]] = []
    seen: set[str] = set()

    for tag in tags:
        if tag.startswith("OWASP:"):
            body = tag.split(":", 1)[1].strip()
            url = CLAUSE_URLS["LLM01"]
            for oid in ("LLM01", "LLM02", "LLM08"):
                if oid in body:
                    url = CLAUSE_URLS[oid]
                    break
            label = f"OWASP {body.split(':')[0] if ':' in body else body}"
            if label not in seen:
                seen.add(label)
                links.append((label, url))
        elif tag.startswith("NIST AI RMF:"):
            label = tag
            if label not in seen:
                seen.add(label)
                links.append((label, CLAUSE_URLS["NIST_AI_RMF"]))
        elif tag.startswith("NIST CSF:"):
            label = tag
            if label not in seen:
                seen.add(label)
                links.append((label, CLAUSE_URLS["NIST_CSF"]))

    return links


def format_clause_links_md(
    categories: Iterable[str] = (),
    framework_tags: Iterable[str] = (),
) -> str:
    links = get_clause_links(categories=categories, framework_tags=framework_tags)
    if not links:
        return "None"
    return " · ".join(f"[{label}]({url})" for label, url in links)


def format_clause_links_plain(
    categories: Iterable[str] = (),
    framework_tags: Iterable[str] = (),
) -> str:
    links = get_clause_links(categories=categories, framework_tags=framework_tags)
    if not links:
        return "None"
    return " | ".join(f"{label} ({url})" for label, url in links)


def format_clause_codes(
    categories: Iterable[str] = (),
    framework_tags: Iterable[str] = (),
) -> str:
    """Return concise non-URL framework codes for tables and compact audit rows."""
    links = get_clause_links(categories=categories, framework_tags=framework_tags)
    if not links:
        return "None"
    return " · ".join(label for label, _ in links)
