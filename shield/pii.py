from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIFinding:
    pii_type: str
    severity: str  # "high" | "contact"
    count: int
    masked_placeholder: str


_CNIC_RE = re.compile(r"\b\d{5}-\d{7}-\d\b")

_API_KEY_PREFIX_RE = re.compile(
    r"\b(?:gsk_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{20,})\b"
)
_API_KEY_ASSIGN_RE = re.compile(
    r"(?i)\b(api[_ -]?key|secret[_ -]?key|access[_ -]?token|bearer[_ -]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-.]{8,})['\"]?"
)
_PASSWORD_RE = re.compile(
    r"(?i)\b(password|passcode|passwd|pwd)\s*[:=]\s*['\"]?([^\s,'\";]{4,})['\"]?"
)

_CARD_GROUPED_RE = re.compile(r"\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b")
_CARD_COMPACT_RE = re.compile(r"\b\d{13,19}\b")

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?:\+92[-\s]?3\d{2}[-\s]?\d{7}\b|\b03\d{2}[-\s]?\d{7}\b|\+\d{1,3}[-\s]?\(?\d{2,4}\)?[-\s]?\d{3,4}[-\s]?\d{3,4}\b|\(\d{3}\)[-\s]?\d{3}[-\s]?\d{4}\b|\b\d{3}-\d{3}-\d{4}\b)"
)


def _passes_luhn(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mask_cards(text: str) -> tuple[str, int]:
    count = 0

    def _replace_grouped(match: re.Match[str]) -> str:
        nonlocal count
        count += 1
        return "[MASKED_CARD]"

    updated = _CARD_GROUPED_RE.sub(_replace_grouped, text)

    def _replace_compact(match: re.Match[str]) -> str:
        nonlocal count
        raw = match.group(0)
        if _passes_luhn(raw):
            count += 1
            return "[MASKED_CARD]"
        return raw

    updated = _CARD_COMPACT_RE.sub(_replace_compact, updated)
    return updated, count


def _apply_high_risk_masks(text: str) -> tuple[str, list[PIIFinding]]:
    findings: list[PIIFinding] = []
    working = text

    working, cnic_count = _CNIC_RE.subn("[MASKED_CNIC]", working)
    if cnic_count:
        findings.append(PIIFinding("CNIC", "high", cnic_count, "[MASKED_CNIC]"))

    api_count = 0
    working, prefix_count = _API_KEY_PREFIX_RE.subn("[MASKED_API_KEY]", working)
    api_count += prefix_count

    def _replace_api_assign(match: re.Match[str]) -> str:
        nonlocal api_count
        value = match.group(2)
        if value == "[MASKED_API_KEY]":
            return match.group(0)
        api_count += 1
        return f"{match.group(1)}=[MASKED_API_KEY]"

    working = _API_KEY_ASSIGN_RE.sub(_replace_api_assign, working)
    if api_count:
        findings.append(PIIFinding("API_KEY", "high", api_count, "[MASKED_API_KEY]"))

    pwd_count = 0

    def _replace_pwd(match: re.Match[str]) -> str:
        nonlocal pwd_count
        value = match.group(2)
        if value == "[MASKED_PASSWORD]":
            return match.group(0)
        pwd_count += 1
        return f"{match.group(1)}=[MASKED_PASSWORD]"

    working = _PASSWORD_RE.sub(_replace_pwd, working)
    if pwd_count:
        findings.append(PIIFinding("PASSWORD", "high", pwd_count, "[MASKED_PASSWORD]"))

    working, card_count = _mask_cards(working)
    if card_count:
        findings.append(PIIFinding("CARD", "high", card_count, "[MASKED_CARD]"))

    return working, findings


def _detect_contact_pii(text: str) -> tuple[list[PIIFinding], int, int]:
    email_matches = _EMAIL_RE.findall(text)
    phone_matches = _PHONE_RE.findall(text)
    findings: list[PIIFinding] = []
    if email_matches:
        findings.append(PIIFinding("EMAIL", "contact", len(email_matches), "[MASKED_EMAIL]"))
    if phone_matches:
        findings.append(PIIFinding("PHONE", "contact", len(phone_matches), "[MASKED_PHONE]"))
    return findings, len(email_matches), len(phone_matches)


def detect_pii(text: str) -> list[PIIFinding]:
    """Detect all high-risk and contact PII in text without altering it."""
    masked_high, high_findings = _apply_high_risk_masks(text)
    contact_findings, _, _ = _detect_contact_pii(masked_high)
    return high_findings + contact_findings


def mask_high_risk_pii(text: str) -> tuple[str, list[PIIFinding]]:
    """
    Mask CNIC, API keys, passwords, and card numbers in text (for chunk->LLM safety).
    Email and phone are still returned in findings (flagged) without masking them in chunks.
    """
    masked_text, high_findings = _apply_high_risk_masks(text)
    contact_findings, _, _ = _detect_contact_pii(masked_text)
    return masked_text, high_findings + contact_findings


def mask_all_pii(text: str) -> tuple[str, list[PIIFinding]]:
    """Mask high-risk PII plus email and phone numbers (for LLM output & audit logs)."""
    masked_text, high_findings = _apply_high_risk_masks(text)
    contact_findings: list[PIIFinding] = []

    masked_text, email_count = _EMAIL_RE.subn("[MASKED_EMAIL]", masked_text)
    if email_count:
        contact_findings.append(PIIFinding("EMAIL", "contact", email_count, "[MASKED_EMAIL]"))

    masked_text, phone_count = _PHONE_RE.subn("[MASKED_PHONE]", masked_text)
    if phone_count:
        contact_findings.append(PIIFinding("PHONE", "contact", phone_count, "[MASKED_PHONE]"))

    return masked_text, high_findings + contact_findings


def make_masked_snippet(text: str, max_len: int = 160) -> str:
    """Create a short, PII-masked snippet safe for SQLite audit logging."""
    masked, _ = mask_all_pii(text)
    collapsed = " ".join(masked.split())
    if len(collapsed) <= max_len:
        return collapsed
    return collapsed[: max(max_len - 3, 1)].rstrip() + "..."
