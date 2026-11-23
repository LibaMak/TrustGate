from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any

from shield.audit_log import AuditLogger
from shield.control_map import get_framework_tags
from shield.pii import PIIFinding, make_masked_snippet, mask_all_pii, mask_high_risk_pii
from shield.scanner import Finding, ScanResult, scan


@dataclass
class ShieldVerdict:
    """Result returned by TrustGateShield inspection hooks."""

    allowed: bool
    stage: str
    status: str = "ALLOW"
    reason: str = "Passed TrustGate Shield checks."
    risk_score: float = 0.0
    flagged_items: list[str] = field(default_factory=list)
    location: str = ""
    framework_tags: list[str] = field(default_factory=list)
    action: str = "safe"
    policy: str = "allow"
    findings: list[Finding] = field(default_factory=list)


@dataclass
class QuarantinedItem:
    chunk_id: str
    source: str
    location: str
    risk_score: int
    reason: str
    framework_tags: list[str] = field(default_factory=list)
    masked_snippet: str = ""


@dataclass
class DocumentScanSummary:
    source: str
    total_chunks: int
    suspicious_chunks: int
    quarantined_chunks: int
    suspicious_ratio: float
    policy_action: str  # "allow" | "sanitize" | "strict_block" | "bypassed"
    max_risk_score: int
    kept_chunks: list[Any] = field(default_factory=list)
    quarantined_items: list[QuarantinedItem] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    framework_tags: list[str] = field(default_factory=list)
    reason: str = ""
    removed_items_count: int = 0
    removed_texts_summary: list[str] = field(default_factory=list)


_HIGH_RISK_QUERY_RE = re.compile(
    r"(?i)\b(?:cnic|national\s+id|password|passcode|passwd|pwd|api[_ -]?key|secret[_ -]?key|access[_ -]?token|card\s+number|credit\s+card|debit\s+card|cvv)\b"
)
_CONTACT_QUERY_RE = re.compile(
    r"(?i)\b(?:phone|mobile|cell|contact\s+number|telephone|email|e-mail)\b"
)


def _normalize_format(source: str, file_type: str | None = None) -> str:
    ft = (file_type or "").lower().lstrip(".")
    if ft in {"pdf"} or source.lower().endswith(".pdf"):
        return "PDF"
    if ft in {"docx"} or source.lower().endswith(".docx"):
        return "DOCX"
    if ft in {"url", "html", "htm"} or source.lower().endswith((".html", ".htm")) or source.lower().startswith(("http://", "https://")):
        return "URL"
    if ft in {"txt", "md"} or source.lower().endswith((".txt", ".md")):
        return "TXT"
    return "TXT"


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    word = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {word}"


def _sanitize_flagged_chunk(chunk: Any) -> tuple[Any | None, list[str], int, int]:
    """
    Remove offending hidden-text spans and flagged sentences/lines from a chunk,
    returning (clean_chunk_or_None, removed_raw_parts, hidden_removed_count, plain_removed_count).
    """
    metadata = dict(getattr(chunk, "metadata", {}) or {})
    working_text = getattr(chunk, "text", "") or ""
    removed_parts: list[str] = []
    hidden_removed = 0
    plain_removed = 0

    # 1. Strip hidden-text spans attached by PDF/DOCX/HTML extractors
    for h_txt in metadata.get("hidden_texts", []):
        candidate = (h_txt or "").strip()
        if not candidate:
            continue
        compact_candidate = " ".join(candidate.split())
        removed_here = False
        if candidate in working_text:
            working_text = working_text.replace(candidate, "")
            removed_here = True
        elif compact_candidate and compact_candidate in working_text:
            working_text = working_text.replace(compact_candidate, "")
            removed_here = True
        else:
            # Regex fallback for whitespace differences across line wraps
            words = [re.escape(w) for w in compact_candidate.split()]
            if words:
                pattern = re.compile(r"\s+".join(words))
                if pattern.search(working_text):
                    working_text = pattern.sub("", working_text)
                    removed_here = True
        if removed_here:
            removed_parts.append(candidate)
            hidden_removed += 1

    # 2. Split remaining text into lines, then sentences, and scan each unit
    clean_lines: list[str] = []
    for raw_line in working_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        sentences = re.split(r"(?<=[.!?])\s+", line)
        kept_sentences: list[str] = []
        for sent in sentences:
            s_clean = sent.strip()
            if not s_clean:
                continue
            seg_res = scan(s_clean)
            if seg_res.action == "quarantine" or seg_res.has_hidden_text:
                removed_parts.append(s_clean)
                if seg_res.has_hidden_text:
                    hidden_removed += 1
                else:
                    plain_removed += 1
            else:
                kept_sentences.append(s_clean)
        if kept_sentences:
            clean_lines.append(" ".join(kept_sentences))

    clean_text = "\n".join(clean_lines).strip()
    if not clean_text:
        return None, removed_parts, hidden_removed, plain_removed

    cloned = copy.copy(chunk)
    cloned.text = clean_text
    metadata["hidden_findings"] = []
    metadata["hidden_texts"] = []
    metadata["sanitized"] = True
    cloned.metadata = metadata

    # Safety re-check: drop chunk if anything flagged still spans across remaining text
    verify = scan(cloned)
    if verify.action == "quarantine" or verify.has_hidden_text:
        removed_parts.append(clean_text)
        if verify.has_hidden_text:
            hidden_removed += 1
        else:
            plain_removed += 1
        return None, removed_parts, hidden_removed, plain_removed

    return cloned, removed_parts, hidden_removed, plain_removed


class TrustGateShield:
    """
    Day 2 TrustGate Shield implementing:
    - Prompt-injection & hidden-text scanning + quarantine
    - Sanitize (default, sentence/line-level) vs Strict Block (>=5 chunks AND >30% suspicious)
    - PII detection & masking (high-risk before LLM + all PII in LLM output)
    - Sensitive query refusal / masked-contact warning
    - OWASP / NIST AI RMF / NIST CSF framework mapping
    - SQLite masked audit logging
    """

    mode: str = "active"

    def __init__(
        self,
        enabled: bool = True,
        strict_threshold: float = 0.30,
        min_chunks_for_strict_block: int = 5,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.enabled = enabled
        self.strict_threshold = strict_threshold
        self.min_chunks_for_strict_block = min_chunks_for_strict_block
        self.audit_logger = audit_logger or AuditLogger()
        if not self.enabled:
            self.mode = "bypassed"

    def _log_if_enabled(
        self,
        *,
        event_type: str,
        source: str,
        location: str,
        risk_score: int,
        action: str,
        categories: list[str],
        framework_tags: list[str],
        reason: str,
        raw_text: str,
        file_format: str = "UNKNOWN",
        finding_type: str | None = None,
        pii_count: int = 0,
    ) -> None:
        if self.audit_logger is None:
            return
        self.audit_logger.log_finding(
            event_type=event_type,
            source=source,
            location=location,
            risk_score=risk_score,
            action=action,
            categories=categories,
            framework_tags=framework_tags,
            reason=reason,
            raw_text=raw_text,
            file_format=file_format,
            finding_type=finding_type,
            pii_count=pii_count,
        )

    def scan_document_chunks(self, source: str, chunks: list[Any]) -> DocumentScanSummary:
        first_meta = (chunks[0].metadata or {}) if chunks else {}
        doc_format = _normalize_format(source, first_meta.get("file_type"))

        if not self.enabled:
            if self.audit_logger is not None:
                for chunk in chunks:
                    loc = (chunk.metadata or {}).get("location", chunk.chunk_id)
                    self.audit_logger.log_chunk_scan(
                        source=source,
                        file_format=doc_format,
                        location=loc,
                        risk_score=0,
                        action="bypassed",
                        pii_masked_count=0,
                    )
            return DocumentScanSummary(
                source=source,
                total_chunks=len(chunks),
                suspicious_chunks=0,
                quarantined_chunks=0,
                suspicious_ratio=0.0,
                policy_action="bypassed",
                max_risk_score=0,
                kept_chunks=list(chunks),
                reason="Shield disabled (OFF).",
            )

        total = len(chunks)
        if total == 0:
            return DocumentScanSummary(
                source=source,
                total_chunks=0,
                suspicious_chunks=0,
                quarantined_chunks=0,
                suspicious_ratio=0.0,
                policy_action="allow",
                max_risk_score=0,
                kept_chunks=[],
                reason="Empty document.",
            )

        suspicious_count = 0
        quarantined_items: list[QuarantinedItem] = []
        flagged_chunks: list[tuple[Any, str, ScanResult]] = []
        clean_chunks: list[tuple[Any, str, int]] = []
        all_findings: list[Finding] = []
        all_categories: set[str] = set()
        max_risk = 0

        for chunk in chunks:
            result: ScanResult = scan(chunk)
            max_risk = max(max_risk, result.risk_score)
            location = (chunk.metadata or {}).get("location", chunk.chunk_id)

            is_suspicious = (
                result.action == "quarantine" or result.has_hidden_text or result.risk_score >= 50
            )
            if is_suspicious:
                suspicious_count += 1

            if result.findings:
                all_findings.extend(result.findings)
                for f in result.findings:
                    all_categories.add(f.category)
                reason = "; ".join(f.detail for f in result.findings[:3])
                cats = sorted({f.category for f in result.findings})
                ftype = "prompt_injection" if result.has_injection else "hidden_text"
                self._log_if_enabled(
                    event_type="chunk_scan",
                    source=source,
                    location=location,
                    risk_score=result.risk_score,
                    action=result.action,
                    categories=cats,
                    framework_tags=result.framework_tags,
                    reason=reason,
                    raw_text=chunk.text,
                    file_format=doc_format,
                    finding_type=ftype,
                )

            if result.action == "quarantine" or result.has_hidden_text:
                flagged_chunks.append((chunk, location, result))
            else:
                clean_chunks.append((chunk, location, result.risk_score))

        suspicious_ratio = suspicious_count / total

        # Strict block ONLY when total chunks >= 5 AND > 30% of chunks are suspicious
        if total >= self.min_chunks_for_strict_block and suspicious_ratio > self.strict_threshold:
            for chunk, location, result in flagged_chunks:
                if result.action == "quarantine":
                    quarantined_items.append(
                        QuarantinedItem(
                            chunk_id=chunk.chunk_id,
                            source=source,
                            location=location,
                            risk_score=result.risk_score,
                            reason="; ".join(f.detail for f in result.findings),
                            framework_tags=result.framework_tags,
                            masked_snippet=make_masked_snippet(chunk.text),
                        )
                    )
            all_categories.add("strict_block")
            tags = get_framework_tags(sorted(all_categories))
            reason = (
                f"Strict Block: {suspicious_count}/{total} chunks ({suspicious_ratio:.0%}) "
                f"exceeded the {self.strict_threshold:.0%} threshold (>= {self.min_chunks_for_strict_block} chunks); "
                "entire document rejected."
            )
            if self.audit_logger is not None:
                for chunk, loc, res in flagged_chunks:
                    self.audit_logger.log_chunk_scan(
                        source=source,
                        file_format=doc_format,
                        location=loc,
                        risk_score=res.risk_score,
                        action="blocked",
                    )
                for chunk, loc, rscore in clean_chunks:
                    self.audit_logger.log_chunk_scan(
                        source=source,
                        file_format=doc_format,
                        location=loc,
                        risk_score=rscore,
                        action="blocked",
                    )
            self._log_if_enabled(
                event_type="strict_block",
                source=source,
                location="Entire Document",
                risk_score=max_risk,
                action="strict_block",
                categories=sorted(all_categories),
                framework_tags=tags,
                reason=reason,
                raw_text=source,
                file_format=doc_format,
                finding_type="prompt_injection" if any(f.category == "prompt_injection" for f in all_findings) else "hidden_text",
            )
            return DocumentScanSummary(
                source=source,
                total_chunks=total,
                suspicious_chunks=suspicious_count,
                quarantined_chunks=len(quarantined_items),
                suspicious_ratio=suspicious_ratio,
                policy_action="strict_block",
                max_risk_score=max_risk,
                kept_chunks=[],
                quarantined_items=quarantined_items,
                findings=all_findings,
                framework_tags=tags,
                reason=reason,
                removed_items_count=len(flagged_chunks),
            )

        # Sentence/line-level sanitization for flagged chunks (preserves clean remainder)
        chunks_to_keep: list[tuple[Any, str, int]] = list(clean_chunks)
        total_hidden_removed = 0
        total_plain_removed = 0
        removed_snippets: list[str] = []

        for chunk, location, result in flagged_chunks:
            clean_chunk, removed_parts, hidden_cnt, plain_cnt = _sanitize_flagged_chunk(chunk)
            total_hidden_removed += hidden_cnt
            total_plain_removed += plain_cnt
            removed_preview = make_masked_snippet(" | ".join(removed_parts) if removed_parts else chunk.text)
            removed_snippets.append(removed_preview)

            finding_reason = "; ".join(f.detail for f in result.findings) or "Suspicious content removed."
            quarantined_items.append(
                QuarantinedItem(
                    chunk_id=chunk.chunk_id,
                    source=source,
                    location=location,
                    risk_score=result.risk_score,
                    reason=finding_reason,
                    framework_tags=result.framework_tags,
                    masked_snippet=removed_preview,
                )
            )
            if self.audit_logger is not None:
                self.audit_logger.log_chunk_scan(
                    source=source,
                    file_format=doc_format,
                    location=location,
                    risk_score=result.risk_score,
                    action="blocked",
                )
            if clean_chunk is not None:
                chunks_to_keep.append((clean_chunk, location, 0))

        # Preserve original chunk order
        chunks_to_keep.sort(key=lambda entry: getattr(entry[0], "index", 0))

        # Mask high-risk PII in kept chunks before indexing/LLM
        sanitized_kept: list[Any] = []
        for chunk, loc, rscore in chunks_to_keep:
            masked_text, pii_findings = mask_high_risk_pii(chunk.text)
            cloned = copy.copy(chunk)
            cloned.text = masked_text
            cloned.metadata = dict(chunk.metadata or {})
            high_pii_count = sum(f.count for f in pii_findings if f.severity == "high")
            if self.audit_logger is not None:
                self.audit_logger.log_chunk_scan(
                    source=source,
                    file_format=doc_format,
                    location=loc,
                    risk_score=rscore,
                    action="allowed",
                    pii_masked_count=high_pii_count,
                )
            if pii_findings:
                cloned.metadata["pii_flagged"] = [f.pii_type for f in pii_findings]
                secret_findings = [f for f in pii_findings if f.pii_type in {"API_KEY", "PASSWORD"}]
                leak_findings = [f for f in pii_findings if f.pii_type not in {"API_KEY", "PASSWORD"}]

                if secret_findings:
                    s_cats = ["secret_exposed", "pii_high_risk"]
                    all_categories.update(s_cats)
                    s_desc = ", ".join(f"{f.pii_type}({f.count})" for f in secret_findings)
                    self._log_if_enabled(
                        event_type="pii_chunk_scan",
                        source=source,
                        location=cloned.metadata.get("location", cloned.chunk_id),
                        risk_score=max(65, max_risk),
                        action="masked_high_risk",
                        categories=s_cats,
                        framework_tags=get_framework_tags(s_cats),
                        reason=f"Secret exposed in chunk: {s_desc}",
                        raw_text=chunk.text,
                        file_format=doc_format,
                        finding_type="secret_exposed",
                        pii_count=sum(f.count for f in secret_findings),
                    )
                if leak_findings:
                    l_cats = ["pii_leak"] + [
                        "pii_high_risk" if f.severity == "high" else "pii_contact" for f in leak_findings
                    ]
                    l_cats = sorted(set(l_cats))
                    all_categories.update(l_cats)
                    l_desc = ", ".join(f"{f.pii_type}({f.count})" for f in leak_findings)
                    has_high = any(f.severity == "high" for f in leak_findings)
                    self._log_if_enabled(
                        event_type="pii_chunk_scan",
                        source=source,
                        location=cloned.metadata.get("location", cloned.chunk_id),
                        risk_score=max(50 if has_high else 25, max_risk),
                        action="masked_high_risk" if has_high else "flagged_contact",
                        categories=l_cats,
                        framework_tags=get_framework_tags(l_cats),
                        reason=f"PII detected in chunk: {l_desc}",
                        raw_text=chunk.text,
                        file_format=doc_format,
                        finding_type="pii_leak",
                        pii_count=sum(f.count for f in leak_findings),
                    )
            sanitized_kept.append(cloned)

        total_removed = total_hidden_removed + total_plain_removed
        if quarantined_items or total_removed > 0:
            policy_action = "sanitize"
            kept_label = _plural(len(sanitized_kept), "clean section")
            if total_hidden_removed > 0 and total_plain_removed == 0:
                removed_label = f"{_plural(total_hidden_removed, 'hidden instruction')} removed"
            elif total_hidden_removed > 0 and total_plain_removed > 0:
                removed_label = (
                    f"{_plural(total_removed, 'offending instruction')} removed "
                    f"({total_hidden_removed} hidden)"
                )
            else:
                removed_label = f"{_plural(max(total_removed, len(quarantined_items)), 'offending instruction')} removed"
            reason = f"Sanitized: {removed_label}, {kept_label} kept."
        else:
            policy_action = "allow"
            reason = "All chunks passed TrustGate Shield checks."

        return DocumentScanSummary(
            source=source,
            total_chunks=total,
            suspicious_chunks=suspicious_count,
            quarantined_chunks=len(quarantined_items),
            suspicious_ratio=suspicious_ratio,
            policy_action=policy_action,
            max_risk_score=max_risk,
            kept_chunks=sanitized_kept,
            quarantined_items=quarantined_items,
            findings=all_findings,
            framework_tags=get_framework_tags(sorted(all_categories)),
            reason=reason,
            removed_items_count=max(total_removed, len(quarantined_items)) if quarantined_items else 0,
            removed_texts_summary=removed_snippets,
        )

    def inspect_document(self, text: str, source: str) -> ShieldVerdict:
        if not self.enabled:
            return ShieldVerdict(
                allowed=True,
                stage="document",
                status="BYPASSED",
                reason="Shield disabled (OFF).",
                policy="bypassed",
            )
        result = scan(text)
        return ShieldVerdict(
            allowed=result.action != "quarantine",
            stage="document",
            status="QUARANTINED" if result.action == "quarantine" else "ALLOW",
            reason="; ".join(f.detail for f in result.findings) or "Document passed.",
            risk_score=float(result.risk_score),
            flagged_items=[f.rule for f in result.findings],
            location=source,
            framework_tags=result.framework_tags,
            action=result.action,
            findings=result.findings,
        )

    def inspect_query(self, query: str) -> ShieldVerdict:
        if not self.enabled:
            return ShieldVerdict(
                allowed=True,
                stage="query",
                status="BYPASSED",
                reason="Shield disabled (OFF).",
                risk_score=0.0,
                policy="bypassed",
            )

        inj_scan = scan(query)
        if inj_scan.action == "quarantine":
            reason = "Blocked prompt-injection attempt in query: " + "; ".join(
                f.detail for f in inj_scan.findings
            )
            self._log_if_enabled(
                event_type="query_block",
                source="user_query",
                location="Chat Input",
                risk_score=inj_scan.risk_score,
                action="refuse",
                categories=sorted({f.category for f in inj_scan.findings}),
                framework_tags=inj_scan.framework_tags,
                reason=reason,
                raw_text=query,
                file_format="QUERY",
                finding_type="prompt_injection",
            )
            return ShieldVerdict(
                allowed=False,
                stage="query",
                status="REFUSED_INJECTION",
                reason=reason,
                risk_score=float(inj_scan.risk_score),
                flagged_items=[f.rule for f in inj_scan.findings],
                location="Chat Input",
                framework_tags=inj_scan.framework_tags,
                action="quarantine",
                policy="refuse",
                findings=inj_scan.findings,
            )

        high_matches = _HIGH_RISK_QUERY_RE.findall(query)
        if high_matches:
            terms = sorted({m.lower() for m in high_matches})
            tags = get_framework_tags(["sensitive_query", "pii_high_risk"])
            reason = (
                f"Refused sensitive query requesting {', '.join(terms)}. "
                "CNIC, card numbers, passwords, and API keys cannot be disclosed."
            )
            self._log_if_enabled(
                event_type="sensitive_query_refusal",
                source="user_query",
                location="Chat Input",
                risk_score=85,
                action="refuse",
                categories=["sensitive_query", "pii_high_risk"],
                framework_tags=tags,
                reason=reason,
                raw_text=query,
                file_format="QUERY",
                finding_type="sensitive_query",
            )
            return ShieldVerdict(
                allowed=False,
                stage="query",
                status="REFUSED_SENSITIVE_QUERY",
                reason=reason,
                risk_score=85.0,
                flagged_items=terms,
                location="Chat Input",
                framework_tags=tags,
                action="refuse",
                policy="refuse",
            )

        contact_matches = _CONTACT_QUERY_RE.findall(query)
        if contact_matches:
            terms = sorted({m.lower() for m in contact_matches})
            tags = get_framework_tags(["sensitive_query", "pii_contact"])
            reason = (
                f"Sensitive contact query ({', '.join(terms)}) detected: "
                "response values will be masked."
            )
            self._log_if_enabled(
                event_type="sensitive_query_warning",
                source="user_query",
                location="Chat Input",
                risk_score=35,
                action="warn_mask",
                categories=["sensitive_query", "pii_contact"],
                framework_tags=tags,
                reason=reason,
                raw_text=query,
                file_format="QUERY",
                finding_type="sensitive_query",
            )
            return ShieldVerdict(
                allowed=True,
                stage="query",
                status="WARN_CONTACT_QUERY",
                reason=reason,
                risk_score=35.0,
                flagged_items=terms,
                location="Chat Input",
                framework_tags=tags,
                action="warn",
                policy="mask_output",
            )

        return ShieldVerdict(
            allowed=True,
            stage="query",
            status="ALLOW",
            reason="Query passed TrustGate Shield checks.",
            risk_score=float(inj_scan.risk_score),
            location="Chat Input",
            framework_tags=inj_scan.framework_tags,
            action="safe",
            policy="allow",
        )

    def prepare_chunks_for_llm(self, retrieved_chunks: list[Any]) -> tuple[list[Any], ShieldVerdict]:
        if not self.enabled:
            return list(retrieved_chunks), ShieldVerdict(
                allowed=True,
                stage="chunks",
                status="BYPASSED",
                reason="Shield disabled (OFF).",
                policy="bypassed",
            )

        safe_chunks: list[Any] = []
        flagged_items: list[str] = []
        categories: set[str] = set()
        max_risk = 0

        for item in retrieved_chunks:
            chunk = getattr(item, "chunk", item)
            scan_res = scan(chunk)
            max_risk = max(max_risk, scan_res.risk_score)
            if scan_res.action == "quarantine":
                flagged_items.append(f"quarantined:{chunk.chunk_id}")
                categories.update(f.category for f in scan_res.findings)
                continue

            masked_text, pii_findings = mask_high_risk_pii(chunk.text)
            if pii_findings:
                for pf in pii_findings:
                    flagged_items.append(f"{pf.pii_type}:{chunk.chunk_id}")
                    categories.add("pii_high_risk" if pf.severity == "high" else "pii_contact")

            cloned_chunk = copy.copy(chunk)
            cloned_chunk.text = masked_text
            if hasattr(item, "chunk"):
                cloned_item = copy.copy(item)
                cloned_item.chunk = cloned_chunk
                safe_chunks.append(cloned_item)
            else:
                safe_chunks.append(cloned_chunk)

        tags = get_framework_tags(sorted(categories))
        status = "SANITIZED" if flagged_items else "ALLOW"
        reason = (
            f"Prepared {len(safe_chunks)} chunk(s) with Shield checks ({', '.join(flagged_items)})."
            if flagged_items
            else "All retrieved chunks passed Shield checks."
        )
        return safe_chunks, ShieldVerdict(
            allowed=True,
            stage="chunks",
            status=status,
            reason=reason,
            risk_score=float(max_risk),
            flagged_items=flagged_items,
            framework_tags=tags,
            action="safe",
            policy="sanitize" if flagged_items else "allow",
        )

    def inspect_chunks(self, chunks: list[Any]) -> ShieldVerdict:
        _, verdict = self.prepare_chunks_for_llm(chunks)
        return verdict

    def sanitize_response(self, response: str) -> tuple[str, ShieldVerdict]:
        if not self.enabled:
            return response, ShieldVerdict(
                allowed=True,
                stage="response",
                status="BYPASSED",
                reason="Shield disabled (OFF).",
                policy="bypassed",
            )

        masked_text, pii_findings = mask_all_pii(response)
        if pii_findings:
            cats = sorted(
                {"pii_high_risk" if f.severity == "high" else "pii_contact" for f in pii_findings}
            )
            tags = get_framework_tags(cats)
            summary = ", ".join(f"{f.pii_type}({f.count})" for f in pii_findings)
            reason = f"Masked PII in LLM output: {summary}."
            has_secret = any(f.pii_type in {"API_KEY", "PASSWORD"} for f in pii_findings)
            total_masked = sum(f.count for f in pii_findings)
            self._log_if_enabled(
                event_type="response_pii_mask",
                source="llm_output",
                location="Assistant Response",
                risk_score=75 if "pii_high_risk" in cats else 35,
                action="masked_output",
                categories=cats,
                framework_tags=tags,
                reason=reason,
                raw_text=response,
                file_format="OUTPUT",
                finding_type="secret_exposed" if has_secret else "pii_leak",
                pii_count=total_masked,
            )
            return masked_text, ShieldVerdict(
                allowed=True,
                stage="response",
                status="MASKED_PII",
                reason=reason,
                risk_score=75.0 if "pii_high_risk" in cats else 35.0,
                flagged_items=[f.pii_type for f in pii_findings],
                location="Assistant Response",
                framework_tags=tags,
                action="masked",
                policy="mask_output",
            )

        return response, ShieldVerdict(
            allowed=True,
            stage="response",
            status="ALLOW",
            reason="Output passed PII & safety checks.",
            risk_score=0.0,
            location="Assistant Response",
            action="safe",
            policy="allow",
        )

    def inspect_response(self, response: str) -> ShieldVerdict:
        _, verdict = self.sanitize_response(response)
        return verdict
