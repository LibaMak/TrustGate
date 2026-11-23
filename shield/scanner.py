from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from typing import Any
from xml.etree import ElementTree as ET

import pymupdf
from bs4 import BeautifulSoup, Comment
from docx import Document as DocxDocument

from shield.control_map import get_framework_tags
from shield.pii import make_masked_snippet


@dataclass
class Finding:
    category: str  # "prompt_injection" | "hidden_text"
    rule: str
    detail: str
    location: str
    evidence_snippet: str
    severity_points: int


@dataclass
class ScanResult:
    risk_score: int
    findings: list[Finding] = field(default_factory=list)
    action: str = "safe"  # "safe" | "quarantine"
    framework_tags: list[str] = field(default_factory=list)
    has_hidden_text: bool = False
    has_injection: bool = False


INJECTION_PATTERNS: list[tuple[str, str]] = [
    ("ignore_previous_instructions", r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?"),
    ("disregard_earlier", r"disregard\s+(?:all\s+)?(?:earlier|previous|prior)\b"),
    ("system_prompt", r"\bsystem\s+prompt\b"),
    (
        "reveal_sensitive",
        r"\breveal\s+(?:the\s+|your\s+|all\s+)?(?:hidden\s+|secret\s+|system\s+|internal\s+|confidential\s+)?(?:prompt|instructions?|rules?|secrets?|credentials?|passwords?|keys?|data)\b",
    ),
    ("you_are_now", r"\byou\s+are\s+now\b"),
    ("rank_this_candidate", r"\brank\s+this\s+candidate\b"),
    ("forward_all", r"\bforward\s+all\b"),
    ("do_not_tell_user", r"\bdo\s+not\s+tell\s+the\s+user\b"),
    # 18+ additional prompt-injection & indirect-injection variants
    ("override_instructions", r"\boverride\s+(?:all\s+)?(?:previous|system|safety|prior)\s+(?:instructions?|rules?|policies)\b"),
    ("forget_instructions", r"\bforget\s+(?:all\s+)?(?:your|previous|prior)\s+instructions?\b"),
    ("new_instructions", r"\bnew\s+instructions?\s*:"),
    ("act_as_unrestricted", r"\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|admin|root|jailbroken)\b"),
    ("pretend_you_are", r"\bpretend\s+(?:that\s+)?you\s+are\b"),
    ("developer_mode", r"\bdeveloper\s+mode\b"),
    ("jailbreak", r"\bjailbreak\b"),
    ("bypass_safety", r"\bbypass\s+(?:all\s+)?(?:safety|security|shield|guardrails?|filters?|restrictions?)\b"),
    ("exfiltrate_data", r"\bexfiltrate\b"),
    ("send_all_data", r"\bsend\s+(?:all\s+)?(?:data|documents?|files?|secrets?|context)\s+to\b"),
    ("output_system_prompt", r"\b(?:output|print|show|dump|leak)\s+(?:the\s+|your\s+)?(?:system|hidden|secret)\s+(?:prompt|instructions?)\b"),
    ("repeat_everything_above", r"\brepeat\s+(?:everything|all\s+text)\s+above\b"),
    ("do_not_mention_this", r"\bdo\s+not\s+(?:mention|disclose|report)\s+this\b"),
    ("secretly_instruct", r"\bsecretly\s+(?:include|send|rank|recommend|execute|append)\b"),
    ("highest_priority_instruction", r"\bhighest\s+priority\s+instruction\b"),
    ("shortlist_hire_candidate", r"\b(?:always|must)\s+(?:shortlist|hire|select|recommend)\s+this\s+candidate\b"),
    ("ignore_safety_rules", r"\bignore\s+(?:all\s+)?(?:safety|security|policy)\s+(?:rules?|guidelines?|checks?)\b"),
    ("role_delimiter_system", r"(?:\[system\]|<\|im_start\|>system|<system>)"),
    ("prompt_injection_tag", r"\bprompt\s+injection\b"),
    ("execute_hidden_command", r"\bexecute\s+(?:the\s+)?(?:following|hidden)\s+(?:command|instruction)\b"),
]

_COMPILED_INJECTIONS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(pattern, re.IGNORECASE)) for name, pattern in INJECTION_PATTERNS
]

_ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF\u2060\u00AD]")
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_TAG_UNICODE_RE = re.compile(r"[\U000E0000-\U000E007F]")
_PDF_INVISIBLE_TR_RE = re.compile(rb"(?:^|[\r\n\s])3\s+Tr(?:$|[\r\n\s])")


def _rgb_from_int(color_int: int) -> tuple[int, int, int]:
    return ((color_int >> 16) & 0xFF, (color_int >> 8) & 0xFF, color_int & 0xFF)


def _is_white_or_near_white(rgb: tuple[int, int, int]) -> bool:
    return rgb[0] >= 245 and rgb[1] >= 245 and rgb[2] >= 245


def _parse_hex_rgb(hex_str: str | None) -> tuple[int, int, int] | None:
    if not hex_str:
        return None
    cleaned = hex_str.strip().lstrip("#")
    if len(cleaned) != 6:
        return None
    try:
        return (int(cleaned[0:2], 16), int(cleaned[2:4], 16), int(cleaned[4:6], 16))
    except ValueError:
        return None


def detect_txt_hidden_unicode(text: str, location: str = "Text Document") -> list[Finding]:
    """Detect zero-width, bidi-override, and Unicode tag characters."""
    findings: list[Finding] = []
    zw_matches = _ZERO_WIDTH_RE.findall(text)
    if zw_matches:
        findings.append(
            Finding(
                category="hidden_text",
                rule="txt_zero_width_unicode",
                detail=f"Detected {len(zw_matches)} zero-width/invisible Unicode character(s).",
                location=location,
                evidence_snippet=make_masked_snippet(text),
                severity_points=60,
            )
        )
    bidi_matches = _BIDI_OVERRIDE_RE.findall(text)
    if bidi_matches:
        findings.append(
            Finding(
                category="hidden_text",
                rule="txt_bidi_override_unicode",
                detail=f"Detected {len(bidi_matches)} bidirectional override Unicode character(s).",
                location=location,
                evidence_snippet=make_masked_snippet(text),
                severity_points=60,
            )
        )
    tag_matches = _TAG_UNICODE_RE.findall(text)
    if tag_matches:
        findings.append(
            Finding(
                category="hidden_text",
                rule="txt_tag_unicode",
                detail=f"Detected {len(tag_matches)} invisible Unicode tag character(s).",
                location=location,
                evidence_snippet=make_masked_snippet(text),
                severity_points=60,
            )
        )
    return findings


def extract_pdf_with_hidden(data: bytes) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Extract PDF pages with PyMuPDF and inspect spans for hidden-text techniques."""
    doc = pymupdf.open(stream=data, filetype="pdf")
    segments: list[dict[str, Any]] = []
    page_texts: list[str] = []
    total_hidden = 0

    try:
        for page_idx, page in enumerate(doc, start=1):
            location = f"Page {page_idx}"
            page_rect = page.rect
            text_dict = page.get_text("dict")
            hidden_findings: list[dict[str, Any]] = []
            hidden_texts: list[str] = []
            page_lines: list[str] = []

            raw_contents = page.read_contents()
            has_invisible_tr = bool(_PDF_INVISIBLE_TR_RE.search(raw_contents))
            if has_invisible_tr:
                page_plain = (page.get_text("text") or "").strip()
                hidden_findings.append(
                    {
                        "rule": "pdf_invisible_render_mode",
                        "detail": "PDF content stream uses invisible text render mode (3 Tr).",
                        "location": location,
                        "snippet": make_masked_snippet(page_plain),
                    }
                )
                if page_plain:
                    hidden_texts.append(page_plain)

            for block in text_dict.get("blocks", []):
                if block.get("type") != 0:
                    continue
                for line in block.get("lines", []):
                    line_spans: list[str] = []
                    for span in line.get("spans", []):
                        span_text = span.get("text", "")
                        if not span_text.strip():
                            continue
                        line_spans.append(span_text)

                        color_int = int(span.get("color", 0))
                        rgb = _rgb_from_int(color_int)
                        size = float(span.get("size", 12.0))
                        bbox = span.get("bbox", (0, 0, 0, 0))

                        reasons: list[tuple[str, str]] = []
                        if _is_white_or_near_white(rgb):
                            reasons.append(
                                (
                                    "pdf_white_text",
                                    f"White/background-colored text RGB{rgb} detected.",
                                )
                            )
                        if size < 2.0:
                            reasons.append(
                                (
                                    "pdf_micro_font",
                                    f"Microscopic font size ({size:.2f}pt < 2pt) detected.",
                                )
                            )
                        if (
                            bbox[2] < page_rect.x0 - 2
                            or bbox[0] > page_rect.x1 + 2
                            or bbox[3] < page_rect.y0 - 2
                            or bbox[1] > page_rect.y1 + 2
                        ):
                            reasons.append(
                                (
                                    "pdf_offpage_text",
                                    f"Off-page text coordinates {tuple(round(v, 1) for v in bbox)}.",
                                )
                            )

                        for rule, detail in reasons:
                            hidden_findings.append(
                                {
                                    "rule": rule,
                                    "detail": detail,
                                    "location": location,
                                    "snippet": make_masked_snippet(span_text),
                                }
                            )
                            hidden_texts.append(span_text)

                    if line_spans:
                        page_lines.append("".join(line_spans).strip())

            full_page_text = "\n".join(line for line in page_lines if line).strip()
            if full_page_text:
                page_texts.append(full_page_text)
                total_hidden += len(hidden_findings)
                segments.append(
                    {
                        "text": full_page_text,
                        "location": location,
                        "hidden_findings": hidden_findings,
                        "hidden_texts": hidden_texts,
                    }
                )

        metadata = {"page_count": len(doc), "hidden_signal_count": total_hidden}
    finally:
        doc.close()

    return "\n\n".join(page_texts), metadata, segments


def _extract_docx_comments(data: bytes) -> list[str]:
    comments: list[str] = []
    try:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            if "word/comments.xml" not in zf.namelist():
                return []
            xml_bytes = zf.read("word/comments.xml")
        root = ET.fromstring(xml_bytes)
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        for comment_el in root.findall(".//w:comment", ns):
            texts = [t.text for t in comment_el.findall(".//w:t", ns) if t.text]
            joined = "".join(texts).strip()
            if joined:
                comments.append(joined)
    except Exception:
        return []
    return comments


def _run_has_vanish_xml(run: Any) -> bool:
    rpr = getattr(run._element, "rPr", None)
    if rpr is None:
        return False
    ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    return rpr.find(f"{ns}vanish") is not None


def extract_docx_with_hidden(data: bytes) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Extract DOCX paragraphs, tables, hidden runs, white runs, and comments."""
    doc = DocxDocument(BytesIO(data))
    segments: list[dict[str, Any]] = []
    parts: list[str] = []
    total_hidden = 0

    for p_idx, paragraph in enumerate(doc.paragraphs, start=1):
        text = paragraph.text.strip()
        if not text:
            continue
        location = f"Paragraph {p_idx}"
        hidden_findings: list[dict[str, Any]] = []
        hidden_texts: list[str] = []

        for run in paragraph.runs:
            run_text = run.text.strip()
            if not run_text:
                continue
            if run.font.hidden or _run_has_vanish_xml(run):
                hidden_findings.append(
                    {
                        "rule": "docx_hidden_run",
                        "detail": "DOCX run has hidden font attribute (w:vanish).",
                        "location": location,
                        "snippet": make_masked_snippet(run_text),
                    }
                )
                hidden_texts.append(run_text)
            rgb = run.font.color.rgb if run.font.color and run.font.color.rgb else None
            if rgb is not None:
                parsed = _parse_hex_rgb(str(rgb))
                if parsed and _is_white_or_near_white(parsed):
                    hidden_findings.append(
                        {
                            "rule": "docx_white_text",
                            "detail": f"DOCX run uses white/near-white color #{rgb}.",
                            "location": location,
                            "snippet": make_masked_snippet(run_text),
                        }
                    )
                    hidden_texts.append(run_text)

        parts.append(text)
        total_hidden += len(hidden_findings)
        segments.append(
            {
                "text": text,
                "location": location,
                "hidden_findings": hidden_findings,
                "hidden_texts": hidden_texts,
            }
        )

    for t_idx, table in enumerate(doc.tables, start=1):
        table_lines: list[str] = []
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells if c.text.strip()]
            if cells:
                table_lines.append(" | ".join(cells))
        if table_lines:
            joined = "\n".join(table_lines)
            parts.append(joined)
            segments.append(
                {
                    "text": joined,
                    "location": f"Table {t_idx}",
                    "hidden_findings": [],
                    "hidden_texts": [],
                }
            )

    comments = _extract_docx_comments(data)
    if comments:
        comment_text = "\n".join(comments)
        parts.append(comment_text)
        hidden_findings = [
            {
                "rule": "docx_comment",
                "detail": "DOCX contains embedded review comment text.",
                "location": "DOCX Comments",
                "snippet": make_masked_snippet(c),
            }
            for c in comments
        ]
        total_hidden += len(hidden_findings)
        segments.append(
            {
                "text": comment_text,
                "location": "DOCX Comments",
                "hidden_findings": hidden_findings,
                "hidden_texts": comments,
            }
        )

    metadata = {
        "paragraph_count": len(doc.paragraphs),
        "table_count": len(doc.tables),
        "comment_count": len(comments),
        "hidden_signal_count": total_hidden,
    }
    return "\n\n".join(parts), metadata, segments


def _check_inline_hidden_style(style_attr: str) -> list[tuple[str, str]]:
    style = style_attr.lower()
    hits: list[tuple[str, str]] = []
    if re.search(r"display\s*:\s*none", style):
        hits.append(("html_display_none", "HTML element styled with display:none."))
    if re.search(r"visibility\s*:\s*hidden", style):
        hits.append(("html_visibility_hidden", "HTML element styled with visibility:hidden."))
    if re.search(r"opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)", style):
        hits.append(("html_opacity_zero", "HTML element styled with opacity:0."))
    font_match = re.search(r"font-size\s*:\s*([0-9.]+)\s*(px|pt|em|rem)?", style)
    if font_match and float(font_match.group(1)) <= 1.5:
        hits.append(("html_zero_size_text", f"HTML element has near-zero font-size ({font_match.group(0)})."))
    if re.search(r"(?:^|;)\s*color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", style):
        hits.append(("html_white_text", "HTML element uses white text color."))
    return hits


def extract_html_with_hidden(html_text: str, source_label: str = "HTML") -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    """Extract visible and hidden HTML elements/comments using BeautifulSoup."""
    soup = BeautifulSoup(html_text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    segments: list[dict[str, Any]] = []
    all_texts: list[str] = []
    total_hidden = 0

    comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment)) if str(c).strip()]
    for idx, c_text in enumerate(comments, start=1):
        location = f"{source_label} Comment #{idx}"
        total_hidden += 1
        all_texts.append(c_text)
        segments.append(
            {
                "text": c_text,
                "location": location,
                "hidden_findings": [
                    {
                        "rule": "html_comment",
                        "detail": "HTML comment contains hidden text.",
                        "location": location,
                        "snippet": make_masked_snippet(c_text),
                    }
                ],
                "hidden_texts": [c_text],
            }
        )

    hidden_elements: list[tuple[Any, list[tuple[str, str]]]] = []
    for el in soup.find_all(True):
        reasons: list[tuple[str, str]] = []
        if el.has_attr("hidden"):
            reasons.append(("html_hidden_attr", f"HTML <{el.name}> has hidden attribute."))
        style_attr = el.get("style") or ""
        if isinstance(style_attr, str) and style_attr.strip():
            reasons.extend(_check_inline_hidden_style(style_attr))
        if reasons:
            hidden_elements.append((el, reasons))

    hidden_texts_recorded: list[str] = []
    for idx, (el, reasons) in enumerate(hidden_elements, start=1):
        el_text = " ".join(el.get_text(" ", strip=True).split())
        if not el_text:
            el.decompose()
            continue
        location = f"{source_label} Hidden <{el.name}> #{idx}"
        hidden_findings = [
            {
                "rule": rule,
                "detail": detail,
                "location": location,
                "snippet": make_masked_snippet(el_text),
            }
            for rule, detail in reasons
        ]
        total_hidden += len(hidden_findings)
        all_texts.append(el_text)
        hidden_texts_recorded.append(el_text)
        segments.append(
            {
                "text": el_text,
                "location": location,
                "hidden_findings": hidden_findings,
                "hidden_texts": [el_text],
            }
        )
        el.decompose()

    # Remove comments before collecting remaining visible body text
    for c_node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        c_node.extract()

    visible_text = " ".join(soup.get_text(" ", strip=True).split())
    if visible_text:
        all_texts.insert(0, visible_text)
        segments.insert(
            0,
            {
                "text": visible_text,
                "location": f"{source_label} Visible Body",
                "hidden_findings": [],
                "hidden_texts": [],
            },
        )

    metadata = {"hidden_signal_count": total_hidden, "hidden_element_count": len(hidden_texts_recorded)}
    return "\n\n".join(all_texts), metadata, segments


def scan(chunk: Any, enable_hidden_text: bool = True) -> ScanResult:
    """
    Scan a chunk (Chunk object or plain string) for prompt-injection patterns and hidden text.

    Returns ScanResult(risk_score 0-100, findings, action='safe'|'quarantine', framework_tags).
    """
    if isinstance(chunk, str):
        text = chunk
        metadata: dict[str, Any] = {}
        location = "Query / Text"
    else:
        text = getattr(chunk, "text", "") or ""
        metadata = getattr(chunk, "metadata", {}) or {}
        location = metadata.get("location") or getattr(chunk, "chunk_id", "Document Chunk")

    findings: list[Finding] = []

    if enable_hidden_text:
        # 1. Hidden-text signals attached during PDF/DOCX/HTML extraction
        for hf in metadata.get("hidden_findings", []):
            findings.append(
                Finding(
                    category="hidden_text",
                    rule=str(hf.get("rule", "hidden_text")),
                    detail=str(hf.get("detail", "Hidden text detected.")),
                    location=str(hf.get("location", location)),
                    evidence_snippet=str(hf.get("snippet") or make_masked_snippet(text)),
                    severity_points=60,
                )
            )

        # 2. TXT / raw string zero-width or unusual Unicode hidden characters
        findings.extend(detect_txt_hidden_unicode(text, location=location))

    # 3. Prompt injection regex/keyword matching across chunk text (and hidden texts when enabled)
    search_targets: list[tuple[str, str]] = [(location, text)]
    if enable_hidden_text:
        for h_txt in metadata.get("hidden_texts", []):
            if h_txt and h_txt not in text:
                search_targets.append((location, h_txt))

    seen_rules: set[str] = set()
    for target_loc, target_text in search_targets:
        for rule_name, compiled in _COMPILED_INJECTIONS:
            if rule_name in seen_rules:
                continue
            match = compiled.search(target_text)
            if match:
                seen_rules.add(rule_name)
                findings.append(
                    Finding(
                        category="prompt_injection",
                        rule=rule_name,
                        detail=f"Matched prompt-injection pattern '{match.group(0)}'.",
                        location=target_loc,
                        evidence_snippet=make_masked_snippet(target_text),
                        severity_points=70,
                    )
                )

    hidden_count = sum(1 for f in findings if f.category == "hidden_text")
    injection_count = sum(1 for f in findings if f.category == "prompt_injection")
    has_hidden_text = hidden_count > 0
    has_injection = injection_count > 0

    if has_hidden_text and has_injection:
        risk_score = min(100, 95 + 5 * (injection_count - 1))
        action = "quarantine"
    elif has_injection:
        risk_score = min(90, 70 + 10 * (injection_count - 1))
        action = "quarantine"
    elif has_hidden_text:
        risk_score = min(85, 60 + 5 * (hidden_count - 1))
        action = "safe"
    else:
        risk_score = 0
        action = "safe"

    categories = sorted({f.category for f in findings})
    framework_tags = get_framework_tags(categories)

    return ScanResult(
        risk_score=risk_score,
        findings=findings,
        action=action,
        framework_tags=framework_tags,
        has_hidden_text=has_hidden_text,
        has_injection=has_injection,
    )
