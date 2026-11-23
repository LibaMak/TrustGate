from __future__ import annotations

import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shield.scanner import (
    extract_docx_with_hidden,
    extract_html_with_hidden,
    extract_pdf_with_hidden,
)

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".md", ".html", ".htm"}


@dataclass
class Document:
    source: str
    file_type: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    segments: list[dict[str, Any]] = field(default_factory=list)


def _extract_text_bytes(data: bytes) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    text = data.decode("utf-8", errors="replace").strip()
    segments = (
        [
            {
                "text": text,
                "location": "Text Document",
                "hidden_findings": [],
                "hidden_texts": [],
            }
        ]
        if text
        else []
    )
    return text, {"char_count": len(text)}, segments


def load_uploaded_file(name: str, data: bytes) -> Document:
    ext = Path(name).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{ext}' for '{name}'. "
            f"Supported types: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )

    if ext == ".pdf":
        content, metadata, segments = extract_pdf_with_hidden(data)
    elif ext == ".docx":
        content, metadata, segments = extract_docx_with_hidden(data)
    elif ext in {".html", ".htm"}:
        html_str = data.decode("utf-8", errors="replace")
        content, metadata, segments = extract_html_with_hidden(html_str, source_label="HTML")
    else:
        content, metadata, segments = _extract_text_bytes(data)

    return Document(
        source=Path(name).name,
        file_type=ext.lstrip("."),
        content=content,
        metadata=metadata,
        segments=segments,
    )


def load_file(path: str | Path) -> Document:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    doc = load_uploaded_file(file_path.name, file_path.read_bytes())
    doc.metadata["path"] = str(file_path)
    return doc


def load_url(url: str, timeout: int = 10) -> Document:
    """Fetch a web page URL and extract visible + hidden HTML content."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TrustGate/0.2 (+https://localhost)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw_bytes = resp.read()
        charset = resp.headers.get_content_charset() or "utf-8"
    html_str = raw_bytes.decode(charset, errors="replace")
    content, metadata, segments = extract_html_with_hidden(html_str, source_label="URL")
    metadata["url"] = url
    return Document(
        source=url,
        file_type="url",
        content=content,
        metadata=metadata,
        segments=segments,
    )
