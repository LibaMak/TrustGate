from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from rag.loader import Document

# Normalize horizontal whitespace while preserving line breaks and zero-width/bidi/tag Unicode
# characters so line-level sanitization and TXT hidden-character detection both work cleanly.
_HORIZ_WS_RE = re.compile(r"[ \t\f\v]+")
_MULTI_NL_RE = re.compile(r"\n{3,}")


def _clean_preserve_lines(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [_HORIZ_WS_RE.sub(" ", line).strip() for line in normalized.split("\n")]
    joined = "\n".join(lines).strip()
    return _MULTI_NL_RE.sub("\n\n", joined)


@dataclass
class Chunk:
    chunk_id: str
    source: str
    index: int
    text: str
    metadata: dict[str, Any] = field(default_factory=dict)


def chunk_text(
    text: str,
    chunk_size: int = 500,
    chunk_overlap: int = 100,
) -> list[str]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive.")
    if chunk_overlap < 0:
        raise ValueError("chunk_overlap cannot be negative.")
    if chunk_overlap >= chunk_size:
        raise ValueError("chunk_overlap must be smaller than chunk_size.")

    cleaned = _clean_preserve_lines(text)
    if not cleaned:
        return []

    if len(cleaned) <= chunk_size:
        return [cleaned]

    chunks: list[str] = []
    start = 0
    text_len = len(cleaned)

    while start < text_len:
        end = min(start + chunk_size, text_len)
        if end < text_len:
            nl_at = cleaned.rfind("\n", start + chunk_size // 2, end)
            if nl_at != -1:
                end = nl_at + 1
            else:
                split_at = cleaned.rfind(". ", start + chunk_size // 2, end)
                if split_at != -1:
                    end = split_at + 1
                else:
                    space_at = cleaned.rfind(" ", start + chunk_size // 2, end)
                    if space_at != -1:
                        end = space_at

        piece = cleaned[start:end].strip()
        if piece:
            chunks.append(piece)

        if end >= text_len:
            break

        next_start = max(end - chunk_overlap, start + 1)
        start = next_start

    return chunks


def chunk_document(
    doc: Document,
    chunk_size: int = 500,
    chunk_overlap: int = 100,
) -> list[Chunk]:
    chunks: list[Chunk] = []
    chunk_idx = 0

    if doc.segments:
        for seg in doc.segments:
            seg_text = str(seg.get("text", "")).strip()
            if not seg_text:
                continue
            pieces = chunk_text(seg_text, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
            seg_meta = {
                "file_type": doc.file_type,
                "location": seg.get("location", doc.source),
                "hidden_findings": list(seg.get("hidden_findings", [])),
                "hidden_texts": list(seg.get("hidden_texts", [])),
            }
            for piece in pieces:
                chunks.append(
                    Chunk(
                        chunk_id=f"{doc.source}#chunk-{chunk_idx}",
                        source=doc.source,
                        index=chunk_idx,
                        text=piece,
                        metadata=dict(seg_meta),
                    )
                )
                chunk_idx += 1
        if chunks:
            return chunks

    pieces = chunk_text(doc.content, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    return [
        Chunk(
            chunk_id=f"{doc.source}#chunk-{idx}",
            source=doc.source,
            index=idx,
            text=piece,
            metadata={"file_type": doc.file_type, "location": doc.source, **doc.metadata},
        )
        for idx, piece in enumerate(pieces)
    ]
