from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from shield.pii import make_masked_snippet, mask_all_pii

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "trustgate_audit.db"

FINDING_TYPES = (
    "prompt_injection",
    "hidden_text",
    "pii_leak",
    "secret_exposed",
    "sensitive_query",
)


def _derive_finding_type(event_type: str, categories: list[str]) -> str:
    cat_set = set(categories)
    if event_type in {"sensitive_query_refusal", "sensitive_query_warning"} or "sensitive_query" in cat_set:
        return "sensitive_query"
    if "prompt_injection" in cat_set or event_type == "query_block":
        return "prompt_injection"
    if "hidden_text" in cat_set:
        return "hidden_text"
    if "secret_exposed" in cat_set:
        return "secret_exposed"
    if "pii_leak" in cat_set or "pii_high_risk" in cat_set or "pii_contact" in cat_set:
        return "pii_leak"
    if "strict_block" in cat_set:
        return "prompt_injection"
    return "prompt_injection"


class AuditLogger:
    """SQLite audit logger storing only masked snippets (never raw PII or full chunks)."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS shield_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    location TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    categories TEXT NOT NULL,
                    framework_tags TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    masked_snippet TEXT NOT NULL,
                    file_format TEXT NOT NULL DEFAULT 'UNKNOWN',
                    finding_type TEXT NOT NULL DEFAULT 'prompt_injection',
                    pii_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            existing_cols = {
                row["name"] for row in conn.execute("PRAGMA table_info(shield_findings)").fetchall()
            }
            if "file_format" not in existing_cols:
                conn.execute(
                    "ALTER TABLE shield_findings ADD COLUMN file_format TEXT NOT NULL DEFAULT 'UNKNOWN'"
                )
            if "finding_type" not in existing_cols:
                conn.execute(
                    "ALTER TABLE shield_findings ADD COLUMN finding_type TEXT NOT NULL DEFAULT 'prompt_injection'"
                )
            if "pii_count" not in existing_cols:
                conn.execute(
                    "ALTER TABLE shield_findings ADD COLUMN pii_count INTEGER NOT NULL DEFAULT 0"
                )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS chunk_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    file_format TEXT NOT NULL,
                    location TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    pii_masked_count INTEGER NOT NULL DEFAULT 0
                )
                """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS document_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    file_format TEXT NOT NULL,
                    total_chars INTEGER NOT NULL,
                    removed_chars INTEGER NOT NULL,
                    removed_pct REAL NOT NULL,
                    flagged_pct REAL NOT NULL,
                    policy_action TEXT NOT NULL,
                    sensitive_items_masked INTEGER NOT NULL DEFAULT 0,
                    pii_breakdown TEXT NOT NULL DEFAULT '{}'
                )
                """
            )

    def log_finding(
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
        snippet = make_masked_snippet(raw_text, max_len=160)
        safe_reason, _ = mask_all_pii(reason)
        ts = datetime.now(timezone.utc).isoformat()
        resolved_type = finding_type or _derive_finding_type(event_type, categories)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO shield_findings (
                    timestamp, event_type, source, location, risk_score,
                    action, categories, framework_tags, reason, masked_snippet,
                    file_format, finding_type, pii_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    event_type,
                    source,
                    location,
                    int(risk_score),
                    action,
                    json.dumps(categories),
                    json.dumps(framework_tags),
                    safe_reason,
                    snippet,
                    file_format.upper(),
                    resolved_type,
                    int(pii_count),
                ),
            )

    def log_chunk_scan(
        self,
        *,
        source: str,
        file_format: str,
        location: str,
        risk_score: int,
        action: str,
        pii_masked_count: int = 0,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO chunk_scans (
                    timestamp, source, file_format, location, risk_score, action, pii_masked_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    source,
                    file_format.upper(),
                    location,
                    int(risk_score),
                    action,
                    int(pii_masked_count),
                ),
            )

    def log_document_scan(
        self,
        *,
        source: str,
        file_format: str,
        total_chars: int,
        removed_chars: int,
        removed_pct: float,
        flagged_pct: float,
        policy_action: str,
        sensitive_items_masked: int,
        pii_breakdown: dict[str, int],
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO document_scans (
                    timestamp, source, file_format, total_chars, removed_chars,
                    removed_pct, flagged_pct, policy_action, sensitive_items_masked, pii_breakdown
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    source,
                    file_format.upper(),
                    int(total_chars),
                    int(removed_chars),
                    float(removed_pct),
                    float(flagged_pct),
                    policy_action,
                    int(sensitive_items_masked),
                    json.dumps(pii_breakdown),
                ),
            )

    def get_recent_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, event_type, source, location, risk_score,
                       action, categories, framework_tags, reason, masked_snippet,
                       file_format, finding_type, pii_count
                FROM shield_findings
                ORDER BY id DESC
                LIMIT ?
                """,
                (max(int(limit), 1),),
            ).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["categories"] = json.loads(item["categories"])
            item["framework_tags"] = json.loads(item["framework_tags"])
            results.append(item)
        return results

    def get_dashboard_stats(self) -> dict[str, Any]:
        """Aggregate document-level percentages, PII breakdowns, format stats, and findings from SQLite."""
        with self._connect() as conn:
            scan_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_chunks,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked_chunks,
                    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) AS allowed_chunks,
                    COALESCE(SUM(pii_masked_count), 0) AS chunk_pii_masked
                FROM chunk_scans
                """
            ).fetchone()

            doc_rows = conn.execute(
                """
                SELECT source, file_format, total_chars, removed_chars, removed_pct,
                       flagged_pct, policy_action, sensitive_items_masked, pii_breakdown
                FROM document_scans
                """
            ).fetchall()

            output_pii_row = conn.execute(
                """
                SELECT COALESCE(SUM(pii_count), 0) AS output_pii_masked
                FROM shield_findings
                WHERE event_type = 'response_pii_mask'
                """
            ).fetchone()

            query_flag_row = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM shield_findings
                WHERE finding_type = 'sensitive_query'
                """
            ).fetchone()

            type_rows = conn.execute(
                """
                SELECT finding_type, COUNT(*) AS cnt
                FROM shield_findings
                GROUP BY finding_type
                """
            ).fetchall()

            format_finding_rows = conn.execute(
                """
                SELECT file_format, COUNT(*) AS detections
                FROM shield_findings
                GROUP BY file_format
                """
            ).fetchall()

            finding_rows = conn.execute(
                """
                SELECT id, timestamp, event_type, source, location, risk_score,
                       action, categories, framework_tags, reason, masked_snippet,
                       file_format, finding_type, pii_count
                FROM shield_findings
                ORDER BY id DESC
                """
            ).fetchall()

        findings_by_type: dict[str, int] = {ft: 0 for ft in FINDING_TYPES}
        for r in type_rows:
            ft = r["finding_type"]
            findings_by_type[ft] = int(r["cnt"])

        findings_per_format = {r["file_format"]: int(r["detections"]) for r in format_finding_rows}

        total_doc_chars = 0
        total_removed_chars = 0
        doc_pii_total = 0
        pii_masked_by_type: dict[str, int] = {}
        fmt_docs: dict[str, dict[str, Any]] = {}

        for dr in doc_rows:
            t_chars = int(dr["total_chars"] or 0)
            r_chars = int(dr["removed_chars"] or 0)
            masked_cnt = int(dr["sensitive_items_masked"] or 0)
            fmt = str(dr["file_format"] or "TXT").upper()

            total_doc_chars += t_chars
            total_removed_chars += r_chars
            doc_pii_total += masked_cnt

            breakdown = json.loads(dr["pii_breakdown"] or "{}")
            for k, v in breakdown.items():
                pii_masked_by_type[k] = pii_masked_by_type.get(k, 0) + int(v)

            entry = fmt_docs.setdefault(
                fmt,
                {"docs": 0, "total_chars": 0, "removed_chars": 0, "masked": 0},
            )
            entry["docs"] += 1
            entry["total_chars"] += t_chars
            entry["removed_chars"] += r_chars
            entry["masked"] += masked_cnt

        if doc_rows and total_doc_chars > 0:
            content_removed_pct = round(min(100.0, (total_removed_chars / total_doc_chars) * 100), 1)
            content_kept_pct = round(max(0.0, 100.0 - content_removed_pct), 1)
        else:
            content_removed_pct = 0.0
            content_kept_pct = 100.0 if doc_rows else 0.0

        format_metrics_table: list[dict[str, Any]] = []
        for fmt in ("PDF", "DOCX", "URL", "TXT"):
            info = fmt_docs.get(fmt, {"docs": 0, "total_chars": 0, "removed_chars": 0, "masked": 0})
            fmt_removed_pct = (
                round(min(100.0, (info["removed_chars"] / info["total_chars"]) * 100), 1)
                if info["total_chars"] > 0
                else 0.0
            )
            format_metrics_table.append(
                {
                    "File Format": fmt,
                    "Documents": info["docs"],
                    "Content Removed (%)": fmt_removed_pct,
                    "Sensitive Items Masked": info["masked"],
                    "Detections": findings_per_format.get(fmt, 0),
                }
            )

        total_pii_types = sum(pii_masked_by_type.values())
        pii_share_table: list[dict[str, Any]] = [
            {
                "Sensitive Type": ptype,
                "Count": cnt,
                "Share (%)": round((cnt / total_pii_types) * 100, 1) if total_pii_types else 0.0,
            }
            for ptype, cnt in sorted(pii_masked_by_type.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

        all_findings: list[dict[str, Any]] = []
        for row in finding_rows:
            item = dict(row)
            item["categories"] = json.loads(item["categories"])
            item["framework_tags"] = json.loads(item["framework_tags"])
            all_findings.append(item)

        out_pii = int((output_pii_row["output_pii_masked"] if output_pii_row else 0) or 0)
        chunk_pii = int((scan_row["chunk_pii_masked"] if scan_row else 0) or 0)
        total_sensitive_masked = (doc_pii_total if doc_rows else chunk_pii) + out_pii

        return {
            "documents_scanned": len(doc_rows),
            "content_removed_pct": content_removed_pct,
            "content_kept_pct": content_kept_pct,
            "sensitive_items_masked": total_sensitive_masked,
            "pii_masked_by_type": pii_masked_by_type,
            "pii_share_table": pii_share_table,
            "sensitive_queries_flagged": int((query_flag_row["cnt"] if query_flag_row else 0) or 0),
            "findings_by_type": findings_by_type,
            "format_table": format_metrics_table,
            "all_findings": all_findings,
            # Legacy keys kept for non-UI tests
            "total_chunks_scanned": int((scan_row["total_chunks"] if scan_row else 0) or 0),
            "blocked_chunks": int((scan_row["blocked_chunks"] if scan_row else 0) or 0),
            "allowed_chunks": int((scan_row["allowed_chunks"] if scan_row else 0) or 0),
            "pii_items_masked": total_sensitive_masked,
        }

    def get_logged_sources(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT source FROM (
                    SELECT source FROM document_scans
                    UNION
                    SELECT source FROM chunk_scans
                    UNION
                    SELECT source FROM shield_findings
                )
                WHERE source IS NOT NULL AND source != ''
                ORDER BY source ASC
                """
            ).fetchall()
        return [str(r["source"]) for r in rows]

    def delete_by_source(self, source: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM shield_findings WHERE source = ?", (source,))
            conn.execute("DELETE FROM chunk_scans WHERE source = ?", (source,))
            conn.execute("DELETE FROM document_scans WHERE source = ?", (source,))

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM shield_findings").fetchone()
            return int(row["cnt"]) if row else 0

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM shield_findings")
            conn.execute("DELETE FROM chunk_scans")
            conn.execute("DELETE FROM document_scans")
