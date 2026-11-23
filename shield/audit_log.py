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
    """SQLite audit logger storing only masked snippets (never full chunks or raw PII)."""

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
        """Aggregate metrics, per-type counts, per-format detections, and audit rows from SQLite."""
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

            format_scan_rows = conn.execute(
                """
                SELECT
                    file_format,
                    COUNT(*) AS chunks_scanned,
                    SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) AS blocked,
                    SUM(CASE WHEN action = 'allowed' THEN 1 ELSE 0 END) AS allowed
                FROM chunk_scans
                GROUP BY file_format
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
        scans_per_format = {
            r["file_format"]: {
                "chunks_scanned": int(r["chunks_scanned"] or 0),
                "blocked": int(r["blocked"] or 0),
                "allowed": int(r["allowed"] or 0),
            }
            for r in format_scan_rows
        }

        format_table: list[dict[str, Any]] = []
        for fmt in ("PDF", "DOCX", "URL", "TXT"):
            scan_info = scans_per_format.get(fmt, {"chunks_scanned": 0, "blocked": 0, "allowed": 0})
            format_table.append(
                {
                    "File Format": fmt,
                    "Chunks Scanned": scan_info["chunks_scanned"],
                    "Blocked": scan_info["blocked"],
                    "Allowed": scan_info["allowed"],
                    "Detections": findings_per_format.get(fmt, 0),
                }
            )

        all_findings: list[dict[str, Any]] = []
        for row in finding_rows:
            item = dict(row)
            item["categories"] = json.loads(item["categories"])
            item["framework_tags"] = json.loads(item["framework_tags"])
            all_findings.append(item)

        chunk_pii = int((scan_row["chunk_pii_masked"] if scan_row else 0) or 0)
        out_pii = int((output_pii_row["output_pii_masked"] if output_pii_row else 0) or 0)

        return {
            "total_chunks_scanned": int((scan_row["total_chunks"] if scan_row else 0) or 0),
            "blocked_chunks": int((scan_row["blocked_chunks"] if scan_row else 0) or 0),
            "allowed_chunks": int((scan_row["allowed_chunks"] if scan_row else 0) or 0),
            "pii_items_masked": chunk_pii + out_pii,
            "sensitive_queries_flagged": int((query_flag_row["cnt"] if query_flag_row else 0) or 0),
            "findings_by_type": findings_by_type,
            "format_table": format_table,
            "all_findings": all_findings,
        }

    def get_logged_sources(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT source FROM (
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

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM shield_findings").fetchone()
            return int(row["cnt"]) if row else 0

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM shield_findings")
            conn.execute("DELETE FROM chunk_scans")
