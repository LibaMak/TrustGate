from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from shield import (
    FINDING_TYPES,
    AuditLogger,
    extract_control_breakdowns,
    format_clause_codes,
    risk_level_from_score,
)


def render_dashboard(
    audit_logger: AuditLogger,
    shield_enabled: bool,
    results_dir: Any = None,
) -> None:
    """Render the Security Dashboard page (no links, no chunks, no snippets)."""
    _ = results_dir
    if not shield_enabled:
        st.error(
            "⚠️ **Protection is OFF** — "
            "Turn Shield ON in the sidebar to block hidden instructions and mask private details."
        )

    stats = audit_logger.get_dashboard_stats()
    all_findings: list[dict[str, Any]] = stats["all_findings"]
    logged_sources = audit_logger.get_logged_sources()

    # 1. Single source of truth for KPI metrics (all-time SQLite totals)
    st.caption("All-time totals across uploaded files (use Clear All Logs below to reset).")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Files Scanned", stats["documents_scanned"])
    c2.metric("Unsafe Text Removed (%)", f"{stats['content_removed_pct']:.1f}%")
    c3.metric("Private Details Masked", stats["sensitive_items_masked"])
    c4.metric("Blocked Questions", stats["sensitive_queries_flagged"])

    st.divider()

    # 2. Separate Charts: Unsafe Text Removed (%) vs Private Details Masked
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("Safe vs Removed Content (%)")
        st.caption("Injection and hidden-text removals only (private details are masked, not removed).")
        rk_df = pd.DataFrame(
            {
                "Status": ["Removed (%)", "Kept (%)"],
                "Percentage": [stats["content_removed_pct"], stats["content_kept_pct"]],
            }
        ).set_index("Status")
        st.bar_chart(rk_df)

    with chart_col2:
        st.subheader("Private Details Masked")
        pii_share_rows = stats["pii_share_table"]
        if pii_share_rows:
            pii_df = pd.DataFrame(pii_share_rows)
            st.bar_chart(pii_df.set_index("Sensitive Type")[["Share (%)"]])
            st.dataframe(pii_df, use_container_width=True, hide_index=True)
        else:
            st.info("No private details masked yet.")

    st.divider()

    # 3. Issues by Category & Security Standards Triggered (no external links here)
    st.subheader("Issues by Category")
    ft_counts = stats["findings_by_type"]
    ft_df = pd.DataFrame(
        {
            "Issue Category": list(FINDING_TYPES),
            "Count": [ft_counts.get(ft, 0) for ft in FINDING_TYPES],
        }
    ).set_index("Issue Category")
    st.bar_chart(ft_df)

    st.subheader("Security Standards Triggered")
    rmf_counts: dict[str, int] = {}
    csf_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}

    for row in all_findings:
        bd = extract_control_breakdowns(row.get("categories", []), row.get("framework_tags", []))
        for fn in bd["nist_ai_rmf"]:
            rmf_counts[fn] = rmf_counts.get(fn, 0) + 1
        for cat in bd["nist_csf"]:
            csf_counts[cat] = csf_counts.get(cat, 0) + 1
        for oid in bd["owasp"]:
            owasp_counts[oid] = owasp_counts.get(oid, 0) + 1

    fw_c1, fw_c2, fw_c3 = st.columns(3)
    with fw_c1:
        st.caption("NIST AI RMF")
        if rmf_counts:
            st.bar_chart(pd.DataFrame({"Count": rmf_counts}))
        else:
            st.info("No entries yet.")
    with fw_c2:
        st.caption("NIST CSF 2.0")
        if csf_counts:
            st.bar_chart(pd.DataFrame({"Count": csf_counts}))
        else:
            st.info("No entries yet.")
    with fw_c3:
        st.caption("OWASP Top 10")
        if owasp_counts:
            st.bar_chart(pd.DataFrame({"Count": owasp_counts}))
        else:
            st.info("No entries yet.")

    st.divider()

    # 4. Results by File Type
    st.subheader("Results by File Type")
    fmt_df = pd.DataFrame(stats["format_table"])
    st.dataframe(fmt_df, use_container_width=True, hide_index=True)

    st.divider()

    # 5. Activity Log (metadata only — no snippets, no links)
    st.subheader("Activity Log")

    if logged_sources or all_findings:
        m_col1, m_col2, m_col3 = st.columns([3, 1.3, 1.2])
        with m_col1:
            selected_source = st.selectbox(
                "Remove logs for a past file",
                options=logged_sources if logged_sources else ["(none)"],
                disabled=not logged_sources,
                label_visibility="collapsed",
                key="dash_delete_source_select",
            )
        with m_col2:
            if st.button(
                "Delete File Log",
                key="dash_delete_source_btn",
                use_container_width=True,
                disabled=not logged_sources,
            ):
                audit_logger.delete_by_source(selected_source)
                st.rerun()
        with m_col3:
            if st.button("Clear All Logs", key="dash_clear_log", use_container_width=True):
                audit_logger.clear()
                st.rerun()

    if not all_findings:
        st.info("No activity logged yet. Upload files on the Chat & Documents page.")
        return

    available_actions = sorted({str(r["action"]) for r in all_findings})
    available_types = sorted({str(r["finding_type"]) for r in all_findings})

    f_col1, f_col2 = st.columns(2)
    with f_col1:
        selected_actions = st.multiselect(
            "Filter by Action",
            options=available_actions,
            default=available_actions,
            key="dash_filter_action",
        )
    with f_col2:
        selected_types = st.multiselect(
            "Filter by Issue Type",
            options=available_types,
            default=available_types,
            key="dash_filter_type",
        )

    filtered = [
        {
            "time": r["timestamp"][:19].replace("T", " "),
            "source": r["source"],
            "issue_type": r["finding_type"],
            "risk_level": risk_level_from_score(r["risk_score"]),
            "action": r["action"],
            "standards": format_clause_codes(r.get("categories", []), r.get("framework_tags", [])),
        }
        for r in all_findings
        if str(r["action"]) in selected_actions and str(r["finding_type"]) in selected_types
    ]
    st.dataframe(pd.DataFrame(filtered), use_container_width=True, hide_index=True)
