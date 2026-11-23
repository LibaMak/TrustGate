from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from shield import FINDING_TYPES, AuditLogger, extract_control_breakdowns


def render_dashboard(
    audit_logger: AuditLogger,
    shield_enabled: bool,
    results_dir: Any = None,
) -> None:
    """Render the Security Dashboard tab backed strictly by live SQLite audit logs."""
    _ = results_dir
    if not shield_enabled:
        st.error(
            "⚠️ **Protection disabled, Govern control weak** — "
            "TrustGate Shield is currently OFF. Enable the Shield toggle in the sidebar to enforce "
            "OWASP LLM Top 10, NIST AI RMF, and NIST CSF controls."
        )

    stats = audit_logger.get_dashboard_stats()
    all_findings: list[dict[str, Any]] = stats["all_findings"]
    logged_sources = audit_logger.get_logged_sources()

    # 1. Top KPI Metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Chunks Scanned", stats["total_chunks_scanned"])
    c2.metric("Blocked", stats["blocked_chunks"])
    c3.metric("Allowed", stats["allowed_chunks"])
    c4.metric("PII Items Masked", stats["pii_items_masked"])
    c5.metric("Sensitive Queries Flagged", stats["sensitive_queries_flagged"])

    st.divider()

    # 2. Bar Charts: Blocked vs Allowed & Findings by Type
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("Blocked vs Allowed Chunks")
        ba_df = pd.DataFrame(
            {
                "Status": ["Blocked", "Allowed"],
                "Chunks": [stats["blocked_chunks"], stats["allowed_chunks"]],
            }
        ).set_index("Status")
        st.bar_chart(ba_df)

    with chart_col2:
        st.subheader("Findings by Type")
        ft_counts = stats["findings_by_type"]
        ft_df = pd.DataFrame(
            {
                "Finding Type": list(FINDING_TYPES),
                "Count": [ft_counts.get(ft, 0) for ft in FINDING_TYPES],
            }
        ).set_index("Finding Type")
        st.bar_chart(ft_df)

    # 3. Bar Chart: Violations by Framework Control (NIST AI RMF, NIST CSF, OWASP)
    st.subheader("Violations by Framework Control")
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
        st.caption("NIST AI RMF Function")
        if rmf_counts:
            st.bar_chart(pd.DataFrame({"Violations": rmf_counts}))
        else:
            st.info("No NIST AI RMF violations logged yet.")
    with fw_c2:
        st.caption("NIST CSF Category")
        if csf_counts:
            st.bar_chart(pd.DataFrame({"Violations": csf_counts}))
        else:
            st.info("No NIST CSF violations logged yet.")
    with fw_c3:
        st.caption("OWASP LLM Top 10 ID")
        if owasp_counts:
            st.bar_chart(pd.DataFrame({"Violations": owasp_counts}))
        else:
            st.info("No OWASP violations logged yet.")

    st.divider()

    # 4. Detections per File Format Table
    st.subheader("Detections per File Format")
    fmt_df = pd.DataFrame(stats["format_table"])
    st.dataframe(fmt_df, use_container_width=True, hide_index=True)

    st.divider()

    # 5. Manage Past Document Logs & Filtered Audit Log Table (masked snippet only)
    st.subheader("SQLite Audit Log (Masked Snippets Only)")

    if logged_sources or all_findings:
        m_col1, m_col2, m_col3 = st.columns([3, 1.3, 1.2])
        with m_col1:
            selected_source = st.selectbox(
                "Remove logs for a past document",
                options=logged_sources if logged_sources else ["(none)"],
                disabled=not logged_sources,
                label_visibility="collapsed",
                key="dash_delete_source_select",
            )
        with m_col2:
            if st.button(
                "Delete Document Log",
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
        st.info("No audit findings logged. Upload and scan documents in the Chat & Documents tab.")
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
            "Filter by Finding Type",
            options=available_types,
            default=available_types,
            key="dash_filter_type",
        )

    filtered = [
        {
            "time": r["timestamp"][:19].replace("T", " "),
            "source": r["source"],
            "location": r["location"],
            "finding_type": r["finding_type"],
            "risk_score": r["risk_score"],
            "action": r["action"],
            "masked_snippet": r["masked_snippet"],
        }
        for r in all_findings
        if str(r["action"]) in selected_actions and str(r["finding_type"]) in selected_types
    ]
    st.dataframe(pd.DataFrame(filtered), use_container_width=True, hide_index=True)
