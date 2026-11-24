from __future__ import annotations

import importlib
from typing import Any

import streamlit as st

import config
import dashboard
import rag.llm as llm_mod
import shield as shield_pkg
import shield.audit_log as audit_log_mod
import shield.control_map as control_map_mod
import shield.engine as engine_mod

importlib.reload(config)
importlib.reload(llm_mod)
importlib.reload(control_map_mod)
importlib.reload(audit_log_mod)
importlib.reload(engine_mod)
importlib.reload(shield_pkg)

CHUNK_OVERLAP = config.CHUNK_OVERLAP
CHUNK_SIZE = config.CHUNK_SIZE
TOP_K = config.TOP_K
get_settings = config.get_settings

AI_UNAVAILABLE_MESSAGE = llm_mod.AI_UNAVAILABLE_MESSAGE
BaseLLM = llm_mod.BaseLLM
build_llm = llm_mod.build_llm

format_clause_codes = control_map_mod.format_clause_codes
format_clause_links_md = control_map_mod.format_clause_links_md
risk_level_from_score = control_map_mod.risk_level_from_score

from rag.loader import Document, load_uploaded_file, load_url
from rag.pipeline import IngestionReport, PreparedQuery, RAGPipeline

st.set_page_config(
    page_title="TrustGate — Safe Document Q&A",
    page_icon="🛡️",
    layout="wide",
)


def _init_state() -> None:
    defaults = {
        "documents": [],
        "history": [],
        "pipeline": None,
        "ingestion_report": None,
        "ingest_signature": None,
        "shield_enabled": True,
        "pending_preview": None,
        "uploader_key": 0,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _sync_pipeline(
    docs: list[Document],
    llm: BaseLLM,
    shield_enabled: bool,
    audit_logger: Any,
) -> tuple[RAGPipeline, IngestionReport | None]:
    signature = (
        tuple((d.source, len(d.content)) for d in docs),
        shield_enabled,
        CHUNK_SIZE,
        CHUNK_OVERLAP,
    )
    existing: RAGPipeline | None = st.session_state.pipeline
    if existing is not None and st.session_state.ingest_signature == signature:
        existing.llm = llm
        existing.top_k = TOP_K
        return existing, st.session_state.ingestion_report

    shield = engine_mod.TrustGateShield(enabled=shield_enabled, audit_logger=audit_logger)
    pipeline = RAGPipeline(
        llm=llm,
        shield=shield,
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        top_k=TOP_K,
    )
    report: IngestionReport | None = None
    if docs:
        report = pipeline.ingest_documents(docs, replace=True)
    st.session_state.pipeline = pipeline
    st.session_state.ingestion_report = report
    st.session_state.ingest_signature = signature
    return pipeline, report


def _unique_source_citations(items: list[Any]) -> list[str]:
    """Return deduplicated 'filename — Page/Section' citations with zero chunk IDs."""
    seen: list[str] = []
    for item in items:
        chunk = getattr(item, "chunk", item)
        source = getattr(chunk, "source", "Document")
        loc = (getattr(chunk, "metadata", {}) or {}).get("location", "Document")
        label = f"**{source}** — {loc}"
        if label not in seen:
            seen.append(label)
    return seen


def _render_upload_and_warning_cards(report: IngestionReport | None, shield_enabled: bool) -> None:
    if report is None or not report.document_summaries:
        return

    for s in report.document_summaries:
        line = s.upload_status_line or "Safe: 100% content kept | 0 sensitive items masked"
        if s.policy_action == "strict_block":
            st.error(f"**{s.source}** — {line}")
        elif s.policy_action == "sanitize":
            st.warning(f"**{s.source}** — {line}")
        else:
            st.success(f"**{s.source}** — {line}")

    if not shield_enabled:
        return

    for s in report.document_summaries:
        if s.policy_action == "strict_block":
            ftype = "prompt_injection" if any(f.category == "prompt_injection" for f in s.findings) else "hidden_text"
            risk_lvl = risk_level_from_score(s.max_risk_score)
            clauses_md = format_clause_links_md(framework_tags=s.framework_tags)
            st.error(
                f"**{s.source}** · **Issue:** `{ftype}` · "
                f"**Location:** `Entire Document` · **Risk:** `{risk_lvl}` · "
                f"**Action:** `Blocked ({s.flagged_pct:.0f}% flagged)`\n\n"
                f"**Standards:** {clauses_md}"
            )

    if report.quarantined_items:
        with st.expander(f"Issues Found ({len(report.quarantined_items)})", expanded=True):
            for item in report.quarantined_items:
                risk_lvl = risk_level_from_score(item.risk_score)
                clauses_md = format_clause_links_md(framework_tags=item.framework_tags)
                st.markdown(
                    f"- **{item.source}** · **Issue:** `{item.finding_type}` · "
                    f"**Location:** `{item.location}` · **Risk:** `{risk_lvl}` · "
                    f"**Action:** `{item.action}`\n"
                    f"  - **Standards:** {clauses_md}"
                )


def _complete_or_record_error(pipeline: RAGPipeline, prepared: PreparedQuery) -> dict[str, Any]:
    """Run LLM generation on prepared context; never silently fall back to Mock on error."""
    sources = _unique_source_citations(prepared.retrieved_chunks)
    try:
        response = pipeline.complete_ask(prepared)
        return {
            "query": response.query,
            "answer": response.answer,
            "llm_name": response.llm_name,
            "sources": _unique_source_citations(response.retrieved_chunks),
            "verdicts": response.shield_verdicts,
            "ai_error": False,
        }
    except Exception:
        return {
            "query": prepared.query,
            "answer": AI_UNAVAILABLE_MESSAGE,
            "llm_name": pipeline.llm.name,
            "sources": sources,
            "verdicts": prepared.shield_verdicts,
            "ai_error": True,
        }


def main() -> None:
    _init_state()
    importlib.reload(control_map_mod)
    importlib.reload(audit_log_mod)
    importlib.reload(engine_mod)
    importlib.reload(shield_pkg)
    importlib.reload(dashboard)
    settings = get_settings()
    audit_logger = audit_log_mod.AuditLogger()

    st.title("🛡️ TrustGate")
    st.caption("Safe document Q&A — removes hidden instructions and masks private details.")

    with st.sidebar:
        st.header("Protection")
        shield_enabled = st.toggle(
            "Shield (ON / OFF)",
            value=st.session_state.shield_enabled,
            help="Turn protection ON to block hidden instructions and mask private details.",
        )
        st.session_state.shield_enabled = shield_enabled

        st.subheader("Status")
        if shield_enabled:
            st.success(
                "**Protection ON**\n\n"
                "- Hidden-text & injection check: Active\n"
                "- Private details masking: Active\n"
                "- Sensitive question guard: Active"
            )
        else:
            st.error(
                "**Protection OFF**\n\n"
                "Scanning and masking are currently disabled."
            )

        st.divider()
        st.subheader("Upload Documents")
        uploaded_files = st.file_uploader(
            "Choose PDF, DOCX, TXT, or HTML files",
            type=["pdf", "docx", "txt", "md", "html", "htm"],
            accept_multiple_files=True,
            key=f"file_uploader_{st.session_state.uploader_key}",
        )

        upload_mode = st.radio(
            "Upload Mode",
            options=["Replace current", "Add to current"],
            horizontal=True,
            label_visibility="collapsed",
        )

        if st.button("Scan & Load Files", use_container_width=True, disabled=not uploaded_files):
            try:
                loaded = [load_uploaded_file(f.name, f.getvalue()) for f in uploaded_files]
                if upload_mode == "Add to current" and st.session_state.documents:
                    existing_by_name = {d.source: d for d in st.session_state.documents}
                    for doc in loaded:
                        existing_by_name[doc.source] = doc
                    st.session_state.documents = list(existing_by_name.values())
                else:
                    st.session_state.documents = loaded
                    st.session_state.history = []
                st.session_state.pending_preview = None
                st.session_state.ingest_signature = None
                st.session_state.uploader_key += 1
                st.rerun()
            except Exception as exc:
                st.error(f"Failed to load uploads: {exc}")

        with st.expander("Add from Website", expanded=False):
            url_input = st.text_input("Website URL", placeholder="https://example.com")
            if st.button("Load Website", use_container_width=True, disabled=not url_input.strip()):
                try:
                    doc = load_url(url_input.strip())
                    if upload_mode == "Add to current" and st.session_state.documents:
                        existing_by_name = {d.source: d for d in st.session_state.documents}
                        existing_by_name[doc.source] = doc
                        st.session_state.documents = list(existing_by_name.values())
                    else:
                        st.session_state.documents = [doc]
                        st.session_state.history = []
                    st.session_state.pending_preview = None
                    st.session_state.ingest_signature = None
                    st.rerun()
                except Exception as exc:
                    st.error(f"Failed to load website: {exc}")

        if st.session_state.documents:
            st.caption(f"Loaded Files ({len(st.session_state.documents)})")
            for idx, doc in enumerate(st.session_state.documents):
                col_name, col_rm = st.columns([5, 1])
                with col_name:
                    st.markdown(f"`{doc.source}`")
                with col_rm:
                    if st.button("✕", key=f"rm_doc_{idx}_{doc.source}", help=f"Remove {doc.source}"):
                        st.session_state.documents = [
                            d for i, d in enumerate(st.session_state.documents) if i != idx
                        ]
                        st.session_state.pending_preview = None
                        st.session_state.ingest_signature = None
                        if not st.session_state.documents:
                            st.session_state.pipeline = None
                            st.session_state.ingestion_report = None
                        st.rerun()

            if st.button("Clear All Files", use_container_width=True):
                st.session_state.documents = []
                st.session_state.history = []
                st.session_state.pending_preview = None
                st.session_state.pipeline = None
                st.session_state.ingestion_report = None
                st.session_state.ingest_signature = None
                st.session_state.uploader_key += 1
                st.rerun()

    active_llm, llm_notice = build_llm(settings)

    pipeline, report = _sync_pipeline(
        docs=st.session_state.documents,
        llm=active_llm,
        shield_enabled=shield_enabled,
        audit_logger=audit_logger,
    )

    if not shield_enabled:
        st.error("⚠️ **Protection is OFF** — Turn Shield ON in the sidebar.")

    if llm_notice:
        st.warning(f"{llm_notice} Security checks and masking remain active.")

    page_choice = st.segmented_control(
        "View",
        options=["Chat & Documents", "Dashboard"],
        default="Chat & Documents",
        label_visibility="collapsed",
    )
    active_page = page_choice or "Chat & Documents"

    if active_page == "Dashboard":
        dashboard.render_dashboard(audit_logger, shield_enabled)
        return

    # ---------------- Chat & Documents Page ----------------
    if settings.llm_mode == "cloud":
        st.info(
            "Cloud Mode Notice: Text is sent to an external API after redaction. "
            "Do not upload highly confidential documents."
        )

    _render_upload_and_warning_cards(report, shield_enabled)

    st.divider()
    bar_title, bar_preview, bar_clear = st.columns([3.5, 1.8, 1.1])
    with bar_title:
        turns = len(st.session_state.history)
        turn_label = f"{turns} turn" if turns == 1 else f"{turns} turns"
        st.markdown(f"#### Ask a Question · `{turn_label}`")
    with bar_preview:
        preview_before_send = st.checkbox(
            "Review before sending",
            value=False,
            help="Check which sources will be sent before asking the AI.",
        )
    with bar_clear:
        if st.button(
            "Clear Chat",
            use_container_width=True,
            disabled=(not st.session_state.history and st.session_state.pending_preview is None),
        ):
            st.session_state.history = []
            st.session_state.pending_preview = None
            st.rerun()

    if not st.session_state.history and st.session_state.pending_preview is None:
        st.caption("Upload a file from the sidebar, then ask a question below.")

    for entry in st.session_state.history:
        with st.chat_message("user"):
            st.write(entry["query"])
        with st.chat_message("assistant"):
            for v in entry["verdicts"]:
                clauses_md = format_clause_links_md(framework_tags=v.framework_tags)
                risk_lvl = risk_level_from_score(v.risk_score)
                loc = v.location or "Chat Input"
                if v.stage == "query" and v.status in {"REFUSED_SENSITIVE_QUERY", "REFUSED_INJECTION"}:
                    ftype = "prompt_injection" if v.status == "REFUSED_INJECTION" else "sensitive_query"
                    st.error(
                        f"**Issue:** `{ftype}` · **Location:** `{loc}` · "
                        f"**Risk:** `{risk_lvl}` · **Action:** `Refused`\n\n"
                        f"**Standards:** {clauses_md}"
                    )
                elif v.stage == "query" and v.status == "WARN_CONTACT_QUERY":
                    st.warning(
                        f"**Issue:** `sensitive_query` · **Location:** `{loc}` · "
                        f"**Risk:** `{risk_lvl}` · **Action:** `Masked Output`\n\n"
                        f"**Standards:** {clauses_md}"
                    )
                elif v.stage == "response" and v.status == "MASKED_PII":
                    st.info(
                        f"**Issue:** `pii_leak` · **Location:** `Assistant Response` · "
                        f"**Risk:** `{risk_lvl}` · **Action:** `Masked Output`\n\n"
                        f"**Standards:** {clauses_md}"
                    )
            if entry.get("ai_error"):
                st.error(entry["answer"])
            else:
                st.write(entry["answer"])
            with st.expander("Sources & Check Details"):
                st.caption(f"Model: {entry['llm_name']}")
                for v in entry["verdicts"]:
                    codes = format_clause_codes(framework_tags=v.framework_tags)
                    risk_lvl = risk_level_from_score(v.risk_score)
                    loc = v.location or v.stage
                    st.markdown(
                        f"- `{v.stage}` · **Location:** `{loc}` · **Risk:** `{risk_lvl}` · "
                        f"**Action:** `{v.action}` · **Standards:** `{codes}`"
                    )
                if entry["sources"]:
                    st.markdown("**Sources:**")
                    for src_label in entry["sources"]:
                        st.markdown(f"- {src_label}")

    pending: PreparedQuery | None = st.session_state.pending_preview
    if pending is not None:
        with st.container(border=True):
            st.markdown("#### Review Before Sending")
            st.caption(f"AI Model: **{active_llm.name}** · Private details masked.")
            st.markdown(f"**Question:** {pending.query}")
            preview_sources = _unique_source_citations(pending.retrieved_chunks)
            if preview_sources:
                st.markdown("**Sources to consult:**")
                for src_label in preview_sources:
                    st.markdown(f"- {src_label}")
            else:
                st.write("_No matching sources found._")

            c_confirm, c_cancel = st.columns(2)
            with c_confirm:
                if st.button("Confirm & Send", type="primary", use_container_width=True):
                    st.session_state.history.append(_complete_or_record_error(pipeline, pending))
                    st.session_state.pending_preview = None
                    st.rerun()
            with c_cancel:
                if st.button("Cancel", use_container_width=True):
                    st.session_state.pending_preview = None
                    st.rerun()

    query = st.chat_input("Ask a question about your documents...")
    if query:
        if not st.session_state.documents:
            st.warning("Upload a document first from the sidebar.")
        else:
            prepared = pipeline.prepare_ask(query, top_k=TOP_K)
            if prepared.blocked_response is not None:
                response = prepared.blocked_response
                st.session_state.pending_preview = None
                st.session_state.history.append(
                    {
                        "query": response.query,
                        "answer": response.answer,
                        "llm_name": response.llm_name,
                        "sources": _unique_source_citations(response.retrieved_chunks),
                        "verdicts": response.shield_verdicts,
                        "ai_error": False,
                    }
                )
                st.rerun()
            elif preview_before_send:
                st.session_state.pending_preview = prepared
                st.rerun()
            else:
                st.session_state.history.append(_complete_or_record_error(pipeline, prepared))
                st.session_state.pending_preview = None
                st.rerun()


if __name__ == "__main__":
    main()
