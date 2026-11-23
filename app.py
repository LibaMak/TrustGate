from __future__ import annotations

import importlib
from typing import Any

import streamlit as st

import dashboard
import shield.audit_log as audit_log_mod
from config import get_settings
from rag.llm import BaseLLM, GroqLLM, MockLLM, OllamaLLM, is_ollama_available
from rag.loader import Document, load_uploaded_file, load_url
from rag.pipeline import IngestionReport, PreparedQuery, RAGPipeline
from shield import TrustGateShield

st.set_page_config(
    page_title="TrustGate — RAG Security Shield",
    page_icon="🛡️",
    layout="wide",
)


def _format_framework_tags(tags: list[str]) -> str:
    """Format OWASP / NIST AI RMF / NIST CSF tags consistently for warning cards."""
    if not tags:
        return "None"
    owasp: list[str] = []
    rmf: list[str] = []
    csf: list[str] = []
    other: list[str] = []
    for tag in tags:
        if tag.startswith("OWASP:"):
            owasp.append(tag.split(":", 1)[1].strip())
        elif tag.startswith("NIST AI RMF:"):
            rmf.append(tag.split(":", 1)[1].strip())
        elif tag.startswith("NIST CSF:"):
            csf.append(tag.split(":", 1)[1].strip())
        else:
            other.append(tag)
    parts: list[str] = []
    if owasp:
        parts.append(f"**OWASP:** {', '.join(owasp)}")
    if rmf:
        parts.append(f"**NIST AI RMF:** {', '.join(rmf)}")
    if csf:
        parts.append(f"**NIST CSF:** {', '.join(csf)}")
    if other:
        parts.extend(other)
    return " | ".join(parts)


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
    chunk_size: int,
    chunk_overlap: int,
    top_k: int,
    audit_logger: Any,
) -> tuple[RAGPipeline, IngestionReport | None]:
    signature = (
        tuple((d.source, len(d.content)) for d in docs),
        shield_enabled,
        chunk_size,
        chunk_overlap,
    )
    existing: RAGPipeline | None = st.session_state.pipeline
    if existing is not None and st.session_state.ingest_signature == signature:
        existing.llm = llm
        existing.top_k = top_k
        return existing, st.session_state.ingestion_report

    shield = TrustGateShield(enabled=shield_enabled, audit_logger=audit_logger)
    pipeline = RAGPipeline(
        llm=llm,
        shield=shield,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        top_k=top_k,
    )
    report: IngestionReport | None = None
    if docs:
        report = pipeline.ingest_documents(docs, replace=True)
    st.session_state.pipeline = pipeline
    st.session_state.ingestion_report = report
    st.session_state.ingest_signature = signature
    return pipeline, report


def _render_quarantine_warnings(report: IngestionReport | None, shield_enabled: bool) -> None:
    if not shield_enabled or report is None:
        return

    for summary in report.document_summaries:
        tags_md = _format_framework_tags(summary.framework_tags)
        if summary.policy_action == "strict_block":
            st.error(
                f"**STRICT BLOCK — {summary.source}**\n\n"
                f"- **Reason:** {summary.reason}\n"
                f"- **Location:** Entire Document | **Max Risk:** `{summary.max_risk_score}/100`\n"
                f"- **Frameworks:** {tags_md}"
            )
        elif summary.policy_action == "sanitize":
            st.warning(
                f"**SANITIZED — {summary.source}**\n\n"
                f"- **Reason:** {summary.reason}\n"
                f"- **Max Risk:** `{summary.max_risk_score}/100`\n"
                f"- **Frameworks:** {tags_md}"
            )
        elif summary.suspicious_chunks > 0:
            st.warning(
                f"**HIDDEN CONTENT WARNING — {summary.source}**\n\n"
                f"- **Reason:** {summary.reason}\n"
                f"- **Max Risk:** `{summary.max_risk_score}/100`\n"
                f"- **Frameworks:** {tags_md}"
            )

    if report.quarantined_items:
        with st.expander(
            f"Quarantined / Removed Content ({len(report.quarantined_items)}) — Never Indexed or Sent to LLM",
            expanded=True,
        ):
            for item in report.quarantined_items:
                st.markdown(
                    f"- **`{item.chunk_id}`** | Location: `{item.location}` | Risk: `{item.risk_score}/100`\n"
                    f"  - **Reason:** {item.reason}\n"
                    f"  - **Frameworks:** {_format_framework_tags(item.framework_tags)}\n"
                    f"  - **Masked Snippet:** `{item.masked_snippet}`"
                )


def _select_active_llm(
    llm_mode: str,
    groq_api_key: str,
    groq_model: str,
    ollama_base_url: str,
    ollama_model: str,
) -> tuple[BaseLLM, str | None]:
    if llm_mode == "Cloud (Groq)":
        try:
            return GroqLLM(api_key=groq_api_key, model=groq_model), None
        except ValueError as exc:
            return MockLLM(), f"{exc} Falling back to MockLLM."

    if llm_mode == "Local (Ollama)":
        ok, detail = is_ollama_available(ollama_base_url)
        if not ok:
            return (
                MockLLM(),
                f"Local Ollama unavailable ({detail}) Start Ollama with `ollama run {ollama_model}`. "
                "Falling back to MockLLM.",
            )
        return OllamaLLM(model=ollama_model, base_url=ollama_base_url), None

    return MockLLM(), None


def _execute_prepared_with_fallback(pipeline: RAGPipeline, prepared: PreparedQuery) -> tuple[Any, str | None]:
    try:
        return pipeline.complete_ask(prepared), None
    except Exception as exc:
        if isinstance(pipeline.llm, OllamaLLM):
            original_llm = pipeline.llm
            pipeline.llm = MockLLM()
            try:
                resp = pipeline.complete_ask(prepared)
                return resp, f"Local Ollama call failed ({exc}). Fell back to MockLLM."
            finally:
                pipeline.llm = original_llm
        raise


def main() -> None:
    _init_state()
    importlib.reload(audit_log_mod)
    importlib.reload(dashboard)
    settings = get_settings()
    audit_logger = audit_log_mod.AuditLogger()

    st.title("🛡️ TrustGate — Security-First RAG Shield")
    st.caption(
        "Prompt-injection scanner, hidden-text detector, quarantine & >30% strict-block policy, "
        "PII masking, and OWASP/NIST SQLite audit logging."
    )

    with st.sidebar:
        st.header("Shield & LLM Configuration")
        shield_enabled = st.toggle(
            "TrustGate Shield (ON / OFF)",
            value=st.session_state.shield_enabled,
            help="Toggle scanning, quarantine, PII masking, and query protection ON or OFF.",
        )
        st.session_state.shield_enabled = shield_enabled

        if shield_enabled:
            st.success("Shield Status: **ON** (Sanitize default, Strict Block > 30%)")
        else:
            st.warning("Shield Status: **OFF (BYPASSED)** — scanning and masking disabled.")

        mode_options = ["Mock (Offline)", "Cloud (Groq)", "Local (Ollama)"]
        default_mode_index = 0 if settings.use_mock_llm or not settings.has_groq_key else 1
        llm_mode = st.radio(
            "LLM Mode",
            options=mode_options,
            index=default_mode_index,
            help="Cloud uses Groq API, Local uses Ollama (llama3.2:3b), Mock runs deterministically offline.",
        )

        groq_models = [
            "openai/gpt-oss-20b",
            "openai/gpt-oss-120b",
            "qwen/qwen3.8-27b",
            "allam-2-7b",
        ]
        if settings.groq_model and settings.groq_model not in groq_models:
            groq_models.insert(0, settings.groq_model)
        groq_model = st.selectbox(
            "Groq Model",
            options=groq_models,
            index=groq_models.index(settings.groq_model) if settings.groq_model in groq_models else 0,
            disabled=(llm_mode != "Cloud (Groq)"),
        )
        ollama_model = st.text_input(
            "Ollama Model",
            value=settings.ollama_model,
            disabled=(llm_mode != "Local (Ollama)"),
        )

        if llm_mode == "Cloud (Groq)":
            st.info(
                "Text is sent to an external API after redaction. "
                "Do not upload highly confidential documents."
            )
            if not settings.has_groq_key:
                st.warning("No GROQ_API_KEY detected in `.env`. Add it or switch to Local/Mock mode.")

        st.divider()
        st.subheader("RAG Parameters")
        chunk_size = st.slider("Chunk Size (chars)", min_value=200, max_value=1500, value=settings.chunk_size, step=50)
        chunk_overlap = st.slider(
            "Chunk Overlap (chars)",
            min_value=0,
            max_value=min(400, chunk_size - 50),
            value=min(settings.chunk_overlap, chunk_size - 50),
            step=25,
        )
        top_k = st.slider("Top-K Chunks", min_value=1, max_value=8, value=settings.top_k, step=1)

        st.divider()
        st.subheader("Documents")
        uploaded_files = st.file_uploader(
            "Upload PDF, DOCX, TXT, or HTML files",
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

        if st.button("Index Uploads", use_container_width=True, disabled=not uploaded_files):
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

        with st.expander("Fetch Web Page URL", expanded=False):
            url_input = st.text_input("Web Page URL", placeholder="https://example.com")
            if st.button("Load URL", use_container_width=True, disabled=not url_input.strip()):
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
                    st.error(f"Failed to load URL: {exc}")

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

    active_llm, llm_notice = _select_active_llm(
        llm_mode=llm_mode,
        groq_api_key=settings.groq_api_key,
        groq_model=groq_model,
        ollama_base_url=settings.ollama_base_url,
        ollama_model=ollama_model,
    )

    pipeline, report = _sync_pipeline(
        docs=st.session_state.documents,
        llm=active_llm,
        shield_enabled=shield_enabled,
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        top_k=top_k,
        audit_logger=audit_logger,
    )

    if not shield_enabled:
        st.error(
            "⚠️ **Protection disabled, Govern control weak** — "
            "TrustGate Shield is OFF. Enable the Shield toggle in the sidebar."
        )

    if llm_notice:
        st.warning(llm_notice)

    quarantined_count = len(report.quarantined_items) if report else 0
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Indexed Docs", len(pipeline.documents))
    m2.metric("Indexed Chunks", len(pipeline.chunks))
    m3.metric("Quarantined Chunks", quarantined_count)
    m4.metric("Shield Mode", "ON" if shield_enabled else "OFF (BYPASSED)")

    tab_chat, tab_dash = st.tabs(["Chat & Documents", "Security Dashboard"])

    with tab_chat:
        if llm_mode == "Cloud (Groq)":
            st.info(
                "Cloud Mode Notice: Text is sent to an external API after redaction. "
                "Do not upload highly confidential documents."
            )

        _render_quarantine_warnings(report, shield_enabled)

        if report is not None and report.document_summaries:
            with st.expander(f"Document Scan Summary ({len(report.document_summaries)})", expanded=False):
                for s in report.document_summaries:
                    st.markdown(
                        f"- **{s.source}** — `{s.policy_action.upper()}` · "
                        f"`{len(s.kept_chunks)}/{s.total_chunks}` chunks kept · "
                        f"Risk `{s.max_risk_score}/100`"
                    )

        st.divider()
        bar_title, bar_preview, bar_clear = st.columns([3.5, 1.8, 1.1])
        with bar_title:
            turns = len(st.session_state.history)
            turn_label = f"{turns} turn" if turns == 1 else f"{turns} turns"
            st.markdown(f"#### Conversation · `{turn_label}`")
        with bar_preview:
            preview_before_send = st.checkbox(
                "Preview before send",
                value=False,
                help="Inspect the exact redacted context and question before sending to the LLM.",
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
            st.caption("Upload files or fetch a URL from the sidebar, then ask a question below.")

        for entry in st.session_state.history:
            with st.chat_message("user"):
                st.write(entry["query"])
            with st.chat_message("assistant"):
                for v in entry["verdicts"]:
                    tags_md = _format_framework_tags(v.framework_tags)
                    if v.stage == "query" and v.status in {"REFUSED_SENSITIVE_QUERY", "REFUSED_INJECTION"}:
                        st.error(f"**Blocked ({v.status})** — {v.reason}\n\n{tags_md}")
                    elif v.stage == "query" and v.status == "WARN_CONTACT_QUERY":
                        st.warning(f"**Sensitive Query Warning** — {v.reason}\n\n{tags_md}")
                    elif v.stage == "response" and v.status == "MASKED_PII":
                        st.caption(f"Output PII Masked ({v.reason}) · {tags_md}")
                st.write(entry["answer"])
                with st.expander(f"Audit & Sources ({len(entry['chunks'])} chunks)"):
                    st.caption(f"Model: {entry['llm_name']}")
                    for v in entry["verdicts"]:
                        tags_str = _format_framework_tags(v.framework_tags)
                        st.markdown(
                            f"- `{v.stage}` · `{v.status}` (risk `{v.risk_score:.0f}`): "
                            f"{v.reason} | {tags_str}"
                        )
                    if entry["chunks"]:
                        for item in entry["chunks"]:
                            loc = (item.chunk.metadata or {}).get("location", item.chunk.chunk_id)
                            st.markdown(f"- **{item.chunk.chunk_id}** (`{loc}`, score `{item.score:.3f}`)")
                            st.code(item.chunk.text, language=None)

        pending: PreparedQuery | None = st.session_state.pending_preview
        if pending is not None:
            with st.container(border=True):
                st.markdown("#### Preview Before Send (Redacted Payload)")
                st.caption(f"Target LLM: **{active_llm.name}**")
                st.markdown(f"**Question:** {pending.query}")
                if not pending.retrieved_chunks:
                    st.write("_No context chunks retrieved._")
                else:
                    for item in pending.retrieved_chunks:
                        loc = (item.chunk.metadata or {}).get("location", item.chunk.chunk_id)
                        st.markdown(f"- **{item.chunk.chunk_id}** (`{loc}`, score: `{item.score:.3f}`)")
                        st.code(item.chunk.text, language=None)

                c_confirm, c_cancel = st.columns(2)
                with c_confirm:
                    if st.button("Confirm & Send to LLM", type="primary", use_container_width=True):
                        try:
                            response, runtime_notice = _execute_prepared_with_fallback(pipeline, pending)
                        except Exception as exc:
                            st.error(f"LLM request failed: {exc}")
                        else:
                            if runtime_notice:
                                st.warning(runtime_notice)
                            st.session_state.history.append(
                                {
                                    "query": response.query,
                                    "answer": response.answer,
                                    "llm_name": response.llm_name,
                                    "chunks": response.retrieved_chunks,
                                    "verdicts": response.shield_verdicts,
                                }
                            )
                            st.session_state.pending_preview = None
                            st.rerun()
                with c_cancel:
                    if st.button("Cancel", use_container_width=True):
                        st.session_state.pending_preview = None
                        st.rerun()

    with tab_dash:
        dashboard.render_dashboard(audit_logger, shield_enabled)

    query = st.chat_input("Ask about your loaded documents...")
    if query:
        if not st.session_state.documents:
            st.warning("Load documents first using the sidebar.")
        else:
            try:
                prepared = pipeline.prepare_ask(query, top_k=top_k)
                if prepared.blocked_response is not None:
                    response = prepared.blocked_response
                    st.session_state.pending_preview = None
                    st.session_state.history.append(
                        {
                            "query": response.query,
                            "answer": response.answer,
                            "llm_name": response.llm_name,
                            "chunks": response.retrieved_chunks,
                            "verdicts": response.shield_verdicts,
                        }
                    )
                    st.rerun()
                elif preview_before_send:
                    st.session_state.pending_preview = prepared
                    st.rerun()
                else:
                    response, runtime_notice = _execute_prepared_with_fallback(pipeline, prepared)
                    if runtime_notice:
                        st.warning(runtime_notice)
                    st.session_state.pending_preview = None
                    st.session_state.history.append(
                        {
                            "query": response.query,
                            "answer": response.answer,
                            "llm_name": response.llm_name,
                            "chunks": response.retrieved_chunks,
                            "verdicts": response.shield_verdicts,
                        }
                    )
                    st.rerun()
            except Exception as exc:
                st.error(f"LLM request failed: {exc}")


if __name__ == "__main__":
    main()
