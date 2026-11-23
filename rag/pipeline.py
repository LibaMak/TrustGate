from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rag.chunker import Chunk, chunk_document
from rag.llm import BaseLLM, MockLLM
from rag.loader import Document, load_file
from rag.retriever import RetrievedChunk, TfidfRetriever
from shield import (
    DocumentScanSummary,
    QuarantinedItem,
    ShieldVerdict,
    TrustGateShield,
)


@dataclass
class IngestionReport:
    documents: list[Document] = field(default_factory=list)
    chunks: list[Chunk] = field(default_factory=list)
    shield_verdicts: list[ShieldVerdict] = field(default_factory=list)
    document_summaries: list[DocumentScanSummary] = field(default_factory=list)
    quarantined_items: list[QuarantinedItem] = field(default_factory=list)
    rejected_documents: list[str] = field(default_factory=list)


@dataclass
class RAGResponse:
    query: str
    answer: str
    llm_name: str
    retrieved_chunks: list[RetrievedChunk] = field(default_factory=list)
    shield_verdicts: list[ShieldVerdict] = field(default_factory=list)


@dataclass
class PreparedQuery:
    query: str
    retrieved_chunks: list[RetrievedChunk] = field(default_factory=list)
    shield_verdicts: list[ShieldVerdict] = field(default_factory=list)
    blocked_response: RAGResponse | None = None


class RAGPipeline:
    """End-to-end RAG pipeline enforced by TrustGateShield."""

    def __init__(
        self,
        llm: BaseLLM | None = None,
        shield: TrustGateShield | None = None,
        chunk_size: int = 500,
        chunk_overlap: int = 100,
        top_k: int = 3,
    ) -> None:
        self.llm: BaseLLM = llm or MockLLM()
        self.shield: TrustGateShield = shield or TrustGateShield(enabled=True)
        self.retriever = TfidfRetriever()
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.top_k = top_k
        self.documents: list[Document] = []
        self.chunks: list[Chunk] = []
        self.last_ingestion_report: IngestionReport | None = None

    def clear(self) -> None:
        self.documents = []
        self.chunks = []
        self.retriever.clear()
        self.last_ingestion_report = None

    def ingest_documents(self, docs: list[Document], replace: bool = True) -> IngestionReport:
        if replace:
            self.clear()

        verdicts: list[ShieldVerdict] = []
        summaries: list[DocumentScanSummary] = []
        quarantined_items: list[QuarantinedItem] = []
        rejected_documents: list[str] = []
        new_docs: list[Document] = []
        new_chunks: list[Chunk] = []

        for doc in docs:
            doc_chunks = chunk_document(
                doc,
                chunk_size=self.chunk_size,
                chunk_overlap=self.chunk_overlap,
            )
            summary = self.shield.scan_document_chunks(doc.source, doc_chunks)
            summaries.append(summary)
            quarantined_items.extend(summary.quarantined_items)

            if summary.policy_action == "strict_block":
                rejected_documents.append(doc.source)
                verdicts.append(
                    ShieldVerdict(
                        allowed=False,
                        stage="document",
                        status="STRICT_BLOCK",
                        reason=summary.reason,
                        risk_score=float(summary.max_risk_score),
                        location=doc.source,
                        framework_tags=summary.framework_tags,
                        action="quarantine",
                        policy="strict_block",
                        findings=summary.findings,
                    )
                )
                continue

            verdicts.append(
                ShieldVerdict(
                    allowed=True,
                    stage="document",
                    status=summary.policy_action.upper(),
                    reason=summary.reason,
                    risk_score=float(summary.max_risk_score),
                    location=doc.source,
                    framework_tags=summary.framework_tags,
                    action="safe" if not summary.quarantined_items else "sanitize",
                    policy=summary.policy_action,
                    findings=summary.findings,
                )
            )

            if summary.kept_chunks:
                new_docs.append(doc)
                new_chunks.extend(summary.kept_chunks)

        self.documents.extend(new_docs)
        self.chunks.extend(new_chunks)
        self.retriever.index(self.chunks)

        report = IngestionReport(
            documents=list(self.documents),
            chunks=list(self.chunks),
            shield_verdicts=verdicts,
            document_summaries=summaries,
            quarantined_items=quarantined_items,
            rejected_documents=rejected_documents,
        )
        self.last_ingestion_report = report
        return report

    def ingest_files(self, paths: list[str | Path], replace: bool = True) -> IngestionReport:
        docs = [load_file(path) for path in paths]
        return self.ingest_documents(docs, replace=replace)

    def prepare_ask(self, query: str, top_k: int | None = None) -> PreparedQuery:
        verdicts: list[ShieldVerdict] = []

        query_verdict = self.shield.inspect_query(query)
        verdicts.append(query_verdict)
        if not query_verdict.allowed:
            tags_str = ", ".join(query_verdict.framework_tags)
            refusal = f"Refused by TrustGate Shield: {query_verdict.reason}"
            if tags_str:
                refusal += f"\n\nFramework Tags: {tags_str}"
            return PreparedQuery(
                query=query,
                retrieved_chunks=[],
                shield_verdicts=verdicts,
                blocked_response=RAGResponse(
                    query=query,
                    answer=refusal,
                    llm_name=self.llm.name,
                    retrieved_chunks=[],
                    shield_verdicts=verdicts,
                ),
            )

        k = top_k if top_k is not None else self.top_k
        retrieved = self.retriever.retrieve(query, top_k=k)

        safe_retrieved, chunk_verdict = self.shield.prepare_chunks_for_llm(retrieved)
        verdicts.append(chunk_verdict)
        if retrieved and not safe_retrieved:
            return PreparedQuery(
                query=query,
                retrieved_chunks=[],
                shield_verdicts=verdicts,
                blocked_response=RAGResponse(
                    query=query,
                    answer="Blocked by TrustGate Shield: all retrieved chunks were quarantined.",
                    llm_name=self.llm.name,
                    retrieved_chunks=[],
                    shield_verdicts=verdicts,
                ),
            )

        return PreparedQuery(
            query=query,
            retrieved_chunks=safe_retrieved,
            shield_verdicts=verdicts,
            blocked_response=None,
        )

    def complete_ask(self, prepared: PreparedQuery) -> RAGResponse:
        if prepared.blocked_response is not None:
            return prepared.blocked_response

        raw_answer = self.llm.generate(prepared.query, prepared.retrieved_chunks)
        final_answer, response_verdict = self.shield.sanitize_response(raw_answer)
        verdicts = [*prepared.shield_verdicts, response_verdict]

        return RAGResponse(
            query=prepared.query,
            answer=final_answer,
            llm_name=self.llm.name,
            retrieved_chunks=prepared.retrieved_chunks,
            shield_verdicts=verdicts,
        )

    def ask(self, query: str, top_k: int | None = None) -> RAGResponse:
        prepared = self.prepare_ask(query, top_k=top_k)
        return self.complete_ask(prepared)
