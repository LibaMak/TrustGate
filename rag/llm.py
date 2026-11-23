from __future__ import annotations

import json
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

from groq import Groq

from rag.retriever import RetrievedChunk


def _format_context(context_chunks: list[RetrievedChunk]) -> str:
    return "\n\n".join(
        f"[{item.chunk.source}#chunk-{item.chunk.index} | score={item.score:.2f}]\n{item.chunk.text}"
        for item in context_chunks
    )


def _build_prompts(query: str, context_chunks: list[RetrievedChunk]) -> tuple[str, str]:
    formatted_context = _format_context(context_chunks)
    system_prompt = (
        "You are TrustGate Assistant, a helpful document Q&A assistant. "
        "Answer the user's question using ONLY the provided context snippets. "
        "Cite the source document name when possible. If the answer is not present "
        "in the context, clearly say you do not have enough information."
    )
    user_prompt = (
        f"Context:\n{formatted_context}\n\n"
        f"Question: {query}\n\n"
        "Answer concisely and cite the relevant source(s):"
    )
    return system_prompt, user_prompt


def is_ollama_available(base_url: str = "http://localhost:11434", timeout: float = 1.5) -> tuple[bool, str]:
    """Check whether a local Ollama daemon is reachable at base_url."""
    url = base_url.rstrip("/") + "/api/tags"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, "Ollama daemon reachable."
            return False, f"Ollama returned HTTP {resp.status}."
    except Exception as exc:
        return False, f"Ollama is not reachable at {base_url} ({exc})."


class BaseLLM(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def generate(self, query: str, context_chunks: list[RetrievedChunk]) -> str:
        raise NotImplementedError


class MockLLM(BaseLLM):
    """Deterministic offline LLM used for smoke testing and keyless local runs."""

    @property
    def name(self) -> str:
        return "MockLLM (offline)"

    def generate(self, query: str, context_chunks: list[RetrievedChunk]) -> str:
        if not context_chunks:
            return (
                f"[MockLLM] No indexed context found to answer: '{query}'. "
                "Please load at least one document first."
            )

        best = context_chunks[0]
        citations = ", ".join(
            f"{item.chunk.source}#chunk-{item.chunk.index} (score={item.score:.2f})"
            for item in context_chunks
        )
        snippet = best.chunk.text[:320].strip()
        if len(best.chunk.text) > 320:
            snippet += "..."

        return (
            f"[MockLLM] Grounded answer for '{query}':\n\n"
            f"Top matching context from {best.chunk.source} (chunk {best.chunk.index}):\n"
            f"\"{snippet}\"\n\n"
            f"Sources consulted: {citations}"
        )


class GroqLLM(BaseLLM):
    """Groq-hosted Cloud LLM client."""

    def __init__(self, api_key: str, model: str = "openai/gpt-oss-20b") -> None:
        if not api_key or api_key.strip() == "your_groq_api_key_here":
            raise ValueError(
                "GROQ_API_KEY is missing. Add it to your local .env file or switch to Mock/Local LLM."
            )
        self._model = model
        self._client = Groq(api_key=api_key.strip())

    @property
    def name(self) -> str:
        return f"Cloud Groq ({self._model})"

    def generate(self, query: str, context_chunks: list[RetrievedChunk]) -> str:
        if not context_chunks:
            return "No document context is loaded. Upload or load documents before asking a question."

        system_prompt, user_prompt = _build_prompts(query, context_chunks)
        completion = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        return (completion.choices[0].message.content or "").strip()


class OllamaLLM(BaseLLM):
    """Local Ollama LLM client (default llama3.2:3b)."""

    def __init__(
        self,
        model: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ) -> None:
        self._model = model.strip() or "llama3.2:3b"
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def name(self) -> str:
        return f"Local Ollama ({self._model})"

    def generate(self, query: str, context_chunks: list[RetrievedChunk]) -> str:
        if not context_chunks:
            return "No document context is loaded. Upload or load documents before asking a question."

        system_prompt, user_prompt = _build_prompts(query, context_chunks)
        payload = json.dumps(
            {
                "model": self._model,
                "stream": False,
                "options": {"temperature": 0.2},
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }
        ).encode("utf-8")

        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        message = body.get("message") or {}
        return str(message.get("content", "")).strip()
