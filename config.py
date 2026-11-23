from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_GROQ_MODEL = "openai/gpt-oss-20b"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:3b"
DEPRECATED_GROQ_MODELS = {"llama-3.1-8b-instant", "llama-3.3-70b-versatile"}
load_dotenv(BASE_DIR / ".env", override=True)


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    groq_api_key: str
    groq_model: str
    use_mock_llm: bool
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    chunk_size: int = 500
    chunk_overlap: int = 100
    top_k: int = 3
    sample_docs_dir: Path = BASE_DIR / "sample_docs"

    @property
    def has_groq_key(self) -> bool:
        key = self.groq_api_key.strip()
        return bool(key) and key != "your_groq_api_key_here"


def get_settings() -> Settings:
    load_dotenv(BASE_DIR / ".env", override=True)
    api_key = os.getenv("GROQ_API_KEY", "").strip()
    model = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL).strip() or DEFAULT_GROQ_MODEL
    if model in DEPRECATED_GROQ_MODELS:
        model = DEFAULT_GROQ_MODEL
    default_mock = not bool(api_key and api_key != "your_groq_api_key_here")
    use_mock = _parse_bool(os.getenv("TRUSTGATE_USE_MOCK_LLM"), default=default_mock)
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", DEFAULT_OLLAMA_BASE_URL).strip() or DEFAULT_OLLAMA_BASE_URL
    ollama_model = os.getenv("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL).strip() or DEFAULT_OLLAMA_MODEL
    return Settings(
        groq_api_key=api_key,
        groq_model=model,
        use_mock_llm=use_mock,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
    )
