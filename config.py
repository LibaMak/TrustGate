from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values

BASE_DIR = Path(__file__).resolve().parent

DEFAULT_MODEL = "openai/gpt-oss-20b"
DEFAULT_GROQ_MODEL = DEFAULT_MODEL
DEFAULT_LLM_MODE = "cloud"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "llama3.2:3b"

CHUNK_SIZE = 500
CHUNK_OVERLAP = 100
TOP_K = 3


def _read_st_secret(key: str) -> str:
    """Safely read a secret from Streamlit secrets when available."""
    try:
        import streamlit as st

        if key in st.secrets:
            return str(st.secrets[key]).strip()
    except Exception:
        pass
    return ""


@dataclass(frozen=True)
class Settings:
    groq_api_key: str
    groq_model: str = DEFAULT_MODEL
    llm_mode: str = DEFAULT_LLM_MODE
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    ollama_model: str = DEFAULT_OLLAMA_MODEL
    chunk_size: int = CHUNK_SIZE
    chunk_overlap: int = CHUNK_OVERLAP
    top_k: int = TOP_K
    sample_docs_dir: Path = BASE_DIR / "sample_docs"

    @property
    def has_groq_key(self) -> bool:
        key = self.groq_api_key.strip()
        return bool(key) and key != "your_groq_api_key_here"

    @property
    def use_mock_llm(self) -> bool:
        return self.llm_mode == "mock"


def get_settings() -> Settings:
    env_file = dotenv_values(BASE_DIR / ".env")

    # Read GROQ_API_KEY from st.secrets first, then .env (then process env fallback)
    api_key = (
        _read_st_secret("GROQ_API_KEY")
        or str(env_file.get("GROQ_API_KEY") or "").strip()
        or os.getenv("GROQ_API_KEY", "").strip()
    )

    raw_mode = (
        os.getenv("LLM_MODE", "").strip()
        or _read_st_secret("LLM_MODE")
        or str(env_file.get("LLM_MODE") or "").strip()
        or DEFAULT_LLM_MODE
    ).lower()
    if raw_mode in {"local", "ollama"}:
        llm_mode = "ollama"
    elif raw_mode == "mock":
        llm_mode = "mock"
    else:
        llm_mode = "cloud"

    ollama_base_url = (
        os.getenv("OLLAMA_BASE_URL", "").strip()
        or _read_st_secret("OLLAMA_BASE_URL")
        or str(env_file.get("OLLAMA_BASE_URL") or "").strip()
        or DEFAULT_OLLAMA_BASE_URL
    )
    ollama_model = (
        os.getenv("OLLAMA_MODEL", "").strip()
        or _read_st_secret("OLLAMA_MODEL")
        or str(env_file.get("OLLAMA_MODEL") or "").strip()
        or DEFAULT_OLLAMA_MODEL
    )

    return Settings(
        groq_api_key=api_key,
        groq_model=DEFAULT_MODEL,
        llm_mode=llm_mode,
        ollama_base_url=ollama_base_url,
        ollama_model=ollama_model,
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        top_k=TOP_K,
    )
