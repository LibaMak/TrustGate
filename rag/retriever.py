from __future__ import annotations

from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from rag.chunker import Chunk


@dataclass
class RetrievedChunk:
    chunk: Chunk
    score: float


class TfidfRetriever:
    """Lightweight in-memory TF-IDF cosine-similarity retriever."""

    def __init__(self) -> None:
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._chunks: list[Chunk] = []

    @property
    def chunk_count(self) -> int:
        return len(self._chunks)

    def clear(self) -> None:
        self._vectorizer = None
        self._matrix = None
        self._chunks = []

    def index(self, chunks: list[Chunk]) -> None:
        self._chunks = list(chunks)
        if not self._chunks:
            self._vectorizer = None
            self._matrix = None
            return

        corpus = [chunk.text for chunk in self._chunks]
        try:
            vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
            matrix = vectorizer.fit_transform(corpus)
        except ValueError:
            vectorizer = TfidfVectorizer(stop_words=None, ngram_range=(1, 2))
            matrix = vectorizer.fit_transform(corpus)

        self._vectorizer = vectorizer
        self._matrix = matrix

    def retrieve(self, query: str, top_k: int = 3) -> list[RetrievedChunk]:
        if not self._chunks or self._vectorizer is None or self._matrix is None:
            return []

        cleaned_query = query.strip()
        if not cleaned_query:
            return []

        query_vec = self._vectorizer.transform([cleaned_query])
        scores = cosine_similarity(query_vec, self._matrix).flatten()
        ranked_indices = scores.argsort()[::-1][: max(top_k, 1)]

        return [
            RetrievedChunk(chunk=self._chunks[idx], score=float(scores[idx]))
            for idx in ranked_indices
        ]
