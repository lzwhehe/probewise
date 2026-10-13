"""轻量 RAG：从处置手册、ATT&CK 说明和历史案例中检索与告警相关的段落，供报告引用。

检索默认用 BM25（中文按字符二元组切分，英文按单词），零依赖、可离线；
配置了 OpenAI 兼容的 embeddings 接口时，可以对 BM25 的候选结果做向量重排。
"""

from __future__ import annotations

import json
import math
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .kb import DATA_DIR

RAG_DIR = DATA_DIR / "rag"
SOURCE_NAMES = {"playbooks.md": "处置手册", "attack_notes.md": "ATT&CK 说明", "cases.md": "历史案例"}


@dataclass
class Chunk:
    id: str
    title: str
    text: str
    source: str


def tokenize(text: str) -> list[str]:
    text = text.lower()
    tokens = re.findall(r"[a-z0-9_]+", text)
    cjk = re.findall(r"[一-鿿]+", text)
    for run in cjk:
        tokens.extend(run[i : i + 2] for i in range(max(1, len(run) - 1)))
    return tokens


def load_chunks(rag_dir: Path = RAG_DIR) -> list[Chunk]:
    chunks = []
    for path in sorted(rag_dir.glob("*.md")):
        source = SOURCE_NAMES.get(path.name, path.stem)
        for block in re.split(r"\n(?=## )", path.read_text(encoding="utf-8")):
            if not block.startswith("## "):
                continue
            header, _, body = block.partition("\n")
            title = header[3:].strip()
            chunk_id = title.split()[0]
            if chunk_id.startswith("T-"):
                chunk_id = chunk_id[2:]
            chunks.append(Chunk(chunk_id, title, body.strip(), source))
    return chunks


class Retriever:
    def __init__(self, chunks: list[Chunk] | None = None, k1: float = 1.5, b: float = 0.75):
        self.chunks = chunks or load_chunks()
        self.k1, self.b = k1, b
        self.docs = [tokenize(c.title + " " + c.text) for c in self.chunks]
        self.avgdl = sum(len(d) for d in self.docs) / max(1, len(self.docs))
        df: dict[str, int] = {}
        for d in self.docs:
            for t in set(d):
                df[t] = df.get(t, 0) + 1
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def bm25(self, query: str) -> list[tuple[float, Chunk]]:
        q = tokenize(query)
        scored = []
        for doc, chunk in zip(self.docs, self.chunks):
            tf: dict[str, int] = {}
            for t in doc:
                tf[t] = tf.get(t, 0) + 1
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                s += self.idf.get(t, 0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * len(doc) / self.avgdl))
            scored.append((s, chunk))
        return sorted(scored, key=lambda x: -x[0])

    def search(self, query: str, k: int = 4, must_include: list[str] | None = None) -> list[dict]:
        ranked = self.bm25(query)
        picked = [c for _, c in ranked if c.id in (must_include or [])]
        for score, c in ranked:
            if len(picked) >= k:
                break
            if score > 0 and c not in picked:
                picked.append(c)
        scores = {c.id: s for s, c in ranked}
        return [
            {"id": c.id, "title": c.title, "source": c.source, "text": c.text, "score": round(scores.get(c.id, 0), 3)}
            for c in picked[:k]
        ]


def rerank_with_embeddings(query: str, hits: list[dict], base_url: str, model: str, api_key: str = "") -> list[dict]:
    """可选：用 OpenAI 兼容的 /embeddings 接口按余弦相似度重排；失败时原样返回。"""
    try:
        body = json.dumps({"model": model, "input": [query] + [h["text"] for h in hits]}).encode()
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        req = urllib.request.Request(f"{base_url.rstrip('/')}/embeddings", data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            vecs = [d["embedding"] for d in json.loads(resp.read())["data"]]
        q, rest = vecs[0], vecs[1:]

        def cos(a, b):
            na = math.sqrt(sum(x * x for x in a)) or 1
            nb = math.sqrt(sum(x * x for x in b)) or 1
            return sum(x * y for x, y in zip(a, b)) / (na * nb)

        return [h for _, h in sorted(zip([cos(q, v) for v in rest], hits), key=lambda x: -x[0])]
    except Exception:
        return hits
