"""
Local ML embeddings (fastembed / ONNX, CPU, no torch) - the "smart ML over dumb
regex" upgrade. Two uses:

  1. CLIP image vectors (Qdrant/clip-ViT-B-32-vision) for SEMANTIC logo similarity,
     fused with pHash. CLIP catches recolored/redrawn logo variants that a pHash
     Hamming distance misses (measured: fakes 0.95-1.0 cosine, unrelated 0.69-0.78).

  2. Text vectors (BAAI/bge-small-en-v1.5, top-MTEB small) for INJECTION detection
     by semantic similarity to a corpus of real jailbreaks, replacing the brittle
     substring marker list. Catches paraphrased/novel injections the list misses.

Determinism: ONNX inference is deterministic on a given machine; every vector is
cached to disk keyed by content sha256, so replays are byte-identical and free.
Everything degrades gracefully: if fastembed or the models are unavailable, the
callers fall back to pHash-only and the substring injection check.

Models download once from HuggingFace (~350MB CLIP, ~130MB bge). Set HF_TOKEN to
avoid rate limits. This module is OPT-IN (the zero-setup pipeline never imports it).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import paths

import numpy as np

_CACHE: Path | None = None  # tests override; default paths.cache_dir("embeddings")
CLIP_MODEL = "Qdrant/clip-ViT-B-32-vision"
TEXT_MODEL = "BAAI/bge-small-en-v1.5"

_clip = None
_text = None


def available() -> bool:
    try:
        import fastembed  # noqa: F401

        return True
    except Exception:
        return False


def _get_clip():
    global _clip
    if _clip is None:
        from fastembed import ImageEmbedding

        _clip = ImageEmbedding(CLIP_MODEL)
    return _clip


def _get_text():
    global _text
    if _text is None:
        from fastembed import TextEmbedding

        _text = TextEmbedding(TEXT_MODEL)
    return _text


def cosine(a, b) -> float:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    na, nb = np.linalg.norm(a), np.linalg.norm(b)
    if na == 0 or nb == 0:
        return 0.0
    return float(a @ b / (na * nb))


def _cache_path(kind: str, digest: str) -> Path:
    cache = _CACHE or paths.cache_dir("embeddings")
    cache.mkdir(parents=True, exist_ok=True)
    return cache / f"{kind}_{digest}.npy"


def clip_image_vector(data: bytes):
    """CLIP vector for image bytes, cached by content hash. None if unavailable."""
    if not available():
        return None
    digest = hashlib.sha256(data).hexdigest()[:24]
    p = _cache_path("clip", digest)
    if p.exists():
        return np.load(p)
    try:
        import io

        from PIL import Image

        img = Image.open(io.BytesIO(data)).convert("RGB")
        vec = np.asarray(list(_get_clip().embed([img]))[0], dtype=np.float32)
        np.save(p, vec)
        return vec
    except Exception:
        return None


def text_vector(text: str):
    """bge vector for text, cached by content hash. None if unavailable."""
    if not available() or not text:
        return None
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]
    p = _cache_path("txt", digest)
    if p.exists():
        return np.load(p)
    try:
        vec = np.asarray(list(_get_text().embed([text]))[0], dtype=np.float32)
        np.save(p, vec)
        return vec
    except Exception:
        return None
