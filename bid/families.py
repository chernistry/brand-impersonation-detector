"""
Model family identity.

A recheck or a supervisor that shares the classifier's model family shares its
training data and blind spots, so agreement between the two is inflated. Policy
code compares families, not model ids: two sizes of one vendor's model are the
same family.
"""
from __future__ import annotations

# Provider prefixes as they appear in OpenRouter / Hugging Face style ids.
_PREFIX = {
    "anthropic": "anthropic",
    "openai": "openai",
    "google": "google",
    "meta-llama": "meta",
    "meta": "meta",
    "mistralai": "mistral",
    "mistral": "mistral",
    "qwen": "qwen",
    "deepseek": "deepseek",
    "deepseek-ai": "deepseek",
    "x-ai": "xai",
    "xai": "xai",
    "cohere": "cohere",
    "microsoft": "microsoft",
    "amazon": "amazon",
    "nvidia": "nvidia",
}

# Bare model ids (local or vendor-native endpoints) by name stem.
_STEM = (
    ("claude", "anthropic"),
    ("gpt-", "openai"),
    ("o1", "openai"),
    ("o3", "openai"),
    ("o4", "openai"),
    ("gemini", "google"),
    ("gemma", "google"),
    ("llama", "meta"),
    ("qwen", "qwen"),
    ("qwq", "qwen"),
    ("mistral", "mistral"),
    ("mixtral", "mistral"),
    ("pixtral", "mistral"),
    ("deepseek", "deepseek"),
    ("grok", "xai"),
    ("command", "cohere"),
    ("phi-", "microsoft"),
    ("nova", "amazon"),
    ("mock-", "rules"),
    ("rules-", "rules"),
    ("signals-", "signals"),
)


def model_family(model_id: str) -> str:
    """Family of a model id, e.g. 'google/gemini-2.5-flash-lite' -> 'google'.

    Unknown ids map to their own lowercased id, so two unknown models are only the
    same family when they are the same model.
    """
    mid = (model_id or "").strip().lower()
    if not mid:
        return "unknown"
    if "/" in mid:
        prefix, rest = mid.split("/", 1)
        if prefix in _PREFIX:
            return _PREFIX[prefix]
        mid = rest  # e.g. "my-org/qwen3-vl-8b" -> look at the model name
    for stem, family in _STEM:
        if mid.startswith(stem):
            return family
    return mid


def same_family(a: str, b: str) -> bool:
    return model_family(a) == model_family(b)
