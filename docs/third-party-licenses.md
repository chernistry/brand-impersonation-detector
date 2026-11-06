# Third-party licences

This repository contains no third-party source code. The packages below are
installed separately by `pip` under their own licences. Licences are as
declared in each package's metadata at the versions tested (Python 3.12,
November 2026); check the installed version before redistributing.

## Runtime dependencies

| Package | Licence |
|---|---|
| pydantic | MIT |
| httpx | BSD-3-Clause |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| Pillow | MIT-CMU |
| ImageHash | BSD-2-Clause |
| numpy | BSD-3-Clause, with bundled parts under 0BSD, MIT, Zlib and CC0-1.0 |
| tldextract | BSD-3-Clause |
| confusable-homoglyphs | MIT |
| rapidfuzz | MIT |
| dnstwist | Apache-2.0 |
| rfc3161-client | Apache-2.0 |
| mmh3 | MIT |

Pulled in by these: scipy (BSD-3-Clause) and PyWavelets (MIT AND BSD-3-Clause)
through ImageHash.

## Optional extras

| Extra | Package | Licence |
|---|---|---|
| `console` | fastapi | MIT |
| `console` | starlette | BSD-3-Clause |
| `console` | uvicorn | BSD-3-Clause |
| `embeddings` | fastembed | Apache-2.0 |
| `embeddings` | onnxruntime | MIT |
| `embeddings` | tokenizers | Apache-2.0 |
| `embeddings` | huggingface-hub | Apache-2.0 |

## Models downloaded at runtime

With the `embeddings` extra, fastembed downloads these models on first use.
They are not part of this repository or of the container image.

| Model | Used for | Licence |
|---|---|---|
| `Qdrant/clip-ViT-B-32-vision` | logo similarity | MIT |
| `BAAI/bge-small-en-v1.5` | semantic injection detector | MIT |

## Data fetched at runtime

Live sensors and enrichment read public sources at run time. Nothing from them
is bundled. Their terms apply to the operator who runs them.

| Source | Used by | Terms |
|---|---|---|
| WhatsMyName dataset | username enumeration sensor | CC BY-SA 4.0 |
| Tranco list | popularity allowlist | per the Tranco project's terms |
| jailbreak_llms prompt corpus | optional extra payloads for `bid adversarial`, read from a local copy you supply | per the corpus's own licence |
| Certificate logs, DNS-over-HTTPS, RDAP, scan search, block lists, app store and ad library APIs | sensors and enrichment | each service's terms of use |

## Development tools

pytest (MIT) and ruff (MIT) are used for development and CI only.
