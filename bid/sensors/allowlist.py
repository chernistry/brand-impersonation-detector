"""
Tranco-backed legit-domain allowlist (keyless false-positive cut).

A typosquat/CT-log sensor generates a lot of noise: a brand-string cert search
returns the brand's own CDNs, security vendors, news sites, and archive.org; a
dnstwist permutation set includes the brand's own regional domains. The single
cheapest precision lever is an allowlist of domains known-legitimate at internet
scale, so we drop them before they ever reach the LLM stage.

Source (keyless, no account): the Tranco research list (https://tranco-list.eu),
a 30-day-averaged top-1M ranking hardened against the manipulation that plagues
raw popularity lists. The daily list is a plain CSV zip served without a key.

Notes:
  - Offline default is a small BUNDLED fixture (brand official domains + common
    infra) so the pipeline runs with no network and no 25 MB download. The live
    Tranco fetch is opt-in and cached on disk.
  - Allowlisting is PRECISION, not ground truth: a domain being in Tranco's top-N
    means "popular", not "not-malicious". We only use it to drop obvious legit
    infra; a brand's OWN domains are always allowlisted regardless of rank.
  - membership is tested on the registrable (eTLD+1) form so www./api./m. all
    collapse to one decision.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

from .. import paths
from ..domains import registrable
from ..useragent import user_agent

_CACHE: Path | None = None  # tests override; default paths.cache_dir("allowlist")
_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "allowlist.json"
# Keyless permalink: the most recent daily Tranco list as a CSV zip.
_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
_UA = {"User-Agent": user_agent()}


class Allowlist:
    """Registrable-domain allowlist. Bundled by default, live Tranco optional."""

    def __init__(self, load_live: bool = False, top_n: int = 100_000,
                 extra: set[str] | None = None, timeout: float = 60.0):
        self.top_n = top_n
        self._mode = "fixture"
        self._error: str | None = None
        self._domains: set[str] = set()

        # 1) always seed from the bundled fixture (brand domains + common infra)
        if _FIXTURE.exists():
            data = json.loads(_FIXTURE.read_text())
            self._domains |= {registrable(d) for d in data.get("allow", []) if d}

        # 2) optionally overlay the live Tranco top-N (cached)
        if load_live:
            try:
                self._domains |= self._load_tranco(top_n, timeout)
                self._mode = "tranco_live"
            except Exception as e:  # network/parse error -> fixture-only, recorded
                self._error = f"{type(e).__name__}: {e}"

        if extra:
            self._domains |= {registrable(d) for d in extra if d}

    def _load_tranco(self, top_n: int, timeout: float) -> set[str]:
        cache_root = _CACHE or paths.cache_dir("allowlist")
        cache_root.mkdir(parents=True, exist_ok=True)
        cache = cache_root / f"tranco_top_{top_n}.txt"
        if cache.exists():
            return {ln.strip() for ln in cache.read_text().splitlines() if ln.strip()}
        from .. import net

        r = net.get("allowlist", _TRANCO_URL, headers=_UA, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        name = zf.namelist()[0]
        out: set[str] = set()
        with zf.open(name) as fh:
            reader = csv.reader(io.TextIOWrapper(fh, encoding="utf-8"))
            for row in reader:
                if len(row) < 2:
                    continue
                out.add(registrable(row[1]))
                if len(out) >= top_n:
                    break
        cache.write_text("\n".join(sorted(out)))
        return out

    def contains(self, domain: str) -> bool:
        """True if the registrable form of `domain` is a known-legit domain."""
        reg = registrable(domain)
        return bool(reg) and reg in self._domains

    def add(self, *domains: str) -> None:
        self._domains |= {registrable(d) for d in domains if d}

    def health(self) -> dict:
        return {
            "component": "tranco_allowlist",
            "mode": self._mode,
            "size": len(self._domains),
            "error_rate": 1.0 if self._error else 0.0,
            "note": self._error or f"{self._mode}: {len(self._domains)} legit registrable domains",
        }
