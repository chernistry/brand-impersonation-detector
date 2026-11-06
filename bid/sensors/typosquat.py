"""
Typosquat domain sensor (dnstwist -> DoH-resolve -> keyless enrich).

Keyless, no account needed. Given a brand's official domain(s), it generates the
lookalike permutation space with dnstwist (the same engine SOC teams use), then
keeps only permutations that RESOLVE via dns.google DoH, i.e. domains someone has
actually registered and pointed somewhere. A registered lookalike of a bank
domain is a strong pre-attack signal: the phishing site usually exists on that
domain days before the social-media lure goes out.

Pipeline fit: emits the same RawObservation every other sensor emits, so the
downstream stages (normalize -> cheap filters -> classify -> rank -> signed
evidence) is identical. A resolving typosquat is edit-distance <= 2 from the
official domain by construction, so the existing handle-distance filter (fed the
brand's own domain SLD, see run_pipeline) keeps it; the domain-intention rule
fires because the link domain is not an official domain.

Keyless confirmation ladder (cheapest first):
  1. dns.google DoH A-record resolve  -> "is it registered + pointed?"  (required)
  2. crt.sh SANs                       -> "does it have TLS certs?"      (optional)
  3. urlscan.io existing scans         -> "has anyone scanned it live?"  (optional)

Rate-limit / opsec:
  - permutations are capped and restricted to high-signal fuzzers; DoH lookups are
    cached (enrich._cached) so a re-run is free and stable.
  - a small inter-request delay keeps DoH well under any sane limit.
  - allowlisted domains (Tranco + brand's own regional domains) are dropped before
    they are ever emitted, so the brand's own infra never becomes a candidate.
  - read-only: urlscan SEARCH, never a submission, so an adversary is never tipped.

ToS / PII: dnstwist runs locally (no ToS surface); dns.google, crt.sh, urlscan
search are public read-only APIs. Emitted domains are infrastructure, not people;
no personal data is collected. WHOIS is intentionally NOT queried (PII + rate
walls); registration is inferred from DNS resolution instead.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import Iterator

from ..domains import registrable
from ..models import Brand, RawObservation

# High-signal dnstwist fuzzers for brand impersonation. We skip the ultra-noisy
# "addition"/"dictionary" families by default to keep the DoH budget focused.
_DEFAULT_FUZZERS = {
    "homoglyph", "replacement", "omission", "insertion", "transposition",
    "vowel-swap", "bitsquatting", "hyphenation", "tld-swap", "subdomain",
    "repetition", "various",
}


class TyposquatSensor:
    """Registered-lookalike-domain sensor. Live network access, no key."""

    def __init__(self, allowlist=None, max_permutations: int = 600,
                 max_resolving: int = 40, fuzzers: set[str] | None = None,
                 enrich: bool = False, delay: float = 0.02, timeout: float = 15.0):
        self._allow = allowlist
        self.max_permutations = max_permutations
        self.max_resolving = max_resolving
        self.fuzzers = fuzzers or _DEFAULT_FUZZERS
        self.enrich = enrich
        self.delay = delay
        self.timeout = timeout
        self._last_error: str | None = None
        self._last_count = 0
        self._last_generated = 0

    def name(self) -> str:
        return "dns_typosquat"

    def _permutations(self, domain: str) -> list[dict]:
        import dnstwist

        fuzz = dnstwist.Fuzzer(domain)
        fuzz.generate()
        perms = fuzz.permutations()
        out = []
        for p in perms:
            fz = p.get("fuzzer", "")
            dom = p.get("domain", "")
            if fz in ("*original", "original"):
                continue
            if self.fuzzers and fz not in self.fuzzers:
                continue
            out.append({"fuzzer": fz, "domain": dom})
            if len(out) >= self.max_permutations:
                break
        return out

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        domains = list(getattr(brand, "official_domains", []) or [])
        if not domains:
            self._last_error = "brand has no official_domains (needs brand_kb)"
            self._last_count = 0
            return

        from .. import enrich as _enrich  # keyless DoH resolve, cached

        self._last_error = None
        self._last_generated = 0
        emitted = 0
        seen: set[str] = set()

        for official in domains:
            official_reg = registrable(official)
            try:
                perms = self._permutations(official)
            except Exception as e:
                self._last_error = f"{type(e).__name__}: {e}"
                continue
            self._last_generated += len(perms)

            for p in perms:
                if emitted >= self.max_resolving:
                    break
                cand = registrable(p["domain"]) or p["domain"]
                if not cand or cand == official_reg or cand in seen:
                    continue
                seen.add(cand)
                if self._allow is not None and self._allow.contains(cand):
                    continue

                try:
                    ips = _enrich.resolve(cand)  # dns.google DoH, cached
                except Exception:
                    ips = []
                if self.delay:
                    time.sleep(self.delay)
                if not ips:
                    continue  # not registered / not pointed -> not a live threat yet

                payload = {
                    "handle": cand,
                    "display_name": cand,
                    "app_name": cand,
                    "bio": f"registered lookalike of {official_reg} "
                           f"(dnstwist:{p['fuzzer']}), resolves to {', '.join(ips[:3])}",
                    "link_in_bio_url": f"https://{cand}",
                    "brand_domain": official_reg,
                    "fuzzer": p["fuzzer"],
                    "resolved_ips": ips,
                }
                if self.enrich:
                    try:
                        sans = _enrich.crtsh_sans(cand, limit=10)
                        payload["cert_sans"] = [s["name"] for s in sans]
                        payload["urlscan"] = _enrich.urlscan_search(cand, limit=3)
                    except Exception:
                        pass

                emitted += 1
                yield RawObservation(
                    sensor_name=self.name(),
                    observed_at=since,
                    platform="dns_typosquat",
                    platform_uid=cand,
                    payload=payload,
                    asset_urls=[],  # domains carry no bundled image asset; logo tier N/A
                )

        self._last_count = emitted

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "live",
            "last_count": self._last_count,
            "generated": self._last_generated,
            "error_rate": 1.0 if self._last_error else 0.0,
            "ban_rate": 0.0,  # no accounts are used: nothing to ban
            "note": self._last_error
            or "dnstwist perms -> dns.google DoH resolve (keyless). Registered lookalikes only.",
        }
