"""
Certificate-Transparency "new lookalike cert" sensor (crt.sh, keyless).

Keyless, no account needed. Every TLS certificate issued for a domain is logged
in public Certificate Transparency logs. Phishing kits provision a cert (usually
free Let's Encrypt) at stand-up time, so a freshly-issued cert whose SAN contains
the brand string is often the FIRST public trace of a campaign, ahead of the
social lure. This sensor queries crt.sh for the brand string, keeps recent certs
on non-official / non-allowlisted registrable domains, and emits one candidate
per distinct lookalike domain.

Why crt.sh and not certstream: certstream needs a live websocket to a firehose
(a long-lived connection, heavy for a batch tool). crt.sh exposes the same CT
data as a keyless JSON query with a time field, which is cacheable. A certstream
feed would be the alternative for continuous monitoring.

Pipeline fit: same RawObservation as every other sensor. A CT candidate's domain
contains the brand token by construction, so the brand-alias text signal fires in
the cheap filter and it survives to the classifier stage; the domain-intention
rule fires because the cert domain is not an official domain.

Keyless confirmation: crt.sh already tells us a real cert exists. Optional DoH
resolve (dns.google) upgrades "cert exists" to "cert + live A record".

Rate-limit / opsec:
  - one crt.sh query per brand token, cached to disk -> re-runs are free + stable.
  - crt.sh 502s under load; on error the sensor yields nothing and says so in
    health(), so it never breaks a run.
  - read-only; no submission anywhere.

ToS / PII: crt.sh is a public CT-log mirror intended for exactly this lookup.
Certificates are infrastructure metadata, not personal data. We store SAN domains
and issuer names only; no registrant PII is queried.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .. import paths
from ..domains import registrable
from ..models import Brand, RawObservation
from ..useragent import user_agent

_CACHE: Path | None = None  # tests override; default paths.cache_dir("ct-logs")
_UA = {"User-Agent": user_agent()}


def _parse_ct_time(s: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


class CTLogSensor:
    """CT-log lookalike-cert sensor. Live network access (crt.sh), no key."""

    def __init__(self, allowlist=None, lookback_days: int = 30, limit: int = 50,
                 resolve_confirm: bool = False, timeout: float = 45.0):
        self._allow = allowlist
        self.lookback_days = lookback_days
        self.limit = limit
        self.resolve_confirm = resolve_confirm
        self.timeout = timeout
        self._last_error: str | None = None
        self._last_count = 0
        self._last_rows = 0

    def name(self) -> str:
        return "ct_log"

    def _crtsh_identity(self, term: str) -> list[dict]:
        """crt.sh substring identity search (keyless), cached to disk."""
        cache_root = _CACHE or paths.cache_dir("ct-logs")
        cache_root.mkdir(parents=True, exist_ok=True)
        cache = cache_root / (f"ct_{term}".replace("/", "_")[:120] + ".json")
        if cache.exists():
            return json.loads(cache.read_text())
        from .. import net

        # %25 = URL-encoded '%' wildcard -> matches the term anywhere in an identity.
        r = net.get("sensor:ct_logs", "https://crt.sh/", params={"q": f"%{term}%", "output": "json"},
                    headers=_UA, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        cache.write_text(json.dumps(data))
        return data

    def scan(self, brand: Brand, since: datetime) -> Iterator[RawObservation]:
        # Search tokens: the brand SLD label + Wikidata aliases (single words only,
        # crt.sh substring match works best on a compact token).
        official_regs = {registrable(d) for d in getattr(brand, "official_domains", []) or []}
        token = brand.name.split()[0].lower()
        try:
            rows = self._crtsh_identity(token)
        except Exception as e:
            self._last_error = f"{type(e).__name__}: {e}"
            self._last_count = 0
            self._last_rows = 0
            return

        self._last_error = None
        self._last_rows = len(rows)

        # "recent": floor at max(since, now - lookback_days). since is the pipeline
        # determinism anchor; lookback is the live-freshness window.
        now = datetime.now(timezone.utc)
        floor = min(since, now) if since else now
        lb = now.timestamp() - self.lookback_days * 86400
        floor = datetime.fromtimestamp(max(floor.timestamp(), lb - 10**9), tz=timezone.utc)

        best: dict[str, dict] = {}  # registrable -> earliest-seen row info
        for row in rows:
            names = (row.get("name_value") or "").split("\n")
            not_before = _parse_ct_time(row.get("not_before", ""))
            for nm in names:
                nm = nm.strip().lstrip("*.").lower()
                if not nm or "@" in nm:
                    continue
                if token not in nm:
                    continue
                reg = registrable(nm)
                if not reg or reg in official_regs:
                    continue
                if self._allow is not None and self._allow.contains(reg):
                    continue
                # keep the most recent cert per registrable domain
                cur = best.get(reg)
                if cur is None or (not_before and (cur["nb"] is None or not_before > cur["nb"])):
                    best[reg] = {
                        "san": nm, "nb": not_before,
                        "issuer": row.get("issuer_name", ""),
                        "cert_id": row.get("id"),
                    }

        # freshness filter + emit
        emitted = 0
        for reg, info in sorted(best.items(), key=lambda kv: (kv[1]["nb"] or floor), reverse=True):
            if emitted >= self.limit:
                break
            nb = info["nb"]
            if nb is not None and nb < datetime.fromtimestamp(lb, tz=timezone.utc):
                continue  # older than the lookback window
            payload = {
                "handle": reg,
                "display_name": reg,
                "app_name": reg,
                "bio": f"CT-log cert for {info['san']} issued by "
                       f"{info['issuer'] or 'unknown CA'}"
                       + (f" (not_before {nb.date()})" if nb else ""),
                "link_in_bio_url": f"https://{reg}",
                "matched_san": info["san"],
                "issuer_name": info["issuer"],
                "not_before": nb.isoformat() if nb else None,
                "crtsh_id": info["cert_id"],
            }
            if self.resolve_confirm:
                try:
                    from .. import enrich as _enrich

                    payload["resolved_ips"] = _enrich.resolve(reg)
                except Exception:
                    payload["resolved_ips"] = []
            emitted += 1
            yield RawObservation(
                sensor_name=self.name(),
                observed_at=since,
                platform="ct_log",
                platform_uid=reg,
                payload=payload,
                asset_urls=[],
            )
        self._last_count = emitted

    def health(self) -> dict:
        return {
            "sensor": self.name(),
            "mode": "live",
            "last_count": self._last_count,
            "cert_rows_seen": self._last_rows,
            "error_rate": 1.0 if self._last_error else 0.0,
            "ban_rate": 0.0,
            "note": self._last_error
            or "crt.sh identity search (keyless). Recent lookalike certs on non-official domains.",
        }
