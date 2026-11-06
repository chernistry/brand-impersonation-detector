"""
Sensor factory - the ONE place that decides which discovery vectors a run uses.

Two modes (each sensor's health() carries its own `mode`, which the console
renders as a live/mock pill):

  default  -> the deterministic, offline pair (LocalSearch mock + Meta Ad Library,
              which is live only when a token is present, else mock). This is what
              the tests and the byte-reproducible evidence core run on.

  broad    -> ALSO attaches the keyless internet sensors:
              Apple App Store (iTunes Search API), registered look-alike domains
              (dnstwist -> DoH resolve), and fresh look-alike TLS certs
              (Certificate Transparency via crt.sh). No API key or login needed.

Native ingestion from the large social networks is not implemented: the social
path in default mode is the LocalSearch fixture sensor. "Broad" means live App
Store + domains + CT, plus username enumeration and Bluesky when `social` is set.
The live sensors degrade to "yields nothing + error in health()" when the network
is unavailable, so a run never breaks; it just shows fewer live vectors. None of
the broad sensors touch the determinism digest - they are hash-anchored sidecars,
like the RFC-3161 timestamp.
"""
from __future__ import annotations

from .allowlist import Allowlist
from .local_search import LocalSearchSensor
from .meta_ad_library import MetaAdLibrarySensor


def build_sensors(brands=None, broad: bool = False, enrich: bool = False,
                  social: bool = True):
    """Return the ordered sensor list for a run.

    brands: used only in broad mode to seed the allowlist with the brands' own
            official domains, so a brand's own infrastructure is never emitted as
            a look-alike candidate.
    broad:  attach the real keyless internet sensors (App Store + look-alike domains
            + CT + username enumeration).
    enrich: let the typosquat/CT sensors do the optional crt.sh/urlscan follow-up.
    social: include the keyless social username-enumeration sensor (WhatsMyName)
            and the Bluesky search sensor.
    """
    sensors = [LocalSearchSensor(), MetaAdLibrarySensor()]
    if not broad:
        return sensors

    # Seed the allowlist with every brand's own registrable domains so the
    # look-alike sensors never flag the brand's real infra as an impersonation.
    own_domains: set[str] = set()
    for b in (brands or []):
        own_domains |= set(getattr(b, "official_domains", []) or [])
    allow = Allowlist(load_live=False, extra=own_domains or None)

    # Imported lazily so a default run needs neither dnstwist nor httpx.
    from .ct_logs import CTLogSensor
    from .itunes import ITunesSearchSensor
    from .typosquat import TyposquatSensor

    sensors += [
        ITunesSearchSensor(),
        TyposquatSensor(allowlist=allow, enrich=enrich),
        CTLogSensor(allowlist=allow),
    ]
    if social:
        # Live keyless social discovery: (1) predict look-alike handles
        # and confirm which are registered (username enumeration), (2) surface
        # unpredicted matches on the open Bluesky network by brand text.
        from .bluesky import BlueskySensor
        from .username_enum import UsernameEnumSensor
        sensors.append(UsernameEnumSensor(
            platforms=["Telegram", "TikTok", "Reddit"], max_permutations=8, delay=0.1))
        sensors.append(BlueskySensor(limit=25))
    return sensors
