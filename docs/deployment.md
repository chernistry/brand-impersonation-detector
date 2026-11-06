# Deployment

The detector runs on infrastructure you control: a laptop, a VM or a container.
It needs no account with any service to run on the bundled fixtures. Live
sensors and hosted models are opt-in.

## Install

Python 3.11 or later (tested on 3.12).

```bash
pip install -e ".[console]"          # pipeline, CLI and operator console
pip install -e ".[console,embeddings]"   # adds CLIP logo similarity and text embeddings
```

All runtime state goes to `$BID_DATA_DIR` (default `./.bid`); see
[architecture.md](architecture.md#runtime-data). Back up that directory; nothing
else holds state.

## Keys

| Variable | Signs | Default |
|---|---|---|
| `BID_HMAC_KEY` | the internal HMAC chain of receipts and journal records | public development value |
| `BID_ED25519_SEED` | the Ed25519 key behind every DSSE signature (key = SHA-256 of the seed) | public development value |
| `BID_LEDGER_KEY` | the analyst label ledger | public development value |
| `BID_CONSOLE_TOKEN` | console access | none |

The development values make fixture runs reproducible; anyone can sign under
them, so receipts made with them prove nothing. Generate real values and keep
them in your secret store:

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
```

An empty variable counts as unset. The console refuses to listen on anything
but loopback while any signing key is still a development value, and prints a
notice when it runs on loopback with them.

**Public key.** Every run directory holds `ed25519_pubkey.txt`, and `bid run`
prints the key. Publish it through a channel you control, so reviewers can pin
it with `bid verify --pubkey`.

**Rotation.** A new seed is a new key: start a new chain (a new run directory)
under it and publish each key with the period it was in use. Old receipts stay
verifiable under the old key.

**KMS or HSM.** Signing goes through the `EvidenceSigner` protocol
([`bid/models.py`](../bid/models.py)). To keep the private key in a KMS or HSM,
implement `package()` with the same canonical manifest and DSSE envelope and
call the key service for the signature.

## Container

The image builds wheels in a throwaway stage and runs as an unprivileged user
with all state in `/data`.

```bash
for v in BID_CONSOLE_TOKEN BID_HMAC_KEY BID_ED25519_SEED BID_LEDGER_KEY; do
  export "$v=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
done
docker compose up --build              # console on http://127.0.0.1:8000
docker compose run --rm console run    # one pipeline run in the same image
```

The compose file requires the four secrets, publishes the port on loopback only,
mounts the root filesystem read-only with a tmpfs `/tmp`, drops all
capabilities and sets `no-new-privileges`. Put a TLS-terminating reverse proxy
in front of it before exposing it.

## Console

```bash
bid console                                    # http://127.0.0.1:8799, opens a browser
bid console --no-open --port 8000
BID_CONSOLE_TOKEN=... bid console --host 0.0.0.0 --profile sovereign
```

| Option | Meaning |
|---|---|
| `--host`, `--port` | listen address (default `127.0.0.1:8799`) |
| `--no-open` | do not open a browser |
| `--brands` | brand file for console runs (default: the bundled fictional brands) |
| `--governance` | governance settings file ([governance.md](governance.md#settings)) |
| `--policy-pack` | policy pack bound into every receipt ([policy-packs.md](policy-packs.md)) |
| `--profile`, `--deployment-id` | deployment profile to apply and attest (below) |

Access:

- Loopback by default. Any other address needs `BID_CONSOLE_TOKEN`; every API
  call then needs it as a bearer header, or the session cookie the sign-in box
  sets (HttpOnly, SameSite=Strict, derived from the token, never the token itself).
- The token admits people; it does not tell them apart. For per-person identity,
  run behind an authenticating proxy and set `BID_CONSOLE_ACTOR_HEADER`
  ([governance.md](governance.md#identity-in-the-console)).
- The page loads nothing from other origins, carries a per-request script nonce
  in its Content-Security-Policy, and renders scraped content as text.
- Secrets are read from the environment and never sent to the page.

## Profiles and attestation

A deployment profile sets four controls for the whole process:

| Control | Meaning |
|---|---|
| `egress` | per-component host allowlist (`null` = unrestricted) |
| `redact_pii` | remove PII from scraped text before any hosted model call |
| `zero_retention` | request zero-data-retention routing from the model API |
| `llm_base_url` | model endpoint (`null` = `BID_LLM_BASE_URL`, else OpenRouter) |

Two profiles are bundled: `default` (unrestricted, the behaviour without a
profile) and `sovereign` ([`bid/profiles/sovereign.json`](../bid/profiles/sovereign.json)).
`--profile` takes a bundled name or a path to your own JSON file.

```bash
bid run --profile sovereign --deployment-id brand-protection-eu
```

With `--profile`, the profile is applied, then the settings actually in effect
are read back from the running process and recorded in the governance journal as
a `deployment_attestation`: profile name and SHA-256, the effective egress
policy, model endpoint (without credentials), redaction and retention settings,
whether the timestamp anchor may leave the host, package and dependency
versions, and `profile_in_effect`, which is true only when the runtime settings
equal what the profile declares. The attestation's hash goes into every receipt
signed in that run (`attestation_hash`).

## Egress

Every outbound HTTP request the package makes goes through `bid.net` under a
component name. The active profile decides which hosts each component may
reach. The check runs on every hop of a redirect.

| Component | Used by |
|---|---|
| `classifier` | hosted model calls |
| `enrich` | public-source pivot: certificate search, RDAP, DNS-over-HTTPS, scan search, block lists |
| `enrich:favicon` | favicon fetch for favicon-hash search |
| `sensor:ct_logs`, `sensor:bluesky`, `sensor:itunes`, `sensor:meta_ad_library`, `sensor:username_enum` | live sensors |
| `allowlist` | popularity-list download |
| `brand_kb` | brand knowledge base build |
| `asset_fetch` | asset downloads |
| `anchor` | RFC-3161 timestamp request |

The `sovereign` profile allows a fixed host list per component and denies
username enumeration, asset downloads, favicon fetches and the timestamp anchor.
RDAP lookups go to `rdap.org`, which answers with a redirect to the registry's
own server; that server is not listed, so RDAP is refused at the redirect.

Not covered by `bid.net`:

- the model download of the optional embeddings extra (fastembed fetches
  models from Hugging Face on first use; pre-load them into its cache for an
  isolated host);
- system DNS lookups, such as the private-address check before a favicon fetch;
- any code you add that builds its own HTTP client.

`bid.net` guards the package's own call sites; it is not a sandbox. Enforce
egress at the network layer as well.

## Model endpoint

| Variable | Meaning |
|---|---|
| `BID_LLM_BASE_URL` | OpenAI-compatible endpoint, for example a self-hosted model server |
| `BID_LLM_API_KEY` | key for that endpoint |
| `OPENROUTER_API_KEY` | used only when the endpoint is `openrouter.ai`; never sent to another host |

`--live` uses the hosted model; without it the rule-based classifier runs and
nothing leaves the host for classification. Zero-data-retention routing applies
to OpenRouter only; a self-hosted endpoint's retention is set by its operator.

With `redact_pii`, e-mail addresses, phone numbers, Luhn-valid card numbers and
mod-97-valid IBANs are replaced before the model call. URLs, domains and IP
addresses are kept, since they are the indicators. The deterministic signals
are always computed on the unredacted text, and each verdict records how many
spans were removed.

## Other variables

| Variable | Meaning |
|---|---|
| `BID_DATA_DIR` | runtime data directory (default `./.bid`) |
| `BID_CONTACT` | contact appended to the User-Agent of outbound requests; public APIs ask automated clients for one |
| `META_AD_LIBRARY_TOKEN` | Meta Ad Library sensor |
| `SHODAN_API_KEY` | favicon-hash search during enrichment (optional) |
| `BID_BRAND_RECORDS_DIR` | local directory of brand records for larger rosters ([`bid/brand_gallery.py`](../bid/brand_gallery.py)) |
| `JAILBREAK_CORPUS_CSV` | local prompt corpus for `bid adversarial --corpus` |
| `HF_TOKEN` | optional, read by the Hugging Face client when the embeddings extra downloads models |

With `--live` or `--sensors broad`, `bid run` reads a `.env` file in the working
directory for API keys; it never overrides a variable that is already set.
Signing keys are read when the package loads, so set them in the environment,
not in `.env`.

## Brands

`--brands` takes a JSON file of your brands, keyed by brand id:

```json
{
  "covelle": {
    "id": "covelle",
    "name": "Covelle Pay",
    "official_handles": ["covellepay", "covelle_pay"],
    "official_logo_assets": ["assets/covelle_official_logo.png"],
    "regions": ["US"]
  }
}
```

Logo paths are relative to the file. A `brand_kb.json` next to it adds aliases
and official domains per brand name (`{"Covelle Pay": {"aliases": [...],
"domains": ["covelle-pay.test"]}}`); `bid brand-kb build "<brand name>" --kb
<dir>/brand_kb.json` drafts entries from Wikidata for you to review. The bundled [`bid/fixtures/`](../bid/fixtures/) shows both files
with fictional brands on reserved `.test` domains.

## Operations checklist

- [ ] Four secrets generated and stored; none on development values.
- [ ] Public key published; reviewers know where to find it.
- [ ] `governance.json` in `$BID_DATA_DIR` with your people.
- [ ] `bid governance escalate` scheduled.
- [ ] Console behind TLS; actor header set if a proxy authenticates users.
- [ ] Profile chosen and attested; egress also enforced at the network layer.
- [ ] `$BID_DATA_DIR` backed up.
