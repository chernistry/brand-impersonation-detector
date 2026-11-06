# Threat model

Scope: the pipeline, the signed records, the operator console and the
command-line tools, as deployed by one organisation on infrastructure it
controls. Reporting instructions are in [SECURITY.md](../SECURITY.md).

## What is protected

| Asset | Why it matters |
|---|---|
| Signed receipts and their chain | they are the record of what was seen and decided; a reviewer relies on them |
| Signing keys (`BID_HMAC_KEY`, `BID_ED25519_SEED`, `BID_LEDGER_KEY`) | whoever holds them can sign records |
| Governance journal | who stopped the queue, which holds went overdue, which settings were in force |
| Analyst decisions and labels | they move findings and calibration |
| Scraped content | may contain personal data of third parties |
| Model and data-source API keys | cost and account exposure |
| Console access | the console signs decisions on a person's behalf |

## Trust boundaries

| Boundary | Trust |
|---|---|
| Scraped text, images and links | untrusted; written by whoever runs the suspect account |
| Hosted model provider | trusted to answer, not trusted with more data than needed |
| Public data sources (certificate logs, DNS-over-HTTPS, RDAP, scan search) | trusted for availability only; answers are observations |
| Console users | trusted per role; identity is only as strong as the deployment's authentication |
| Third-party reviewers | hold the public key and the run directory; no secret |
| The host running the tool | trusted; it holds the keys |

## Threats and controls

| # | Threat | Control | Residual |
|---|---|---|---|
| 1 | A receipt is forged or edited after signing | Ed25519/DSSE signature over the canonical manifest; `bid verify --pubkey` pins the published key, checks the payload type and that every receipt in a chain uses one key | a reviewer who does not pin the key only learns the receipt is intact under the key it names |
| 2 | Asset bytes are swapped after the decision | assets are content-addressed; verification re-hashes every asset from the store | none within the store; the original platform content may change, which a receipt cannot prevent |
| 3 | A receipt is removed from or moved within a chain | each manifest signs the hash of the previous one | removing receipts from the end needs the optional RFC-3161 chain-head timestamp to detect (`bid run --anchor`); the timestamp authority's certificate chain is not validated |
| 4 | Records are signed with the public development keys | the console refuses to listen beyond loopback while any signing key is a development value; the compose file requires real keys | `bid run` on a workstation still uses them by default, by design, for reproducible fixture runs |
| 5 | A signing key leaks | keys come from the environment or a secret store; the `EvidenceSigner` protocol lets a KMS or HSM hold the private key; a new key starts a new chain | a holder of the HMAC key can forge the internal chain; the public check depends on the Ed25519 key alone |
| 6 | Scraped text steers the model (prompt injection) | untrusted text is tagged and datamarked, the instruction hierarchy is explicit, output is schema-constrained, deterministic signals are computed outside the model, a semantic injection detector flags attempts and treats them as a positive signal; `bid adversarial` measures it | adaptive or optimised attacks are not covered by the bundled battery |
| 7 | Scraped content runs script in the console | content is rendered as text, never as HTML; per-request script nonce in the Content-Security-Policy; nothing loads from other origins | none known |
| 8 | Someone reaches the console who should not | loopback by default; any other address needs `BID_CONSOLE_TOKEN`; the session cookie is HttpOnly and SameSite=Strict and derived from the token | the token is shared; without `BID_CONSOLE_ACTOR_HEADER` behind an authenticating proxy, the acting person's name is typed, not authenticated |
| 9 | A release or a queue stop is done by someone without authority | only declared releasers may release, only declared stop authorities may stop or resume; every action is a signed record naming the actor and authority | the actor's identity is as strong as threat 8 allows |
| 10 | The governance journal is tampered with | HMAC chain and DSSE signatures, `bid governance verify --pubkey`; a journal that cannot be read counts as stopped | a journal that reads but fails verification is flagged, not blocked |
| 11 | Enrichment is used to reach internal addresses (SSRF) | the favicon fetch is HTTPS-only, follows no redirects and checks that the host resolves to a public address; the egress allowlist covers every redirect hop | the address check uses the system resolver |
| 12 | Personal data leaves for the model provider | `redact_pii` removes e-mail addresses, phone numbers, valid card numbers and IBANs; zero-data-retention routing on OpenRouter; a self-hosted endpoint via `BID_LLM_BASE_URL`; per-component egress allowlist | redaction is pattern-based; names and free-text details are not removed |
| 13 | An API key is sent to the wrong host | `OPENROUTER_API_KEY` is sent only to `openrouter.ai`; another endpoint gets `BID_LLM_API_KEY` only | none known |
| 14 | Secrets end up in shared records or messages | the attestation records the model endpoint without user info, query or fragment; egress refusals name the component and host, never the URL | none known |
| 15 | A console request reads files outside the run | the asset endpoint accepts only a 64-character lower-case hex content address | none known |
| 16 | Code or dependencies are tampered with | base image pinned by digest; wheels built in a separate stage; dependency versions recorded in the deployment attestation; CI runs a secret scan over the full history | dependencies are installed by version range, not hash-pinned |
| 17 | The egress allowlist is bypassed | every outbound HTTP request of the package goes through `bid.net`, checked on every redirect hop | `bid.net` is not a sandbox: the embeddings model download and system DNS lookups do not go through it; enforce egress at the network layer too |

## Not in scope

- Detection quality. A wrong verdict is a quality issue, handled by evaluation,
  calibration and the person who decides.
- Legal sufficiency or admissibility of the records in any jurisdiction.
- Terms of service and rate limits of the data sources; the operator chooses
  which sensors to run and is responsible for using them within those terms.
- Concurrent writers to one run directory. Appends are not locked; run one
  writer per run directory.
