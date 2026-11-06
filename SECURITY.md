# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Please do not open a
public issue for a suspected vulnerability.

A useful report names the affected version or commit, the component, how to
reproduce it, and what an attacker gains. Reports are acknowledged within
seven days. Fixes ship in a patch release with an advisory that credits the
reporter unless they ask otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Scope

In scope:

- Forging or altering an evidence receipt, a governance record or a release
  record so that verification still passes.
- Bypassing the egress allowlist of a deployment profile, or getting PII past
  redaction into a model request when redaction is on.
- Script injection in the operator console from scraped content (handles,
  bios, link text, image metadata).
- Prompt injection that changes a verdict without the verdict being flagged.
- Authentication bypass of the console when `BID_CONSOLE_TOKEN` is set.

Out of scope:

- Findings that need the HMAC key or the Ed25519 signing seed; these are
  secrets of the deployment.
- Receipts signed under the public development keys, which exist for
  reproducible fixture runs and prove nothing.
- A receipt accepted by `bid verify` without `--pubkey`: without a pinned key
  the result only shows the receipt is intact under the key it names.
- The console listening without a token on loopback, which is its documented
  local mode.
- Detection quality (a missed or wrong verdict). Open an ordinary issue with
  the input that was misclassified.

The threat model is in [docs/threat-model.md](docs/threat-model.md).
