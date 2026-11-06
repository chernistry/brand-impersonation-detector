# Contributing

## Development setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,console]"
.venv/bin/python -m pytest -q
.venv/bin/bid run
```

`bid run` executes the whole pipeline on the bundled fixtures with no network
and no keys, and exits non-zero when a signed receipt fails verification. Run it
before opening a pull request, together with the tests and `ruff check bid tests`.

## Ground rules

- **Determinism.** Fixture runs are byte-reproducible: no wall clock, no
  randomness without a fixed seed, no network in the default path. Time and
  keys are parameters. `bid replay` must stay green.
- **Evidence compatibility.** A change to `EvidenceManifest`, `GovernanceRecord`
  or a projection is a schema change: bump the schema string
  (`bid.evidence/v2`, `bid.projection.<kind>/v1`, ...), keep the old verifier
  path working, and record it in `CHANGELOG.md`.
- **Egress.** Every outbound HTTP request goes through `bid.net` with a
  component name, so deployment profiles can allow or deny it. A new sensor adds
  its hosts to `bid/profiles/sovereign.json` only if it is meant to run there.
- **Untrusted input.** Scraped text and images are untrusted. They never reach
  the console as HTML and never reach a model prompt outside the delimited
  untrusted-content block.
- **Fixtures.** Brands, handles, domains and logos in fixtures are invented
  and use the reserved `.test` TLD. Do not add real organisations' names or
  marks to fixtures or tests.
- **Tests.** New behaviour comes with a test that fails without it.

## Pull requests

Keep a pull request to one change. Describe what changes and how it was
verified. CI runs the tests on Python 3.11 to 3.13, a secret scan, the linter
and a container build.

## Licence

The project is licensed under Apache-2.0. Contributions are accepted under the
same licence, as described in section 5 of the [LICENSE](LICENSE).
