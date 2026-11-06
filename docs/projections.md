# Report projections

A confirmed finding usually has to be filed in more than one place. A
projection turns one signed confirm into the payload one destination needs.
Nothing is sent: an operator reviews each payload and files it. Code:
[`bid/projections.py`](../bid/projections.py), [`bid/stix_export.py`](../bid/stix_export.py).

## Rules

- Only a receipt whose latest outcome is `confirm` is projected. A released
  confirm, an escalation or a reject is refused.
- The candidate and verdict must be the ones the receipt was signed over; their
  hashes are checked against the manifest.
- A projection is a pure function of the receipt, the candidate and the
  verdict: no clock, no network, no randomness. Two runs give byte-identical
  canonical bytes.
- Every projection except `stix` starts with the receipt anchor below; the STIX
  bundle carries the same anchor in its indicator's external reference.
- While the queue is stopped, nothing is projected
  ([governance.md](governance.md#queue-stop)).
- A statement the destination requires from the notifier (for example a
  good-faith statement) is made by the operator who files the report, never by
  this tool.

Anchor carried by every projection:

| Field | Content |
|---|---|
| `schema` | `bid.projection.<kind>/v1` |
| `manifest_hash`, `manifest_hmac` | identify the receipt; check it with `bid verify` |
| `policy_version` | thresholds, model and code revision that produced the verdict |
| `brand_id`, `decided_at` | brand and decision time (UTC) |
| `evidence` | asset hashes, context hash, signing public key |

## Kinds

| Kind | For | Main fields |
|---|---|---|
| `finding` | the internal findings log | `finding_id`, `platform`, `subject`, `label`, `confidence`, `reasoning`, `model_trace`, `outcome` |
| `platform_ip_report` | a platform's trademark or impersonation report form | `report_type`, `rights_owner`, `reported_content` (platform, account id, handle, display name, URL), `description`, `notifier_statement_required` |
| `registrar_abuse` | a registrar or hosting abuse desk | `domain`, `registrable_domain`, `abuse_type`, `evidence_urls`, `first_seen`, and `text`: a plain-text abuse report body |
| `fraud_desk` | a fraud-operations team | `case_id`, `channel`, `label`, `confidence`, `indicators` (handles, domains, URLs), `signals`, `review_checklist` |
| `stix` | a threat-intelligence platform | STIX 2.1 bundle: identity, indicator, and with a campaign graph, infrastructure and relationships |

`registrar_abuse` does not apply to a finding with no domain, or whose linked
domain is one of the brand's official domains; it is skipped with the reason.
STIX ids are derived with uuid5 from the manifest hash and content, so the
same receipt always yields the same ids.

## Use

```bash
bid project <candidate id> --kind all --run-dir <run-dir> --brand-name "Covelle Pay"
bid project <candidate id> --kind registrar_abuse --text    # abuse report body only
```

In the console, a confirmed card has an Export control with the same kinds.

## Checking a notice against a policy pack

A notice pack lists what a notice must contain under one rule and which
projection fields supply each element:

```bash
bid project <candidate id> --kind platform_ip_report > notice.json
bid packs check-notice notice.json --pack eu-dsa-art16
```

The check marks each requirement `met`, `gap` (a field the projection should
carry is empty) or `operator` (the operator adds it). See [policy-packs.md](policy-packs.md).
