# Contract Change Proposal: R1 Optional Findings Extras

## What

Propose five additive optional fields for future Findings Records: `manifest_flags` (list), `obfuscation_score` (number from 0 to 1), `icon_phash` (string), `certificate_reputation`, and evidence locations inside `rule_hits`. These fields are design proposals only and are not currently valid in `findings_record.schema.json`.

## Why

The optional fields would preserve room for later R1 evidence and scoring improvements without changing the current core record. They could help R2 add explainable optional signals while keeping M0 and M1 core behavior backward compatible.

## Who is affected

- R1 must define exact field shapes and produce values only after the optional feature is approved.
- R2 must decide whether and how to consume the fields and ensure missing values have a zero or safe feature default.
- R3 must allow these fields to remain in cached findings and must strip or redact evidence locations if they could expose internal storage details.
- R4 must not display raw evidence locations or optional technical values unless an approved explanation format is defined.
- Team reviewers must approve the exact types and names, add schema support, update fixtures and tests, and bump the contract version before implementation.

## Format clarifications requested by R4

The following Findings Record formats and constraints are reflected in the schema:

- `schema_version` is the fixed string `"1.0"`.
- `analysis_version` must match `^v?[0-9]+[A-Za-z0-9._-]*$`.
- `detected_type` is one of `apk`, `zip`, `other`, or `unknown`.
- Add `analysis_error` to `failure_reason` for an unexpected internal error. This value means "unexpected internal error, not a statement about the file". An `ok` record must still have a null failure reason; `partial` and `failed` records must have a non-null enum value.
- Set maximum string lengths while retaining existing patterns: `app.package_name` 256, `app.version_name` 256, each `indicators.urls` item 2048, each `indicators.domains` item 253, each `indicators.cloud_endpoints` item 2048, and `certificate.subject` 500.
- Keep all existing feature keys required with their current types. Additional feature keys may be added only with number or boolean values; R2 must document each additional key in `shared/schemas/features.md`.

## Exit code for analysis_error

The CLI exits with code 1 when `failure_reason` is `analysis_error` (an unexpected internal error, not a statement about the file). Codes 0, 2, 3 and 4 are unchanged. R3 should treat 1 as "retry once, then report 'could not analyse'".
