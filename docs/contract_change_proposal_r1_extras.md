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
