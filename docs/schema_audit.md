# SideloadGuard Day 1 Schema Audit

## Resolution

- **Blocker 1, `file.claimed_filename`: fixed.** The schema now permits omission and `null`.
- **Blocker 2, raw-token safety: fixed.** Bot-token-like sequences are rejected in the specified free-text fields, params strings, and fixture-wide test scans.
- **Blocker 3, rule positive/negative coverage: deferred to M2.** A dormant guard test was added at `tests/test_rule_test_coverage.py`; it passes until rules exist, then requires matching positive and negative coverage.

## 1. Summary

Overall status: **FAIL**.

The schema and eight fixtures are internally consistent for the implemented Day 1 cases, and the throwaway tests reject all six requested malformed records. However, the release should not pass because `claimed_filename` is required and non-null despite `analyze_apk(..., claimed_filename=None)`, because the schema can accept raw token-like text in free-text fields even though the contract forbids raw tokens, and because the test suite does not cover positive and negative synthetic cases for every rule required by CONTRACT.md Section 7 R1 item 8.

## 2. Audit 1: Section 5.1 field coverage

| Field name exactly as the contract writes it | Present in schema? | Type in schema vs type implied by the contract | Required or optional in schema, and whether the contract implies that | Verdict |
|---|---|---|---|---|
| `schema_version` | yes | Schema: string with fixed value `1.0`; contract names the field but gives no type or allowed value | Required in schema; contract does not explicitly say required or optional | MISMATCH |
| `job_id` | yes | Schema: string UUID-v4-style pattern; contract: UUID v4 string | Required in schema; contract implies required | OK |
| `analysis_version` | yes | Schema: string pattern beginning with optional `v` and digits; contract names the field and says R1 bumps it; no exact type/value syntax | Required in schema; contract implies required | MISMATCH |
| `analysis_status` | yes | Both: string; schema enum `ok`, `partial`, `failed` | Required in schema; contract implies required | OK |
| `failure_reason` | yes | Both: one of the five listed values or null | Required in schema; contract implies required | OK |
| `file` | yes | Both: object | Required in schema; contract implies required | OK |
| `file.sha256` | yes | Both: lowercase hexadecimal SHA-256, 64 characters | Required in schema; contract implies required | OK |
| `file.size_bytes` | yes | Schema: non-negative integer; contract gives no explicit type but size in bytes implies integer | Required in schema; contract implies required | OK |
| `file.detected_type` | yes | Schema: string enum `apk`, `invalid_apk`, `zip`, `unknown`; contract gives no enum or allowed values | Required in schema; contract type/enum is not explicit | MISMATCH |
| `file.claimed_filename` | yes | Schema: required, non-empty string; contract names an in-memory filename and the interface permits `claimed_filename=None` | Required and non-null in schema; contract does not clearly say required or type, but the interface default makes optional/null plausible | MISMATCH |
| `app` | yes | Both: object | Required in schema; contract implies required | OK |
| `app.label` | yes | Schema: string; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `app.package_name` | yes | Schema: string; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `app.version_name` | yes | Schema: string or null; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `app.min_sdk` | yes | Schema: integer or null, minimum 1; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `app.target_sdk` | yes | Schema: integer or null, minimum 1; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `certificate` | yes | Both: object | Required in schema; contract implies required | OK |
| `certificate.signed` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `certificate.sha256_fingerprints[]` | yes | Both: array of lowercase 64-character SHA-256 strings | Required in schema; contract names it, not optional | OK |
| `certificate.subject` | yes | Schema: string or null; contract gives no explicit type or null rule | Required in schema; contract names it, not optional | OK |
| `certificate.self_signed` | yes | Schema: boolean or null; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `certificate.debug_cert` | yes | Schema: boolean or null; contract gives no explicit type | Required in schema; contract names it, not optional | OK |
| `permissions` | yes | Both: object | Required in schema; contract implies required | OK |
| `permissions.requested[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `permissions.dangerous[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `components` | yes | Both: object | Required in schema; contract implies required | OK |
| `components.has_launcher_activity` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.has_accessibility_service` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.has_device_admin` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.has_sms_receiver` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.requests_install_packages` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.requests_overlay` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.embedded_apk_or_dex` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `components.dynamic_code_loading` | yes | Both: boolean | Required in schema; contract names it, not optional | OK |
| `indicators` | yes | Both: object | Required in schema; contract implies required | OK |
| `indicators.urls[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `indicators.domains[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `indicators.ip_addresses[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `indicators.cloud_endpoints[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |
| `indicators.token_hashes[]` | yes | Both: array of lowercase 64-character SHA-256 strings | Required in schema; contract implies required and no raw tokens | OK |
| `rule_hits[]` | yes | Both: array of objects | Required in schema; contract implies required | OK |
| `rule_hits[].rule_id` | yes | Both: string matching `SG-<CAT>-<NNN>` | Required inside every item; contract implies required | OK |
| `rule_hits[].category` | yes | Both: string, enum of `SMS`, `ACC`, `OVL`, `DRP`, `HID`, `EXF`, `IMP`, `OBF` | Required inside every item; contract implies required | OK |
| `rule_hits[].severity` | yes | Both: enum `low`, `medium`, `high` | Required inside every item; contract implies required | OK |
| `rule_hits[].reason_code` | yes | Schema: uppercase-letter-first alphanumeric/underscore string; contract names an initial master-list code | Required inside every item; contract implies required | MISMATCH |
| `rule_hits[].params` | yes | Schema: object; contract gives no type or shape | Required inside every item; contract does not specify | MISMATCH |
| `rule_hits[].evidence_short` | yes | Both: string; contract describes developer-only text | Required inside every item; contract implies required | OK |
| `impersonation` | yes | Both: object | Required in schema; contract implies required | OK |
| `impersonation.claimed_brand` | yes | Both: string or null | Required in schema; contract implies required and allows null | OK |
| `impersonation.match_basis` | yes | Schema: enum `name`, `package`; contract: enum `name`, `package` | Required in schema; contract implies required | OK |
| `impersonation.cert_matches_reference` | yes | Both: boolean or null | Required in schema; contract implies required | OK |
| `impersonation.confidence` | yes | Both: number 0 through 1 | Required in schema; contract implies required | OK |
| `registry_entry_id` | yes | Schema: optional string hook; contract describes this as an optional hook | Optional in schema; contract explicitly implies optional | OK |
| `features` | yes | Both: object/flat number-bool map | Required in schema; contract implies required | OK |
| `warnings[]` | yes | Both: array of strings | Required in schema; contract implies required | OK |

Every object in the schema has `additionalProperties: false`, including `features`, `rule_hits[].params`, and `registry_entry_id`'s parent object. The schema has no top-level or nested field beyond Section 5.1 except the explicitly contracted `registry_entry_id` hook and the feature names supplied by the contract-referenced `features.md`. The feature-name keys themselves are not named literally in Section 5.1, but the contract directs R1 to maintain them in `features.md`.

Notable feature-map mismatch: the schema requires all 22 feature keys, although Section 5.1 only establishes that `features` is a flat number/bool map and does not name or require those keys. It also makes all 22 keys the complete allowed set. This could reject a Findings Record that is valid under the contract but contains a newer R2 feature or omits an unavailable feature.

## 3. Audit findings

### Blockers

- **`shared/schemas/findings_record.schema.json`, `properties.file.properties.claimed_filename`**
  - Location: `properties.file.required`, `properties.file.claimed_filename`
  - What is wrong: `claimed_filename` is required and cannot be null, while `analyze_apk(path, job_id, claimed_filename=None)` makes no filename a legitimate default and the cache stores findings with the filename stripped. The contract's 5.1 wording does not clearly decide storage, but the public interface can provide `None`.
  - Suggested fix: Make `claimed_filename` optional and permit `null`, or define a contract-approved sentinel and make that explicit.

- **`shared/schemas/findings_record.schema.json`, free-text fields**
  - Location: `app.label`, `app.package_name`, `certificate.subject`, `rule_hits[].params`, `rule_hits[].evidence_short`, URL/domain arrays and several other string fields
  - What is wrong: Raw token-like text can pass in any free-text field. Restricting `indicators.token_hashes[]` is necessary but does not prevent a raw token in `evidence_short`, `params`, `label`, or a URL-like value. This conflicts with Section 9's requirement that only hashes be stored and no raw tokens be written.
  - Suggested fix: The contract/schema must define a schema-wide raw-secret prohibition and tests must validate every string field, or fields must be constrained so developer evidence cannot carry extracted secrets.

- **`tests/test_findings_fixtures.py`, rule coverage**
  - Location: fixture-validation test and full test module
  - What is wrong: There are no positive and negative synthetic cases for every rule. The fixtures provide several positive examples and no negative rule cases. This fails CONTRACT.md Section 7 R1 item 8.
  - Suggested fix: Add a table-driven positive fixture and negative fixture for every rule ID, and test that the negative data has no matching hit.

### Should fix

- **`shared/schemas/findings_record.schema.json`, `schema_version`**
  - Location: `properties.schema_version`
  - What is wrong: A fixed `const: "1.0"` is invented: Section 5.1 names `schema_version` but does not specify its value or format.
  - Suggested fix: Choose a contract-approved format, or remove the const until it is specified.

- **`shared/schemas/findings_record.schema.json`, `analysis_version`**
  - Location: `properties.analysis_version`
  - What is wrong: The pattern guesses a string format with an optional `v`. CONTRACT.md only says R1 bumps the version whenever extractor/rules change; it does not specify `v1.0` or that format.
  - Suggested fix: Adopt a documented version format in the contract or use a minimally restrictive string type.

- **`shared/schemas/findings_record.schema.json`, `file.detected_type`**
  - Location: `properties.file.properties.detected_type`
  - What is wrong: The values `apk`, `invalid_apk`, `zip`, and `unknown` are invented. The contract provides no allowed enum.
  - Suggested fix: Approve and document the detected-type enum in Section 5.1 or reduce the schema to a string pending approval.

- **`shared/schemas/findings_record.schema.json`, `rule_hits[].reason_code`**
  - Location: `properties.rule_hits.items.properties.reason_code`
  - What is wrong: The pattern only accepts uppercase-letter-first alphanumeric/underscore strings. It does not require master-list membership, and it does not verify exact snake/upper-snake formatting such as separators. JSON Schema cannot know the external master list.
  - Suggested fix: Keep a UPPER_SNAKE pattern and have tests verify every emitted code against `reason_codes.json`.

- **`shared/schemas/findings_record.schema.json`, `rule_hits[].params`**
  - Location: `properties.rule_hits.items.properties.params`
  - What is wrong: The schema forces an object with no additional properties and invents no contract shape. An ordinary rule may legitimately need scalar, array, or nullable parameters.
  - Suggested fix: Approve a params shape in the contract, or use a conservative JSON value shape until it is defined.

- **`shared/schemas/findings_record.schema.json`, `features`**
  - Location: `properties.features.required` and `properties.features.additionalProperties`
  - What is wrong: All 22 current feature keys are required and no unknown feature is allowed. The contract says only that `features` is a flat number/bool map and names live in `features.md`; it does not say every feature is mandatory or that the set is closed.
  - Suggested fix: Make feature keys optional within a closed documented name set, or add a contract-approved feature-key registry and versioning rule.

- **`shared/schemas/findings_record.schema.json`, unknown-data fields**
  - Location: `app.label`, `app.package_name`, `certificate.subject`, `certificate.sha256_fingerprints`, and SDK fields
  - What is wrong: On failed/partial results the contract is silent about whether unknown app/certificate fields must be objects with `null` values or empty strings/arrays. The schema allows the first but requires `label`, `package_name`, and `subject` to have no null unless the subject field is null. The failed fixture uses empty strings for unknown app identity.
  - Suggested fix: Contractually define failed/partial nullability for app and certificate fields, then make the schema match one consistent representation.

- **`shared/reason_codes.json`, `en_text`**
  - Location: `ACCESSIBILITY_ABUSE`, `EXFIL_BOT_TOKEN`, `EXFIL_CLOUD_ENDPOINT`, `OBFUSCATED_OR_PACKED`, `IMPERSONATION_CERT_MISMATCH`, `MODEL_HIGH_RISK`, `NOT_ANALYSABLE`
  - What is wrong: Several explanations use technical terms such as accessibility, bot, cloud, packed, signing certificate, and high risk without plain explanations for a non-technical senior citizen.
  - Suggested fix: Replace jargon with shorter plain-language descriptions, for example: "special screen-reading access", "fixed external address", "hidden or compressed app", "official signing record", and "risk assessment". Keep calm and non-blaming wording.

- **`tests/test_findings_fixtures.py`, exact master-list check**
  - Location: `test_fixture_validates_and_reason_codes_match`
  - What is wrong: The test verifies fixture reason codes are members of the master list. It does not verify that `reason_codes.json` contains exactly the 19 contracted codes and no extras or omissions.
  - Suggested fix: Load the exact Section 5.5 code list and assert set equality.

### Nice to have

- **`shared/schemas/findings_record.schema.json`, UUID and hash patterns**
  - Location: `properties.job_id.pattern`
  - What is wrong: The UUID pattern accepts uppercase hexadecimal characters. UUID v4 itself has no lowercase requirement, so this is not a contract mismatch; it is only less deterministic than the fixture/test regex.
  - Suggested fix: If job IDs must be canonical lowercase, document that explicitly. Otherwise no change is required.

- **`shared/schemas/findings_record.schema.json`, numeric features**
  - Location: `properties.features.properties.*number*`
  - What is wrong: Count features are typed `number`, so non-integral values are accepted. CONTRACT.md calls them features and examples are counts, but it does not explicitly require integers.
  - Suggested fix: Add `type: integer` and `minimum: 0` for count features once that format is contract-approved.

- **`shared/reason_codes.json`, severity/source audit**
  - Location: each reason-code entry
  - What is wrong: The contract defines source values and default severity fields but does not mandate a particular severity for every code. The selected sources and severities are reasonable M0 choices, not contract violations.
  - Suggested fix: Record future severity changes through contract review rather than treating them as fixed.

## Audit 2: enums and patterns

- **`analysis_status`**: Exact match: `ok`, `partial`, `failed`.
- **`failure_reason`**: Exact match: null, `packed_obfuscated`, `invalid_apk`, `timeout`, `unpack_limit`. The conditional logic and schema enum reject invalid combinations.
- **Severity**: Exact match: `low`, `medium`, `high` is used in rule-hit and reason-code data.
- **Impersonation**: `match_basis` exactly allows `name` and `package`. `confidence` has minimum 0 and maximum 1.
- **`job_id`**: Pattern requires an RFC-style UUID v4 shape. It permits uppercase hexadecimal. The contract only requires UUID v4, so the uppercase allowance is not an exact mismatch.
- **SHA-256**: File SHA-256 and token-hash patterns require exactly 64 lowercase hexadecimal characters. Certificate fingerprints use the same pattern.
- **Timestamps**: The Findings Record has no timestamp field, so there is no Findings Record timestamp pattern to compare. Any future timestamp field must be ISO 8601 UTC with `Z`.
- **Rule IDs**: Exact pattern `^SG-(SMS|ACC|OVL|DRP|HID|EXF|IMP|OBF)-[0-9]{3}$`.
- **Snake case**: Core JSON keys are snake_case. Enum values are snake_case where CONTRACT.md requires strings such as `analysis_status` and `failure_reason`. Uppercase categories are required by the rule-ID/category contract and are an explicit naming-system exception rather than a snake_case enum. Reason codes are UPPER_SNAKE in the fixtures/master list and the schema pattern restricts reason codes to uppercase letters, digits and underscores.
- **`schema_version`**: The schema fixes `1.0`, but Section 5.1 does not specify or imply that exact value. The field should either be contractually fixed or treated minimally.

## Audit 3: logic and strictness

### Object strictness

`additionalProperties: false` is present on the root object and every named object: `file`, `app`, `certificate`, `permissions`, `components`, `indicators`, `rule_hits[].item`, `rule_hits[].params`, `impersonation`, and `features`. No object below the root is missing the setting.

### Conditional logic

The schema rejects `analysis_status: "ok"` with a non-null failure reason and rejects `partial` or `failed` with a null or missing failure reason. It also restricts partial/failed reasons to the four allowed non-null enum values.

In-memory throwaway validation with the benign fixture as a base produced:

| Invalid record | Result |
|---|---|
| `ok` with a failure reason | REJECTED |
| `failed` with null failure reason | REJECTED |
| 63-character SHA-256 | REJECTED |
| Uppercase SHA-256 | REJECTED |
| Rule ID with unknown category `XYZ` | REJECTED |
| Extra unknown top-level field | REJECTED |

### Raw-token and claimed-filename behavior

`indicators.token_hashes[]` accepts only lowercase 64-character SHA-256 strings. It cannot accept a raw Telegram-style token in that field. However, the schema can accept raw token text in free-text fields. It does not enforce the global no-token rule in `evidence_short`, `params`, `app.label`, URLs, domains or warning text.

`file.claimed_filename` cannot be absent and cannot be null. This conflicts with the plausible interpretation of `claimed_filename=None` in `analyze_apk()`.

Unknown values:

- `app.version_name`, `app.min_sdk`, and `app.target_sdk` may be null.
- `certificate.subject`, `certificate.self_signed`, and `certificate.debug_cert` may be null.
- `app.label`, `app.package_name`, `certificate.signed`, and `certificate.sha256_fingerprints` cannot represent unknown state as null; some could be empty values or empty arrays. The contract does not specify how failed/partial unknown fields should be encoded consistently.

## Audit 4: fixtures and tests

Exactly eight fixture JSON files exist. They cover all requested categories:

- `benign_app.json`: benign, no rule hits, valid non-debug certificate
- `sms_stealer.json`: SMS interception hit and SMS receiver
- `dropper.json`: dropper hit with embedded payload and dynamic code loading
- `impersonation.json`: fictional Example Bank, certificate mismatch and name lookalike
- `could_not_analyse.json`: failed invalid APK fixture
- `accessibility_overlay.json`: accessibility and overlay hits
- `hidden_icon_exfil.json`: hidden launcher and bot-token exfiltration
- `partial_packed.json`: partial packed/obfuscated result

The fixtures semantically agree with their core flags and feature maps:

- The benign fixture has no rule hits and no high-severity hits.
- The SMS fixture declares two SMS dangerous permissions and `has_sms_receiver: true`.
- The dropper fixture has both `embedded_apk_or_dex` and `dynamic_code_loading` true.
- The impersonation fixture sets `cert_matches_reference: false` and 0.92 confidence.
- The failed fixture has `failure_reason: invalid_apk`, null/empty minimal app/certificate data and zero counts.
- The accessibility fixture declares both components and has matching permission/request flags.
- The hidden-icon fixture sets `has_launcher_activity: false`, and bot exfiltration uses only a 64-character hash.
- The partial fixture has a packed/obfuscated reason and one high-severity hit.
- Permission, indicator, certificate, component and rule-hit count features agree with the corresponding fields.

No fixture uses an identifiable real brand, real domain, real certificate fingerprint, raw token or known malware-style hash:

- Brands and labels are clearly fictional or Example-prefixed.
- URLs use `example[.]invalid` or `*.example[.]invalid`.
- Certificate fingerprints are 64-character repeated-digit strings.
- File hashes are 64-character synthetic strings of zeros plus a final fixture digit.
- The hidden-icon token hash is a 64-character synthetic hex string.

All rule-hit reason codes in the fixtures are present in `reason_codes.json`. The master list contains exactly the 19 codes listed in CONTRACT.md Section 5.5: no extra code and no omission was found.

The test file includes:

- category-segment/category-field matching: yes
- failed/partial invariant: yes
- raw Telegram-style token detection over all string values in fixtures: yes
- exact master-list set equality: no
- every rule positive and negative: no
- schema validation for all fixtures: yes
- mirrored feature consistency: yes

The test suite therefore misses the Section 7 R1 item 8 requirement for positive and negative synthetic/fixture coverage of every rule.

Reason-code text review:

- Most texts are calm and non-blaming.
- `ACCESSIBILITY_ABUSE` and `IMPERSONATION_CERT_MISMATCH` use technical terms that may be unclear to a senior citizen.
- `EXFIL_BOT_TOKEN`, `EXFIL_CLOUD_ENDPOINT`, and `OBFUSCATED_OR_PACKED` use security jargon such as bot, cloud, packed and hidden.
- `MODEL_HIGH_RISK` says proceed with caution, which is calm rather than alarmist.
- `NOT_ANALYSABLE` says the app may carry risk, which is candid and cautious rather than blaming or alarmist.
- None of the texts directly blames the user.

## 4. Audit 5: contract ambiguities and recommendations

1. **`file.claimed_filename` type, nullability and requiredness**
   - Contract options: required string; optional string; optional string or null; filename omitted after storage.
   - The interface default `claimed_filename=None` and cache stripping make optional/null more plausible.
   - Recommendation: Make it optional and nullable in the Findings Record, or document an empty-string sentinel and forbid null.

2. **`file.detected_type` allowed values**
   - Contract options: only `apk`/`invalid_apk`, a broader enum including `zip`/`unknown`, or an open string.
   - Recommendation: Define an explicit enum: at minimum `apk`, `invalid_apk`, `zip`, `unknown`; keep it additive for future types.

3. **`rule_hits[].params` shape**
   - Contract options: arbitrary object, typed key-value object, string/array/number values, or per-rule schemas.
   - Recommendation: At M0, require an object with contract-approved optional scalar fields; defer rule-specific complex shapes until R2/R4 specify them.

4. **`match_basis` with no impersonation match**
   - Contract options: always `name` or `package`, or add `null`/`unknown`.
   - Recommendation: Do not allow null until no-match semantics are contractually defined; fixtures can use `name` conservatively for non-match records.

5. **`schema_version` value and format**
   - Contract options: fixed `1.0`, semantic-version string, or integer major/minor structure.
   - Recommendation: Fix it in Section 5.1 as a semantic version such as `1.0` and use `const` once the contract approves it.

6. **`analysis_version` format**
   - Contract options: `v1.0`, `1.0`, a build hash, or an implementation-defined string.
   - Recommendation: Define a simple semantic version pattern and document cache-key behavior.

7. **Failed/partial app and certificate representation**
   - Contract options: required objects with empty strings/arrays, required objects with nulls, or allow the entire `app`/`certificate` objects to be absent.
   - Recommendation: Keep the objects required for a stable top-level shape, but contractually allow known unknown fields to be null and arrays to be empty.

8. **Failed/partial `match_basis` and claimed brand**
   - Contract options: retain normal enum/string values, use null for both, or omit impersonation results.
   - Recommendation: Keep the object and fields required; use `claimed_brand: null`, `match_basis: "name"` or `package` only when a comparison has a basis, and add `unknown` if the team needs an explicit no-comparison state.

9. **Features map key closure and requiredness**
   - Contract options: fixed feature names, open map, or versioned recommended feature set.
   - Recommendation: Add a fixed `features.md` v1 key set, make keys optional for backward compatibility, and require values to be integer where a count.

10. **Feature count types**
    - Contract options: `number` as contract text says, or integer for counts.
    - Recommendation: Use integer and minimum 0 for count features; keep booleans as bool.

11. **Certificate fingerprint unknown state**
    - Contract options: empty array, array plus signed false, or null array.
    - Recommendation: Use an empty array for no fingerprints and `signed: false`, as the failed fixture does; document null only for subject/unknown booleans.

12. **Raw-token prohibition in JSON schema**
    - Contract options: enforce only `token_hashes[]`, forbid all raw-token-shaped text anywhere, or rely on application tests.
    - Recommendation: Define a contract-level no-raw-token invariant and add a reusable schema/test pattern for every free-text field that can receive APK-derived or indicator text.
