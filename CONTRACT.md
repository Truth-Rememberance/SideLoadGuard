# SideloadGuard: Team Integration Contract (v0.1)

Team: Nidhi, Yuktaa, Sidhanth, Shravya. This is a draft: fill in the owner names in Section 1 and settle the open items at your first sync.

## 0. How to use this
- This is the single source of truth for how the four modules plug together. If code and this doc disagree, fix one of them the same day.
- Machine-readable versions of every format live in `shared/schemas/` (JSON Schema). The tables below are the human summary.
- **[CORE]** = must be delivered. **[OPTIONAL]** = built only if the team approves it (Section 10) once core is stable. Optional work sits behind a feature flag in `shared/config.defaults.yaml`, default `false`, so it can never break core.
- **Design hook** = a field or placeholder added now so an optional feature can be added later without a breaking change.

## 1. Roles
| Role | Owner | Owns | Folder / package |
|---|---|---|---|
| **R1 Analysis Engine and Registry** | Yuktaa | Intake validation, static extraction, YARA and custom rules, impersonation checks, official-app list, Findings Record format | `analysis/` · `sg_analysis` |
| **R2 Intelligence** | Nidhi | Datasets, features, classifier, evaluation, message analysis, risk scoring, verdict cut-offs | `intel/` · `sg_intel` |
| **R3 Platform, Bot and Safety** | Shravya | Docker sandbox runner, Telegram bot, FastAPI + SQLite, job queue, hash cache, indicator feed, campaigns | `backend/` · `sg_backend` |
| **R4 Web, Dojo and Explanations** | Sidhanth | Website, Inoculation Dojo, explanation and report engine, EN/KN/HI translations | `web/`, `explain/` · `sg_explain` |

**Group-wide (not a role):** field survey, awareness sessions, documentation, final report, demo video. Also prior-art search: each owner finds 2 to 3 recent papers for their area and lists them in `docs/papers.md`.

## 2. How a file travels
1. User sends a file (plus optional message text) via Telegram or the website, and picks a language. *(R3 bot, R4 web)*
2. R3 creates a job, applies size and rate limits, and checks the hash cache.
3. R3 runs the analyzer in the sandbox. R1's code returns a **Findings Record**.
4. R2 `analyze_message()` (if text given) and `score()` return a **Score Result**.
5. R4 `render_explanation()` writes the reply in the user's language.
6. R3 replies, deletes the file, and stores only anonymised indicators.
7. R3 serves the public feed and R4 displays it.

**Golden rule:** only R3 touches users, uploaded files, the database and Docker. R1, R2 and R4 libraries are **pure functions**: data in, JSON out. No network, no database, no global state.

## 3. Repo, tooling, Git
```
sideloadguard/
  CONTRACT.md
  shared/  schemas/  i18n/  registry/  fixtures/  reason_codes.json  config.defaults.yaml
  analysis/  intel/  backend/  web/  explain/
  docker/  docs/  tests/
  samples/   <- GIT-IGNORED, local only
```
- Python 3.11, one `requirements.txt` per package (pinned), `ruff` + `black`, `pytest`. CI (GitHub Actions) runs tests and validates **all fixtures against the schemas**.
- Branches: `main` is protected and always working. Work on `r1/short-name`, `r2/...`, `r3/...`, `r4/...`, and `shared/...` for contract changes.
- Pull requests are **reviewed by someone from a different role**, with tests green. Commits look like `[R1] add manifest parser` or `[SHARED] ...`.
- Secrets in `.env` (git-ignored) with a committed `.env.example`. Env vars start with `SG_`.
- **Never commit APK samples, malware or extracted tokens.** Only hashes and fake-data fixtures.
- **Stub first:** by milestone M1, every role publishes a working stub of its public function or API that returns fixture data, so nobody waits.

## 4. Naming and formats
| Thing | Rule |
|---|---|
| Python | files, functions, variables `snake_case`; classes `PascalCase`; constants `UPPER_SNAKE` |
| JSON keys and enum values | `snake_case` |
| Reason codes | `UPPER_SNAKE`, e.g. `SMS_INTERCEPTION` |
| Rule IDs | `SG-<CAT>-<NNN>`; CAT in `SMS ACC OVL DRP HID EXF IMP OBF` |
| IDs / hashes | UUID v4 for `job_id`; SHA-256 lowercase hex (64 chars) |
| Timestamps | ISO 8601 UTC with Z, e.g. `2026-11-13T10:30:00Z` |
| Languages | `en`, `kn`, `hi` (message analysis may also use `mixed`, `unknown`) |
| Verdicts (exact) | `safe_looking`, `suspicious`, `dangerous`, `could_not_analyse` |
| Severity | `low`, `medium`, `high` |
| Job status | `queued`, `running`, `done`, `failed`, `rejected` |
| API | base `/api/v1`, plural nouns, errors as `{error: {code, message}}` |
| Encoding | UTF-8 everywhere; fonts Noto Sans Kannada and Devanagari with fallback |
| Folder names | never `platform` (shadows a Python stdlib module), hence `backend/` |
| Wording | never show "safe" alone. Label is **Safe-looking** plus the disclaimer key `risk_assessment_not_guarantee` |

## 5. Data contracts [CORE]
Changes go through Section 10. **Additive only** (new optional fields) within version 1.x.

**5.1 Findings Record** (R1 produces; R2, R3 read)
| Field | Notes |
|---|---|
| `schema_version`, `job_id`, `analysis_version` | `analysis_version` is bumped by R1 whenever extractor or rules change (cache key) |
| `analysis_status` | `ok`, `partial`, `failed` |
| `failure_reason` | null, `packed_obfuscated`, `invalid_apk`, `timeout`, `unpack_limit`. Partial or failed means R2 returns `could_not_analyse` |
| `file` | `sha256`, `size_bytes`, `detected_type`, `claimed_filename` (in memory only, stripped before any storage) |
| `app` | `label`, `package_name`, `version_name`, `min_sdk`, `target_sdk` |
| `certificate` | `signed`, `sha256_fingerprints[]`, `subject`, `self_signed`, `debug_cert` |
| `permissions` | `requested[]`, `dangerous[]` |
| `components` | booleans: `has_launcher_activity`, `has_accessibility_service`, `has_device_admin`, `has_sms_receiver`, `requests_install_packages`, `requests_overlay`, `embedded_apk_or_dex`, `dynamic_code_loading` |
| `indicators` | `urls[]`, `domains[]`, `ip_addresses[]`, `cloud_endpoints[]`, `token_hashes[]` (SHA-256 only) |
| `rule_hits[]` | `rule_id`, `category`, `severity`, `reason_code`, `params`, `evidence_short` (developer-only, never shown to users) |
| `impersonation` | `claimed_brand` (or null), `match_basis` (`name`, `package`), `cert_matches_reference` (bool or null), `confidence` 0 to 1. Hook: optional `registry_entry_id` |
| `features` | flat number/bool map; names in `shared/schemas/features.md` |
| `warnings[]` | non-fatal issues |

**5.2 Score Result** (R2 produces; R3, R4 read): `schema_version`, `job_id`, `verdict`, `risk_score` (0 to 1, null if `could_not_analyse`), `reasons[]` (`reason_code`, `source` = `rule`/`model`/`message`/`impersonation`, `severity`, `weight`, `params`), `model` (`name`, `version`, `thresholds_version`), `analysis_version`, `message_analysis` (object or null). Reasons are sorted by weight, and R4 shows at most 5.

**5.3 Message Analysis** (R2): `language`, `lure_theme` (`traffic_fine`, `government_scheme`, `bank_kyc`, `parcel`, `utility_bill`, `reward`, `other`, `none`), `red_flags[]` (`flag_code`, `severity`, optional `span` [start, end]), `claimed_brand`, `consistency` (`status` = `match`/`mismatch`/`unknown`, `details[]` as reason codes), `message_score`. Message text is processed in memory and **never stored or logged**. Hook: `span` exists now, for red-pen highlighting later.

**5.3b Explanation** (R4): `language`, `headline`, `verdict_label`, `reasons[]` (`text`, `icon`), `next_steps[]`, `disclaimer`. Chat version at most 1,200 characters (Telegram's limit is 4,096). A missing translation falls back to English, never blank.

**5.4 Job result** (R3 API): `job_id`, `status`, `created_at`, `language`, `score_result`, `explanation`. Rejected jobs carry `error.code`: `FILE_TOO_LARGE`, `NOT_AN_APK`, `RATE_LIMITED`, `UNPACK_LIMIT`.

**5.5 Reason codes** (R1, R2, R4): master list `shared/reason_codes.json` with `code`, `en_title`, `en_text`, `severity_default`, `source`. Initial codes: `SMS_INTERCEPTION`, `ACCESSIBILITY_ABUSE`, `OVERLAY_ATTACK`, `DROPPER_BEHAVIOUR`, `HIDDEN_LAUNCHER_ICON`, `EXFIL_BOT_TOKEN`, `EXFIL_CLOUD_ENDPOINT`, `EXFIL_HARDCODED_URL`, `OBFUSCATED_OR_PACKED`, `IMPERSONATION_CERT_MISMATCH`, `IMPERSONATION_NAME_LOOKALIKE`, `MESSAGE_URGENCY`, `MESSAGE_THREAT`, `MESSAGE_PAYMENT_DEMAND`, `MESSAGE_FAKE_AUTHORITY`, `MESSAGE_INSTALL_REQUEST`, `MESSAGE_APP_MISMATCH`, `MODEL_HIGH_RISK`, `NOT_ANALYSABLE`.
**No code is emitted until it is in the master list with English text.** R4 adds Kannada and Hindi by the next milestone.

**5.6 Indicator feed** (R3): types `file_sha256`, `domain`, `package_name`, `cert_sha256`, `token_hash`; fields `type`, `value`, `campaign_id`, `first_seen`, `last_seen`, `seen_count`. JSON and CSV. Never files, message text or user identifiers. Campaign v1 rule: indicators sharing a certificate fingerprint, token hash or domain are linked.

**5.7 Official-app list** (R1 owns, `shared/registry/official_apps.json`): `brand_id`, `display_names` (en, kn, hi), `category`, `package_names[]`, `cert_sha256[]`. Hooks (optional fields): `play_store_url`, `official_site`, `last_verified`. R1 seeds 10 for the demo, then about 50 of the most impersonated apps from public advisories. Not in the list means "unknown", never "safe".

## 6. Interfaces [CORE]
**R1** (`sg_analysis`)
```python
validate_intake(path) -> dict        # {ok, detected_type, size_bytes, reject_code}
analyze_apk(path, job_id, claimed_filename=None) -> dict   # Findings Record, never raises
```
CLI run inside the container: `python -m sg_analysis.cli --input /in/sample.bin --job-id <id> --out /out/findings.json`. It always writes valid JSON, even on failure. Exit codes: 0 ok, 2 invalid, 3 timeout, 4 resource limit. It never executes the sample, never opens the network, never visits extracted URLs.

**R2** (`sg_intel`)
```python
score(findings, message_analysis=None) -> dict             # Score Result
analyze_message(text, claimed_brand=None, findings=None) -> dict
```
Models in `intel/models/model_v<N>.joblib` + `.json` (feature order, training date range, metrics). Thresholds live in `intel/config/thresholds.yaml`, never hard-coded elsewhere. A missing feature counts as 0. `score()` runs under 1 s, and the model loads once at startup.

**R4** (`sg_explain`)
```python
render_explanation(score_result, lang, channel='chat') -> dict   # channel: chat or web
render_report(score_result, lang, fmt='html') -> str             # fmt: html or text
```
All text comes from `shared/i18n/<lang>.json` (keys like `reason.SMS_INTERCEPTION.text`). Nothing is hard-coded.

**R3 REST API** (auto-docs at `/docs`)
| Endpoint | Purpose |
|---|---|
| `POST /api/v1/submissions` | multipart: `file`, `language`, optional `message_text`; returns `job_id` |
| `GET /api/v1/submissions/{job_id}` | job result |
| `GET /api/v1/submissions/{job_id}/report?lang=` | printable report |
| `GET /api/v1/feed/indicators` (`?format=json` or `csv`) | feed |
| `GET /api/v1/feed/campaigns` | campaigns |
| `GET /api/v1/health` | status |

R3 delivers a **mock server** (fixtures) by M0/M1 so R4 can build the UI early. CORS allows only the website origin.

**Database (SQLite, core tables):** `jobs` (id, status, language, created_at, result_json, chat_ref, expires_at), `hash_cache` (sha256, analysis_version, findings_json, cached_at), `indicators`, `campaigns`, `rate_limits` (hashed identifier, window, count).
- The cache stores **findings** (filename stripped, tokens hashed only). `score()` re-runs on every request, so model updates apply automatically and a message can be added to a cached file.
- `result_json` (Score Result and Explanation) is deleted after `result_ttl_hours` (default 24).
- `chat_ref` is wiped as soon as the reply is sent.

**Sandbox:** `--network none --read-only --tmpfs /tmp --memory 512m --cpus 1 --pids-limit 128 --cap-drop ALL --security-opt no-new-privileges`, non-root user, input mounted read-only, killed at `analysis_timeout_s`. R1 delivers `analysis/requirements.txt` and `analysis/SYSTEM_DEPS.md` (apt packages, Java runtime for apktool/jadx). R3 builds `docker/analyzer.Dockerfile` and reports the final limits back to R1.

**Config defaults:** `max_upload_mb: 20`, `analysis_timeout_s: 60`, `unpack_max_depth: 3`, `unpack_max_total_mb: 200`, `rate_limit_per_hour: 10`, `result_ttl_hours: 24`, `message_attach_window_min: 10`. Telegram's bot download limit is about 20 MB, so verify the current figure.

## 7. Role sheets

### R1: Analysis Engine and Registry
**Core [CORE]**
1. `validate_intake`: real type by content (ZIP structure plus manifest present), size limit, safe unpack with depth and size limits. Reject archive entries with `..` or absolute paths (zip-slip).
2. `analyze_apk` + CLI: permissions, components, certificate, strings, URLs, endpoints, token hashes, suspicious API calls (Androguard, apktool, jadx, apksigner).
3. YARA and custom rules in `analysis/rules/`, each with metadata `id`, `category`, `severity`, `reason_code`. Cover SMS interception, accessibility abuse, overlays, droppers, hidden icon, exfiltration (bot tokens, cloud endpoints, hardcoded URLs).
4. Impersonation check against the official-app list (label, package look-alikes, certificate comparison).
5. `features` map plus `features.md`.
6. At least 8 fixtures in `shared/fixtures/findings/`: benign, SMS-stealer-like, dropper-like, impersonation, `could_not_analyse`, and others.
7. Seed `official_apps.json`.
8. Tests: every rule has a positive and a negative test on synthetic or fixture data.

**Needs from:** R3 sandbox limits; R2 the features wish-list.
**Provides to:** schema and fixtures (M0), CLI and SYSTEM_DEPS (M1), the rule and reason list (M2).
**Rules:** raw tokens are hashed in memory and never logged or written. Deterministic output. No network.

**Optional [OPTIONAL]**
- **O-R1-1 Registry automation.** A weekly job reads official sites' `/.well-known/assetlinks.json` for package and certificate fingerprints, supports key rotation (several fingerprints with dates), flags stale entries via `last_verified`. Updates arrive only via PR. Needs: R4 for kn/hi display names.
- **O-R1-2 Shopkeeper-shield rules.** Rules for fake payment-screen apps. Needs: survey evidence first, R4 reason texts (`FAKE_PAYMENT_UI`), R2 if new features are added. Flag `enable_shopkeeper_rules`.

### R2: Intelligence
**Core [CORE]**
1. Dataset: `intel/data/manifest.csv` (sha256, label, source, first_seen date, notes). Samples stay local only. The benign set includes popular commercial-style apps.
2. Training uses **the same `analyze_apk` code path as production**, run in the sandbox (no separate feature code, to avoid train/serve mismatch).
3. Classifier plus baselines (rules-only, permission-only). Time-based split, cutoff in `intel/config/split.yaml`. Metrics: precision, recall, false-positive rate. Reports in `docs/eval/eval_v<N>.md` and `.json`.
4. `score()`: combine rule hits, model score and message analysis into verdict, reasons and risk score, with thresholds from config.
5. `analyze_message()`: red flags (urgency, threats, payment demands, fake authority, "install this app"), lure theme, English plus Hinglish/Kanglish (start rule-based and explainable), and the consistency check against the app (claimed brand vs impersonation result, lure theme vs requested permissions).
6. Fixtures in `shared/fixtures/score_results/` and `messages/` (synthetic or paraphrased from public advisories).
7. `shared/lures/lures.json`: sanitised example lure messages (fictional numbers and links) for R4's Dojo.

**Needs from:** R1 features list, fixtures and corpus runs; R3 latency check.
**Provides to:** `sg_intel` stub (M1), real model v1 (M3), reason codes for model and message flags (M2).
**Rules:** never mix data across the time cutoff. No sample redistribution. Reproducible runs (seed and versions saved in the model JSON).

**Optional [OPTIONAL]**
- **O-R2-1 Precise red-pen spans.** Accurate character offsets in `red_flags[].span`. Needs R4 rendering.
- **O-R2-2 Phone health check, OCR side.** `read_settings_screenshot(image_bytes) -> dict` reads app names from Settings screenshots (Hindi and Kannada OCR), compares to an allowlist, returns `unrecognised_services[]`. Needs R3 (intake, delete after reading) and R4 (guides). Flag `enable_health_check`.
- **O-R2-3 Voice input (speech to text).** EN/KN/HI transcription feeding `analyze_message`. Needs R3 (Telegram voice files). Flag `enable_voice`.

### R3: Platform, Bot and Safety
**Core [CORE]**
1. Sandbox runner and `docker/analyzer.Dockerfile`, with tests proving: no network, memory and time limits enforced, and no upload remains on disk afterwards.
2. Telegram bot: language buttons, file intake, optional message text (attach window), replies with the explanation. Commands `/start`, `/language`, `/help`. Oversize files get `FILE_TOO_LARGE` with guidance to use the website.
3. FastAPI backend (Section 6), simple job queue, rate limits using hashed identifiers, hash cache.
4. Indicator database, feed endpoints, campaign grouping, and a campaign report generator (Markdown output from the DB).
5. Mock server with fixture data (M0/M1).
6. Upload handling: random server-side filename (never the original), delete in a `finally` block, no logging of filenames, message text or user identifiers.

**Needs from:** R1 CLI and SYSTEM_DEPS; R2 models; R4 explanation library and i18n.
**Provides to:** API spec, mock server, a running instance for the website and the demo.
**Rules:** R3 calls only public functions of other roles and never edits their modules.

**Optional [OPTIONAL]**
- **O-R3-1 Accounts, friends, emergency contacts.** "Log in with Telegram" (one identity for bot and website, no passwords). Profile = nickname, language, contact links. Friend requests need acceptance, plus an emergency-contact flag. On a `dangerous` verdict, alerts carry only the verdict and the claimed app name. Unlink or delete anytime. Accounts are optional: core works without login. Tables `users` and `links` kept separate from core; endpoints under `/api/v1/accounts/`. Needs R4 for screens and privacy text. Flag `enable_accounts`. Open question: alerts for relatives not on Telegram.
- **O-R3-2 Pause timer.** "Wait 10 minutes" reminder with 3 calm questions. Needs R4 texts. Flag `enable_pause`.
- **O-R3-3 Health-check intake.** Bot flow for screenshots, phone-brand buttons, image deletion right after OCR. Needs R2, R4. Flag `enable_health_check`.
- **O-R3-4 Voice plumbing.** Receive Telegram voice notes, send voice replies. Needs R2 (speech to text) and R4 (text to speech). Flag `enable_voice`.
- **O-R3-5 Dojo anonymous stats.** `POST /api/v1/dojo/sessions` accepting only an anonymous summary (scenario id, counts of permissions granted, score), no identifiers. Needs R4. Flag `enable_dojo_stats`.

### R4: Web, Dojo and Explanations
**Core [CORE]**
1. Website: upload page (file, optional message, language), result page, info pages, live feed view. English, Kannada and Hindi UI. Mobile first, large readable text.
2. **Inoculation Dojo** (HTML/JS, fully client-side, installs nothing). Scenarios in `web/dojo/scenarios/*.json`: lure message, "unknown sources" toggle, Play Protect warning, permission asks (SMS, accessibility, overlay, contacts, battery), fake login screen, "share with contacts" step. Event log kept in memory, grading in `web/dojo/rubric.json`, end summary of what each action could have allowed, calm non-shaming tone, retry button.
3. `sg_explain`: `render_explanation` and `render_report` (headline, reasons, next steps split into "not installed yet" and "already installed", including contacting the bank, the 1930 helpline and cybercrime.gov.in as advice, plus the disclaimer).
4. i18n: all reason codes, steps, disclaimers and Dojo text in EN/KN/HI, reviewed by a native speaker before release.
5. Fixture explanations for every verdict.

**Needs from:** R3 API and mock; R1/R2 reason codes; R2 lure list.
**Provides to:** `sg_explain` stub (M1), full English (M2), Kannada and Hindi (M3), website and Dojo.
**Rules:** the Dojo **never reads or stores typed text** (it only notes that typing started), labels fields DEMO, requests no real permissions and makes no network calls (except O-R3-5). No hard-coded texts. HTML-escape every APK-derived string. No third-party analytics or trackers.

**Optional [OPTIONAL]**
- **O-R4-1 Red-pen highlighting.** Show the user's message with flagged phrases highlighted and a tooltip. Needs R2 spans.
- **O-R4-2 Scam Gym.** Scripted branching practice chat with a pretend scammer, scored on replies. Folder `web/gym/`, same rules as the Dojo, content from R2's lure list. Flag `enable_gym`.
- **O-R4-3 "Here's the real door".** When impersonation is detected, show the genuine app name, Play Store link and official site from the optional registry fields. Needs R1 to fill `play_store_url` and `official_site`. Flag `enable_real_door`.
- **O-R4-4 Needs-vs-asks meter.** Expected vs requested permissions by lure category, data in `shared/expected_permissions.json` (R4 curates, R1 reviews). Flag `enable_meter`.
- **O-R4-5 Voice replies (text to speech)** in EN/KN/HI. Needs R3 plumbing. Flag `enable_voice`.
- **O-R4-6 Health-check guides and UI.** Removal steps for the top ~6 phone brands plus a generic "use the Settings search bar" fallback. Needs R2, R3. Flag `enable_health_check`.
- **O-R4-7 Accounts UI.** Profile, friends list, emergency-contact screens. Needs O-R3-1. Flag `enable_accounts`.
- **O-R4-8 Shopkeeper content.** Vendor-specific Dojo scenario and guidance. Needs O-R1-2 and survey findings.

## 8. Handoffs, milestones, done
| From to | Deliverable | By |
|---|---|---|
| R1 to R2, R3, R4 | Findings schema, 8 fixtures, reason codes | M0 |
| R1 to R2 | `features.md` v1; analyzer ready for corpus runs | M0; M2 |
| R1 to R3 | CLI and `SYSTEM_DEPS.md` | M1 |
| R3 to R1, R2 | Container limits | M0 |
| R3 to R4 | Mock API, then real API | M0/M1; M2 |
| R2 to R3 | `sg_intel` stub, then model v1 | M1; M3 |
| R2 to R4 | Lure list, model and message reason codes | M2 |
| R4 to R3 | `sg_explain` stub, English, then KN/HI | M1; M2; M3 |

**Milestones** (dates set by the team):
- **M0 Contract freeze:** schemas v1.0, fixtures, repo skeleton, CI.
- **M1 Walking skeleton:** Telegram file to fixture result to English reply, all stubs.
- **M2 Real analyzer and API:** rules working, website upload and result page, dataset collected.
- **M3 Intelligence and languages:** model v1, message analysis, KN/HI, Dojo, report maker.
- **M4 Hardening:** sandbox and privacy tests, pilot-ready, field pilot.
- **M5 Evaluation and release:** evaluation frozen, report, demo. **Before making code or the feed public, check with your guide and the institute's IPR cell** (public disclosure can affect patent novelty).

**Definition of done (any task):** tests pass; fixtures validate against schemas; README run steps written; reviewed by another role; no secrets or samples committed; core works with all optional flags off.

## 9. Safety, privacy and ethics (non-negotiable)
- Analysis is static only, inside the sandbox. Samples are never installed on a real phone and never redistributed. Only hashes and indicators are shared.
- Uploaded files are deleted immediately after analysis. R3 stores only: cached findings (filename stripped), Score Result and Explanation until TTL, and anonymised indicators. No file, message text, filename or user identifier in logs or the feed.
- Tokens: store only SHA-256 hashes. **Never use an extracted token** (no testing it, no calling any API with it).
- Never visit extracted URLs and never fetch anything from sample-derived addresses.
- **Treat every APK-derived string as hostile** (labels, package names, domains): HTML-escape in the website, escape Telegram formatting in the bot, use parameterised SQL, and never put them in shell commands.
- Verdict wording is a risk assessment, never a guarantee. Unanalysable files are treated as risky.
- Datasets: record source, date and label for every sample. Respect each source's terms (MalwareBazaar key and terms, AndroZoo approval). Community samples only with consent.
- Survey and awareness-session participants give informed consent. Data minimisation: the privacy text must say "minimal personal data", not "no personal data", if accounts are built.

## 10. Changing the contract, and approving optional features
**Contract changes:** open a GitHub Issue labelled `contract-change` (what, why, who is affected). Allow 24 hours for comments. All affected roles approve. Update schema, fixtures and this doc **in the same PR**. Bump the minor version for additive changes, the major version for breaking ones.

**Working rhythm:** a 15-minute weekly integration check (demo end to end, list blockers). If you're blocked more than a day on another role, post it in the group and develop against the stub meanwhile.

**Optional-feature gate:** an [OPTIONAL] item starts only when (1) its owner's core deliverables are done through M3, (2) the team agrees at a sync and sets Status to *Approved* below, (3) its feature flag exists and defaults to `false`, and (4) every other role it needs agrees to its part. Dropped items lose their flag but keep harmless design hooks.

## 11. Optional features tracker
| ID | Feature | Owner | Needs | Flag | Status |
|---|---|---|---|---|---|
| O-R1-1 | Registry automation | R1 | R4 | (job, no flag) | Not started |
| O-R1-2 | Shopkeeper-shield rules | R1 | R2, R4 | `enable_shopkeeper_rules` | Not started |
| O-R2-1 | Precise red-pen spans | R2 | R4 | none | Not started |
| O-R2-2 | Health check: OCR | R2 | R3, R4 | `enable_health_check` | Not started |
| O-R2-3 | Voice input | R2 | R3 | `enable_voice` | Not started |
| O-R3-1 | Accounts, friends, emergency contacts | R3 | R4 | `enable_accounts` | Not started |
| O-R3-2 | Pause timer | R3 | R4 | `enable_pause` | Not started |
| O-R3-3 | Health-check intake | R3 | R2, R4 | `enable_health_check` | Not started |
| O-R3-4 | Voice plumbing | R3 | R2, R4 | `enable_voice` | Not started |
| O-R3-5 | Dojo anonymous stats | R3 | R4 | `enable_dojo_stats` | Not started |
| O-R4-1 | Red-pen highlighting | R4 | R2 | none | Not started |
| O-R4-2 | Scam Gym | R4 | R2 | `enable_gym` | Not started |
| O-R4-3 | "Here's the real door" | R4 | R1 | `enable_real_door` | Not started |
| O-R4-4 | Needs-vs-asks meter | R4 | R1 | `enable_meter` | Not started |
| O-R4-5 | Voice replies | R4 | R3 | `enable_voice` | Not started |
| O-R4-6 | Health-check guides and UI | R4 | R2, R3 | `enable_health_check` | Not started |
| O-R4-7 | Accounts UI | R4 | R3 | `enable_accounts` | Not started |
| O-R4-8 | Shopkeeper content | R4 | R1 | none | Not started |
