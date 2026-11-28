# SideloadGuard Features Map

v0.1 draft, pending R2 wish list

The schema requires the existing feature keys and their defined types. Additional feature keys are allowed for R2; each additional value must be a number or boolean, and R2 must document every extra key here.

| Name | Type | Meaning | Computed from the Findings Record |
|---|---|---|---|
| num_requested_permissions | number | Number of requested Android permissions | Length of `permissions.requested` |
| num_dangerous_permissions | number | Number of requested dangerous permissions | Length of `permissions.dangerous` |
| num_urls | number | Number of recorded URLs | Length of `indicators.urls` |
| num_domains | number | Number of recorded domains | Length of `indicators.domains` |
| num_ip_addresses | number | Number of recorded IP addresses | Length of `indicators.ip_addresses` |
| num_cloud_endpoints | number | Number of recorded cloud endpoints | Length of `indicators.cloud_endpoints` |
| num_token_hashes | number | Number of token hashes | Length of `indicators.token_hashes` |
| num_cert_fingerprints | number | Number of certificate fingerprints | Length of `certificate.sha256_fingerprints` |
| num_rule_hits | number | Number of matched custom or YARA rules | Length of `rule_hits` |
| num_high_severity_hits | number | Number of high-severity rule matches | Count of `rule_hits` where `severity == "high"` |
| num_medium_severity_hits | number | Number of medium-severity rule matches | Count of `rule_hits` where `severity == "medium"` |
| num_low_severity_hits | number | Number of low-severity rule matches | Count of `rule_hits` where `severity == "low"` |
| has_launcher_activity | bool | Whether a launcher activity exists | Direct copy of `components.has_launcher_activity` |
| has_accessibility_service | bool | Whether an accessibility service exists | Direct copy of `components.has_accessibility_service` |
| has_device_admin | bool | Whether device administrator behavior exists | Direct copy of `components.has_device_admin` |
| has_sms_receiver | bool | Whether an SMS receiver exists | Direct copy of `components.has_sms_receiver` |
| requests_install_packages | bool | Whether package installation is requested | Direct copy of `components.requests_install_packages` |
| requests_overlay | bool | Whether overlay permission is requested | Direct copy of `components.requests_overlay` |
| embedded_apk_or_dex | bool | Whether embedded APK or DEX content exists | Direct copy of `components.embedded_apk_or_dex` |
| dynamic_code_loading | bool | Whether dynamic code loading was detected | Direct copy of `components.dynamic_code_loading` |
| is_signed | bool | Whether the app certificate record is signed | Direct copy of `certificate.signed` |
| is_self_signed | bool | Whether the certificate is self-signed | Direct copy of `certificate.self_signed`, interpreted as false when null |
| is_debug_cert | bool | Whether the certificate is a debug certificate | Direct copy of `certificate.debug_cert`, interpreted as false when null |
