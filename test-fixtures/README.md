# Security & Privacy Validation Fixtures

This folder contains controlled injections used to validate the CI security pipeline. Each fixture is intentionally crafted to exercise a specific scanner and severity policy.

## How to use these fixtures
- **Baseline CI runs exclude this folder.** GitLeaks is allowlisted for `test-fixtures/`, and the custom PII scanner is invoked only against `app/` and `src/` so routine builds pass without touching the fixtures.
- **Use fixtures only for controlled evaluation.** To force a failure, temporarily copy the relevant fixture into `app/` or `src/`, commit the change, and observe the CI failure. Revert the injection afterward to restore a clean baseline.
- **Documented behavior for academic reproducibility:**
  - Baseline (no fixture injection) → CI passes with zero GitLeaks and non-allowlisted PII findings.
  - Injecting a secret fixture into `app/` or `src/` → GitLeaks reports findings; policy gate fails.
  - Injecting a non-allowlisted PII fixture into `app/` or `src/` → PII scanner reports findings; policy gate fails.

## Secrets (GitLeaks)
- **Path:** `test-fixtures/secrets/aws_key.txt`
- **Payload:** Fake AWS-style access key pair.
- **Expected CI behavior:** ❌ GitLeaks should report findings; the policy gate fails when these are present.
- **Report evidence:** `reports/gitleaks.json` / `reports/gitleaks.sarif` showing the secret match.

## PII (Custom Scanner)
- **Allowlisted email:** `test-fixtures/pii/allowlisted_email.txt` contains `testuser@test.local`, which matches the allowlist and should pass silently.
- **Non-allowlisted email:** `test-fixtures/pii/non_allowlisted_email.txt` contains `pii.leak@example.com`, which must trigger the PII scanner.
- **Expected CI behavior:** ✅ passes when only allowlisted data exist; ❌ fails when non-allowlisted findings remain.
- **Report evidence:** `reports/pii_report.json` lists only non-allowlisted findings counted by the policy gate.

## Dependencies (Snyk)
- **High-risk manifest:** `test-fixtures/deps/high/package.json` pins `lodash@4.17.19` (known high-severity issues).
- **Low-risk manifest:** `test-fixtures/deps/low/package.json` uses `uuid@9.0.0`, expected to carry no high/critical CVEs.
- **Expected CI behavior:** ❌ fails when high/critical vulnerabilities are detected; ✅ passes when only low/none are present.
- **Report evidence:** `reports/snyk_node.sarif` and `reports/snyk_python.sarif` with high/critical severities counted in the policy summary.

## ZAP (Dynamic App Security)
- **High-risk endpoint fixture:** `test-fixtures/zap/high-risk.html` contains a reflected XSS pattern to trigger a HIGH alert.
- **Low-risk endpoint fixture:** `test-fixtures/zap/low-risk.html` omits strict headers to produce only low-severity alerts.
- **Expected CI behavior:** ❌ fails when HIGH alerts are present; ✅ passes when alerts are informational/low/medium only.
- **Report evidence:** `reports/zap_report.json` parsed by the policy gate to count HIGH-risk alerts.

These fixtures are designed for deterministic, reproducible evaluation of the CI policy gate without weakening enforcement.
