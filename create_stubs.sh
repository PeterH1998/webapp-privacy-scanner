#!/usr/bin/env bash

# --- Create directories ---
mkdir -p .github/workflows
mkdir -p src/scanner
mkdir -p src/app
mkdir -p zap

# --- Create GitHub Actions workflow stub ---
cat << 'EOF' > .github/workflows/security-pipeline.yml
name: Security & Privacy Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      # We'll add: Node setup, Snyk, GitLeaks, ZAP Docker, Python scanner, Slack report
EOF

# --- Create PII scanner stub ---
cat << 'EOF' > src/scanner/scanner.py
def main():
    # TODO: implement walking repo, regex for emails/phones/SSNs, JSON output
    pass

if __name__ == "__main__":
    main()
EOF

# --- Create Allowlist stub ---
cat << 'EOF' > src/scanner/allowlist.yml
paths:
  - "tests/fixtures/*"

regexes:
  - "example@example.com"
EOF

# --- Create GitLeaks config stub ---
cat << 'EOF' > gitleaks.toml
title = "Webapp Privacy Scanner GitLeaks Config"

[[rules]]
description = "Ignore env example files"
path = '''.*\.env\.example$'''
allowlist = true
EOF

echo "✔️ All configuration stubs created successfully!"
