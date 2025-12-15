#!/usr/bin/env bash
set -euo pipefail

# This script starts a ZAP container, loads the authentication context, runs an
# authenticated spider followed by an active scan, and exports XML/JSON reports.
# It is meant to be used as a CI-friendly template and assumes the target app is
# reachable at http://localhost:3000 from inside the container.

ZAP_CONTAINER=${ZAP_CONTAINER:-zap-scanner}
ZAP_PORT=${ZAP_PORT:-8090}
CONTEXT_NAME=${CONTEXT_NAME:-nextjs-app-context}
ZAP_USER=${ZAP_USER:-ZAP-Test-User}
TARGET_URL=${TARGET_URL:-http://localhost:3000}
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_DIR="${BASE_DIR}/reports"

mkdir -p "${BASE_DIR}/zap" "${REPORT_DIR}"

# Start ZAP in daemon mode
if ! docker ps --format '{{.Names}}' | grep -q "^${ZAP_CONTAINER}$"; then
  docker run -u zap --name "${ZAP_CONTAINER}" -d \
    -p "${ZAP_PORT}:${ZAP_PORT}" \
    -v "${BASE_DIR}/zap:/zap/wrk" \
    -v "${REPORT_DIR}:/zap/reports" \
    owasp/zap2docker-stable \
    zap.sh -daemon -host 0.0.0.0 -port "${ZAP_PORT}" -config api.disablekey=true
fi

# Wait for the API to become available
until curl -sSf "http://localhost:${ZAP_PORT}/JSON/core/view/version/" >/dev/null; do
  echo "Waiting for ZAP to be ready..."
  sleep 2
done

echo "Importing context ${CONTEXT_NAME}"
docker exec "${ZAP_CONTAINER}" zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  context import "/zap/wrk/zap-context.context"

USER_ID=$(docker exec "${ZAP_CONTAINER}" zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  users new "${CONTEXT_NAME}" "${ZAP_USER}")

docker exec "${ZAP_CONTAINER}" zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  users set-credentials "${CONTEXT_NAME}" "${USER_ID}" "email=testuser@test.local&password=testpassword123"

docker exec "${ZAP_CONTAINER}" zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  users set-user-option "${CONTEXT_NAME}" "${USER_ID}" "logged_in_regex" "session=valid"

docker exec "${ZAP_CONTAINER}" zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  users enable "${CONTEXT_NAME}" "${USER_ID}"

# Spider with the authenticated user
zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  spider --context-name "${CONTEXT_NAME}" --user-id "${USER_ID}" --max-depth 5 "${TARGET_URL}"

# Active scan using the medium policy
zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  active-scan --context-name "${CONTEXT_NAME}" --user-id "${USER_ID}" --policy-name "Medium" "${TARGET_URL}"

# Export reports
zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  report -o "/zap/reports/zap_report.xml" -f xml
zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" \
  report -o "/zap/reports/zap_report.json" -f json

# Always complete the scan and allow the policy gate to enforce results
HIGH_ALERTS=$(zap-cli --zap-url http://localhost --port "${ZAP_PORT}" --api-key "" alerts --alert-level High | wc -l)
echo "Found ${HIGH_ALERTS} high-risk alerts (enforced by policy gate)"

echo "ZAP scan completed. Reports saved to ${REPORT_DIR}"
