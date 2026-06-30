#!/usr/bin/env bash
# Builds the Lambda binary and packages deploy/opentofu/dist/function.zip
# with the 'bootstrap' entry marked executable (required by provided.al2023).
#
# Usage: ./build.sh [apigateway|apigatewayv2]
#   apigateway   (default) — self/alb mode; payload format 1.0
#   apigatewayv2            — apigw mode (delegated JWT); payload format 2.0
#
# Run from anywhere; paths are resolved relative to this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${SCRIPT_DIR}/dist"
STAGE_DIR="${DIST_DIR}/stage"

VARIANT="${1:-apigateway}"
if [[ "${VARIANT}" != "apigateway" && "${VARIANT}" != "apigatewayv2" ]]; then
  echo "ERROR: unknown variant '${VARIANT}'. Use 'apigateway' or 'apigatewayv2'." >&2
  exit 1
fi

echo "Building ${VARIANT} Lambda binary (linux/arm64)..."
make -C "${REPO_ROOT}" build-${VARIANT}

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"
cp "${REPO_ROOT}/build/bootstrap-${VARIANT}" "${STAGE_DIR}/bootstrap"
chmod 755 "${STAGE_DIR}/bootstrap"

# zip from inside the stage dir so the archive contains 'bootstrap' at its root,
# with the executable bit retained (archive_file cannot do this).
( cd "${STAGE_DIR}" && zip -X -q "${DIST_DIR}/function.zip" bootstrap )
echo "Packaged ${DIST_DIR}/function.zip (variant: ${VARIANT})"
