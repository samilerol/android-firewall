#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
exec ./scripts/gradle.sh :app:assembleDebug :app:testDebugUnitTest :app:lintDebug "$@"
