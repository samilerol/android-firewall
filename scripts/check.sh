#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME="${ANDROID_HOME:-/workspace/toolchains/android-sdk}"
export ANDROID_USER_HOME="${ANDROID_USER_HOME:-/workspace/toolchains/android-user}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-/workspace/toolchains/gradle-home}"
if [[ -x /workspace/toolchains/jdk-21.0.9+10/bin/javac && -z "${JAVA_HOME:-}" ]]; then
  export JAVA_HOME=/workspace/toolchains/jdk-21.0.9+10
fi
source scripts/java-network.sh
./gradlew --no-daemon assembleDebug testDebugUnitTest lintDebug "$@"
