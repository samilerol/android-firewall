#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export SUITE_TOOLS="${SUITE_TOOLS:-/workspace/toolchains}"
export ANDROID_HOME="${ANDROID_HOME:-$SUITE_TOOLS/android-sdk}"
export ANDROID_USER_HOME="${ANDROID_USER_HOME:-$SUITE_TOOLS/android-user}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$SUITE_TOOLS/gradle-home}"
mkdir -p "$SUITE_TOOLS" "$ANDROID_HOME" "$ANDROID_USER_HOME" "$GRADLE_USER_HOME"
if [[ ! -x "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" ]]; then
  curl -fsSL --retry 2 https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -o "$SUITE_TOOLS/android-tools.zip"
  echo "d313adb7aedccf6cf0cfca51ec180f0059f5f8f8  $SUITE_TOOLS/android-tools.zip" | sha1sum -c -
  unzip -q "$SUITE_TOOLS/android-tools.zip" -d "$SUITE_TOOLS/sdk-unpack"
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  mv "$SUITE_TOOLS/sdk-unpack/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
  rmdir "$SUITE_TOOLS/sdk-unpack"
fi
# Install an open-source JDK if the host supplies only a JRE.
if [[ -z "${JAVA_HOME:-}" && -x "$SUITE_TOOLS/jdk-21.0.9+10/bin/javac" ]]; then
  export JAVA_HOME="$SUITE_TOOLS/jdk-21.0.9+10"
fi
if [[ ! -x "${JAVA_HOME:-/usr/lib/jvm/default-java}/bin/javac" ]] && ! command -v javac >/dev/null; then
  jdk_url='https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.9%2B10/OpenJDK21U-jdk_x64_linux_hotspot_21.0.9_10.tar.gz'
  curl -fsSL --retry 2 "$jdk_url" -o "$SUITE_TOOLS/jdk.tar.gz"
  jdk_hash=810d3773df7e0d6c4394e4e244b264c8b30e0b05a0acf542d065fd78a6b65c2f
  echo "$jdk_hash  $SUITE_TOOLS/jdk.tar.gz" | sha256sum -c -
  tar -xzf "$SUITE_TOOLS/jdk.tar.gz" -C "$SUITE_TOOLS"
  export JAVA_HOME="$SUITE_TOOLS/jdk-21.0.9+10"
fi
if [[ -n "${JAVA_HOME:-}" ]]; then "$JAVA_HOME/bin/javac" -version; else javac -version; fi
# Java clients need explicit proxy properties; preserve platform TLS trust.
source "$ROOT/scripts/java-network.sh"
# Accept Android SDK licenses for the selected development toolchain.
set +o pipefail
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" --licenses > "$SUITE_TOOLS/licenses.log" 2>&1
license_status=${PIPESTATUS[1]}
set -o pipefail
if [[ "$license_status" != 0 ]]; then cat "$SUITE_TOOLS/licenses.log"; exit "$license_status"; fi
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$ANDROID_HOME" 'platforms;android-35' 'build-tools;34.0.0' 'platform-tools'
cd "$ROOT"
./gradlew --no-daemon assembleDebug testDebugUnitTest lintDebug
