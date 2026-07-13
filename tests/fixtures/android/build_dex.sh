#!/usr/bin/env bash
# Rebuild the DEX/APK fixtures from the Java sources in dexsrc/.
#
# Requires a JDK (javac + java) and Google's r8/d8. r8 is fetched from the
# Google Maven repo. The .dex/.apk are checked in so tests run without a JDK;
# re-run only to regenerate.
set -euo pipefail
cd "$(dirname "$0")"

R8_VERSION=${R8_VERSION:-9.1.31}
R8_JAR="r8-${R8_VERSION}.jar"
if [[ ! -f "$R8_JAR" ]]; then
  curl -sSL -o "$R8_JAR" \
    "https://maven.google.com/com/android/tools/r8/${R8_VERSION}/${R8_JAR}"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

javac --release 11 -d "$work" dexsrc/*.java
java -cp "$R8_JAR" com.android.tools.r8.D8 --min-api 21 --output "$work" \
  "$work"/com/glaurung/sample/*.class
cp "$work/classes.dex" sample.dex

# Minimal APK: a zip carrying classes.dex (enough for container detection).
( cd "$work" && zip -q -X classes.zip classes.dex )
cp "$work/classes.zip" sample.apk

echo "built: sample.dex sample.apk"
