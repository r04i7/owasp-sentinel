#!/usr/bin/env bash
# Standalone build (no Gradle needed). Downloads the Montoya API jar, compiles
# every source file with javac, bundles resources, and produces the loadable
# extension jar in dist/. Requires JDK 17+ and internet on first run.
set -euo pipefail

cd "$(dirname "$0")"

MONTOYA_VERSION="2023.12.1"
MONTOYA_JAR="lib/montoya-api-${MONTOYA_VERSION}.jar"
MONTOYA_URL="https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/${MONTOYA_VERSION}/montoya-api-${MONTOYA_VERSION}.jar"
OUT_JAR="dist/owasp-sentinel-1.0.0.jar"

mkdir -p lib build/classes dist

if [ ! -f "$MONTOYA_JAR" ]; then
  echo "[*] Downloading Montoya API ${MONTOYA_VERSION}..."
  curl -sSL "$MONTOYA_URL" -o "$MONTOYA_JAR"
fi

# Resolve the JDK's jar tool. On Windows the Oracle "javapath" shim exposes
# java/javac but not jar, so fall back to JAVA_HOME / the real jdk bin.
JAR_BIN="$(command -v jar || true)"
if [ -z "$JAR_BIN" ]; then
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/jar" ]; then
    JAR_BIN="$JAVA_HOME/bin/jar"
  elif [ -x "/c/Program Files/Java/jdk-21/bin/jar" ]; then
    JAR_BIN="/c/Program Files/Java/jdk-21/bin/jar"
  else
    JAR_BIN="$(ls -d /c/Program\ Files/Java/jdk*/bin/jar 2>/dev/null | head -1 || true)"
  fi
fi
[ -n "$JAR_BIN" ] || { echo "ERROR: could not find the 'jar' tool. Set JAVA_HOME."; exit 1; }

echo "[*] Compiling..."
find src/main/java -name '*.java' > build/sources.txt
# --release 17 (rather than -source/-target) avoids the "system modules path"
# warning and pins the bytecode level Burp's bundled JRE expects.
javac --release 17 -cp "$MONTOYA_JAR" -d build/classes @build/sources.txt

echo "[*] Bundling resources..."
cp -r src/main/resources/. build/classes/

echo "[*] Packaging $OUT_JAR ..."
"$JAR_BIN" --create --file "$OUT_JAR" -C build/classes .

echo "[+] Done: $OUT_JAR"
echo "    Load it in Burp: Extensions -> Add -> Extension type: Java -> select the jar."
