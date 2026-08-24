#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/out"
R8_VER="${R8_VERSION:-8.7.18}"
R8_JAR="${R8_JAR:-$ROOT/.r8-$R8_VER.jar}"
R8_URL="https://dl.google.com/dl/android/maven2/com/android/tools/r8/${R8_VER}/r8-${R8_VER}.jar"

mkdir -p "$OUT"
rm -rf "$OUT"/*
rm -f "$ROOT/hook.dex"

D8_BIN=""
if [[ -n "${ANDROID_HOME:-}${ANDROID_SDK_ROOT:-}" ]]; then
    SDK="${ANDROID_HOME:-$ANDROID_SDK_ROOT}"
    D8_BIN="$(ls -1 "$SDK"/build-tools/*/d8 2>/dev/null | tail -n 1 || true)"
fi

echo "javac HookEntry.java"
javac --release 11 -d "$OUT" "$ROOT/HookEntry.java"

if [[ -n "$D8_BIN" ]]; then
    echo "d8 via $D8_BIN"
    "$D8_BIN" --min-api 29 --output "$OUT" "$OUT/spec/inject/HookEntry.class"
else
    if [[ ! -f "$R8_JAR" ]]; then
        echo "downloading r8 $R8_VER"
        curl -fsSL "$R8_URL" -o "$R8_JAR"
    fi
    echo "d8 via $R8_JAR"
    java -cp "$R8_JAR" com.android.tools.r8.D8 \
        --min-api 29 \
        --output "$OUT" \
        "$OUT/spec/inject/HookEntry.class"
fi

if [[ -f "$OUT/classes.dex" ]]; then
    cp "$OUT/classes.dex" "$ROOT/hook.dex"
else
    echo "d8 did not produce classes.dex" >&2
    exit 1
fi

DEX_SIZE="$(wc -c < "$ROOT/hook.dex")"
echo "Built $ROOT/hook.dex ($DEX_SIZE bytes)"

if command -v adb >/dev/null 2>&1; then
    adb push "$ROOT/hook.dex" /data/local/tmp/hook.dex
    adb shell su -c "chmod 644 /data/local/tmp/hook.dex"
    echo "Pushed to /data/local/tmp/hook.dex"
fi
