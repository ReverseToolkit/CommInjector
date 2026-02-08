#!/bin/bash
LLVM_BIN="$ANDROID_NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin"

$LLVM_BIN/aarch64-linux-android29-clang \
    -shared -fPIC -o libpayload.so payload.c \
    -llog

echo "Built libpayload.so"

adb push libpayload.so /data/local/tmp/libpayload.so
adb shell su -c "chmod 644 /data/local/tmp/libpayload.so"
echo "Pushed to /data/local/tmp/libpayload.so"
