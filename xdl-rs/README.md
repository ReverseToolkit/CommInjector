# xdl-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Rust bindings for [xDL](https://github.com/hexhacking/xDL) - an enhanced implementation of Android DL series functions.

## Features

- **Bypass Android 7.0+ linker namespace restrictions**
- **Query dynamic symbols** from `.dynsym`
- **Query debug symbols** from `.symtab` and `.gnu_debugdata`
- **Enhanced `dl_iterate_phdr()`** with better compatibility
- **Safe Rust API** with automatic resource management
- **Auto-generated FFI bindings** using `bindgen`

## Requirements

- Android 4.1 (API level 16) or higher
- xDL library installed (via Gradle dependency)
- Rust with Android NDK support
