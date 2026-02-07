use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_os == "android" {
        // Download and compile xDL source code
        download_and_compile_xdl();

        // Generate bindings
        generate_bindings();
    } else {
        eprintln!("Warning: xdl-rs only supports Android targets");
    }
}

fn generate_bindings() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let vendor_dir = PathBuf::from(&manifest_dir).join("vendor");
    let xdl_dir = vendor_dir.join("xDL");
    let xdl_include_dir = xdl_dir.join("xdl").join("src").join("main").join("cpp").join("include");

    // Fallback to local include if vendor doesn't exist
    let header_path = if xdl_include_dir.join("xdl.h").exists() {
        xdl_include_dir.join("xdl.h")
    } else {
        PathBuf::from(&manifest_dir).join("include").join("xdl.h")
    };

    println!("cargo:rerun-if-changed={}", header_path.display());

    let ndk_home = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("NDK_HOME"))
        .expect("ANDROID_NDK_HOME or NDK_HOME environment variable must be set");

    let prebuilt_dir = PathBuf::from(&ndk_home)
        .join("toolchains")
        .join("llvm")
        .join("prebuilt");

    let sysroot = std::fs::read_dir(&prebuilt_dir)
        .expect(&format!("Failed to read prebuilt directory: {}", prebuilt_dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("sysroot"))
        .find(|path| path.exists())
        .expect("No valid NDK sysroot found in prebuilt directory");

    let sysroot_include = sysroot.join("usr").join("include");

    let toolchain_base = sysroot.parent().unwrap();
    let lib_clang_dir = toolchain_base.join("lib").join("clang");

    let clang_builtin_include = if lib_clang_dir.exists() {
        std::fs::read_dir(&lib_clang_dir)
            .ok()
            .and_then(|mut entries| entries.next())
            .and_then(|entry| entry.ok())
            .map(|entry| entry.path().join("include"))
    } else {
        None
    };

    println!("cargo:warning=Using NDK sysroot: {}", sysroot.display());
    if let Some(ref clang_inc) = clang_builtin_include {
        println!("cargo:warning=Using clang builtin include: {}", clang_inc.display());
    }

    // Detect target architecture
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "aarch64".to_string());
    let android_api = env::var("ANDROID_API_LEVEL").unwrap_or_else(|_| "21".to_string());
    let target_triple = match target_arch.as_str() {
        "aarch64" => format!("aarch64-linux-android{}", android_api),
        "arm" => format!("armv7a-linux-androideabi{}", android_api),
        "x86" => format!("i686-linux-android{}", android_api),
        "x86_64" => format!("x86_64-linux-android{}", android_api),
        _ => format!("aarch64-linux-android{}", android_api),
    };

    let mut builder = bindgen::Builder::default()
        .header(header_path.to_str().unwrap())
        .allowlist_function("xdl_.*")
        .allowlist_type("xdl_.*")
        .allowlist_var("XDL_.*")
        .allowlist_type("dl_phdr_info")
        .allowlist_type("Elf.*")
        .generate_comments(true)
        .layout_tests(false)
        .derive_debug(true)
        .derive_default(false)
        .clang_arg(format!("--target={}", target_triple))
        .clang_arg(format!("--sysroot={}", sysroot.display()))
        .clang_arg(format!("-D__ANDROID_API__={}", android_api))
        .clang_arg("-nostdinc++");

    // Add clang builtin include first (contains stdint.h, stddef.h, etc.)
    if let Some(clang_inc) = clang_builtin_include {
        if clang_inc.exists() {
            builder = builder.clang_arg(format!("-isystem{}", clang_inc.display()));
        }
    }

    // Add sysroot includes
    if sysroot_include.exists() {
        builder = builder.clang_arg(format!("-isystem{}", sysroot_include.display()));

        // Add architecture-specific includes
        let arch_include = match target_arch.as_str() {
            "aarch64" => sysroot_include.join("aarch64-linux-android"),
            "arm" => sysroot_include.join("arm-linux-androideabi"),
            "x86" => sysroot_include.join("i686-linux-android"),
            "x86_64" => sysroot_include.join("x86_64-linux-android"),
            _ => sysroot_include.join("aarch64-linux-android"),
        };

        if arch_include.exists() {
            builder = builder.clang_arg(format!("-isystem{}", arch_include.display()));
        }
    } else {
        panic!("NDK sysroot not found at: {}", sysroot_include.display());
    }

    let bindings = builder
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn download_and_compile_xdl() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let vendor_dir = PathBuf::from(&manifest_dir).join("vendor");
    let xdl_dir = vendor_dir.join("xDL");
    let xdl_src_dir = xdl_dir.join("xdl").join("src").join("main").join("cpp");

    // Download xDL source if not exists
    if !xdl_dir.exists() {
        println!("cargo:warning=Downloading xDL source code...");
        std::fs::create_dir_all(&vendor_dir).expect("Failed to create vendor directory");

        let status = Command::new("git")
            .args(&[
                "clone",
                "--depth", "1",
                "https://github.com/hexhacking/xDL.git",
                xdl_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to execute git. Please ensure git is installed and in PATH");

        if !status.success() {
            panic!("Failed to clone xDL repository. Please check your network connection");
        }
    }

    // Verify source files exist
    if !xdl_src_dir.exists() {
        panic!(
            "xDL source directory not found at: {}. Try deleting vendor/xDL and rebuilding",
            xdl_src_dir.display()
        );
    }

    println!("cargo:rerun-if-changed={}", xdl_src_dir.display());

    // Compile xDL source files
    let sources = [
        "xdl.c",
        "xdl_iterate.c",
        "xdl_linker.c",
        "xdl_lzma.c",
        "xdl_util.c",
    ];

    let mut build = cc::Build::new();

    for src in &sources {
        build.file(xdl_src_dir.join(src));
    }

    // Add include directories
    build.include(&xdl_src_dir);
    build.include(xdl_src_dir.join("include"));

    // Compiler flags from CMakeLists.txt
    // Use c11 instead of c17 for better compatibility
    build.flag("-std=c11");
    build.flag("-Os"); // Optimize for size
    build.flag("-ffunction-sections");
    build.flag("-fdata-sections");

    // Disable warnings to avoid build failures
    build.warnings(false);

    // Compile as static library
    build.compile("xdl");

    println!("cargo:warning=xDL compiled successfully");
}
