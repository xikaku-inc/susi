// build.rs for susi_server
//
// If `conan` is available on PATH, this script builds the C++ integration-test
// binary (cpp/test_package/PackageTest) so that the Rust integration tests can
// drive it.  The path to the built binary is emitted as the compile-time env
// variable SUSI_CPP_TEST_BIN, accessible in tests via env!().
//
// If conan is missing or the build fails the script prints a warning and
// continues — the Rust test suite marks the C++ test as skipped rather than
// failed in that case.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    // Declare custom cfg names so rustc's check-cfg lint doesn't warn.
    println!("cargo:rustc-check-cfg=cfg(susi_conan_available)");
    println!("cargo:rustc-check-cfg=cfg(susi_cpp_built)");

    // Re-run only when the C++ sources change, not on every Rust edit.
    println!("cargo:rerun-if-changed=../../cpp/src/susi.cpp");
    println!("cargo:rerun-if-changed=../../cpp/include/susi.h");
    println!("cargo:rerun-if-changed=../../cpp/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../../cpp/conanfile.py");
    println!("cargo:rerun-if-changed=../../cpp/test_package/main.cpp");
    println!("cargo:rerun-if-changed=../../cpp/test_package/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../../cpp/test_package/conanfile.py");
    println!("cargo:rerun-if-changed=../../cpp/test_package/conanfile_build.py");

    if !conan_available() {
        println!("cargo:warning=conan not found — C++ integration test will be skipped");
        return;
    }

    // Conan is present: from here on any failure becomes a test failure, not a skip.
    println!("cargo:rustc-cfg=susi_conan_available");

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let cpp_dir = {
        let raw = manifest_dir.join("../../cpp").canonicalize()
            .expect("canonicalize cpp dir");
        // Windows canonicalize() prepends \\?\ (UNC extended-length prefix) which
        // confuses MSVC cl.exe.  Strip it so we get a plain C:\... path.
        let s = raw.to_string_lossy();
        if let Some(plain) = s.strip_prefix(r"\\?\") {
            PathBuf::from(plain.to_owned())
        } else {
            raw
        }
    };
    let test_pkg_dir  = cpp_dir.join("test_package");
    let out_dir       = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let build_dir     = out_dir.join("cpp_test_build");
    std::fs::create_dir_all(&build_dir).expect("create cpp build dir");

    // Step 1: conan create the main library so it is in the local cache.
    // --test-folder "" skips running the test_package binary (which requires
    // server args we don't have at package-creation time).
    if !run("conan create", Command::new("conan")
        .args(["create", ".", "--build=missing", "-s", "build_type=Debug", "--test-folder", ""])
        .current_dir(&cpp_dir))
    {
        println!("cargo:warning=conan create failed — C++ integration test will fail");
        println!("cargo:rustc-env=SUSI_CPP_BUILD_ERROR=conan create failed");
        return;
    }

    // Step 2: conan install using conanfile_build.py (no cmake_layout, explicit
    // susi/1.0.0 require) so that CMakeDeps generates susiConfig.cmake directly
    // into --output-folder without any build/<type>/generators/ nesting.
    let build_conanfile = test_pkg_dir.join("conanfile_build.py");
    if !run("conan install (test_package)", Command::new("conan")
        .args([
            "install", build_conanfile.to_str().unwrap(),
            "--build=missing",
            "-s", "build_type=Debug",
            "--output-folder", build_dir.to_str().unwrap(),
        ])
        .current_dir(&build_dir))
    {
        println!("cargo:warning=conan install failed — C++ integration test will fail");
        println!("cargo:rustc-env=SUSI_CPP_BUILD_ERROR=conan install (test_package) failed");
        return;
    }

    // Step 3: cmake configure + build.
    // conanfile_build.py has no cmake_layout so generators land directly in
    // --output-folder (build_dir): conan_toolchain.cmake sets CMAKE_PREFIX_PATH
    // to build_dir and susiConfig.cmake is also there.
    let toolchain = build_dir.join("conan_toolchain.cmake");
    if !run("cmake configure", Command::new("cmake")
        .args([
            "-S", test_pkg_dir.to_str().unwrap(),
            "-B", build_dir.to_str().unwrap(),
            &format!("-DCMAKE_TOOLCHAIN_FILE={}", toolchain.display()),
            "-DCMAKE_BUILD_TYPE=Debug",
        ])
        .current_dir(&build_dir))
    {
        println!("cargo:warning=cmake configure failed — C++ integration test will fail");
        println!("cargo:rustc-env=SUSI_CPP_BUILD_ERROR=cmake configure failed");
        return;
    }

    if !run("cmake build", Command::new("cmake")
        .args(["--build", build_dir.to_str().unwrap(), "--config", "Debug"])
        .current_dir(&build_dir))
    {
        println!("cargo:warning=cmake build failed — C++ integration test will fail");
        println!("cargo:rustc-env=SUSI_CPP_BUILD_ERROR=cmake build failed");
        return;
    }

    // Step 4: locate the produced binary.
    let binary = find_binary(&build_dir, "PackageTest");
    match binary {
        Some(p) => {
            println!("cargo:rustc-env=SUSI_CPP_TEST_BIN={}", p.display());
            // Signal to the test crate that the binary exists; used to
            // conditionally un-ignore the C++ test via #[cfg_attr].
            println!("cargo:rustc-cfg=susi_cpp_built");
            println!("cargo:warning=C++ test binary built: {}", p.display());
        }
        None => {
            println!("cargo:warning=PackageTest binary not found after build — C++ test will fail");
            println!("cargo:rustc-env=SUSI_CPP_BUILD_ERROR=PackageTest binary not found after cmake build");
        }
    }
}

fn conan_available() -> bool {
    Command::new("conan")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command, print its output on failure, return success flag.
fn run(label: &str, cmd: &mut Command) -> bool {
    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            println!("cargo:warning={label}: could not spawn: {e}");
            return false;
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("cargo:warning={label} failed (exit {:?})", output.status.code());
        for line in stderr.lines().chain(stdout.lines()).take(20) {
            println!("cargo:warning=  {line}");
        }
        return false;
    }
    true
}

/// Search common output locations for the compiled binary.
fn find_binary(build_dir: &Path, name: &str) -> Option<PathBuf> {
    let candidates = [
        build_dir.join(name),
        build_dir.join(format!("{}.exe", name)),
        build_dir.join("Debug").join(name),
        build_dir.join("Debug").join(format!("{}.exe", name)),
        build_dir.join("build").join("Debug").join(name),
        build_dir.join("build").join("Debug").join(format!("{}.exe", name)),
    ];
    candidates.into_iter().find(|p| p.exists())
}
