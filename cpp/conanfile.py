from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps

class SusiRecipe(ConanFile):
    name = "susi"
    version = "1.0.0"
    package_type = "library"
    
    settings = "os", "compiler", "build_type", "arch"
    options = {
        # shared is required by conan but will be ignored (always False)
        "shared": [False],
        # When True, a global constructor aborts the process at startup if the
        # binary is not code-signed.  Mirrors the Rust require-signed-binary
        # feature.  Passes -DSUSI_REQUIRE_SIGNED_BINARY=ON to CMake.
        "require_signed_binary": [True, False],
        # Build the tests in tests/. Only meant for builds of this repository;
        # the package doesn't change.
        "build_tests": [True, False],
    }
    default_options = {"shared": False, "require_signed_binary": False, "build_tests": False}

    exports_sources = "CMakeLists.txt", "src/*", "include/*"

    def requirements(self):
        self.requires("openssl/3.6.5")
        self.requires("nlohmann_json/[~3.11]")
        self.requires("libcurl/[>=7.85 <9]")

    def build_requirements(self):
        if self.options.build_tests:
            self.test_requires("catch2/3.16.1")
            self.test_requires("cpp-httplib/0.65.0")

    def package_id(self):
        del self.info.options.build_tests

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["SUSI_REQUIRE_SIGNED_BINARY"] = self.options.require_signed_binary
        tc.variables["SUSI_BUILD_TESTS"] = self.options.build_tests
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["susi"]
        if self.options.require_signed_binary:
            self.cpp_info.defines = ["SUSI_REQUIRE_SIGNED_BINARY=1"]
        if self.settings.os == "Macos":
            self.cpp_info.frameworks = ["IOKit", "CoreFoundation", "Security"]