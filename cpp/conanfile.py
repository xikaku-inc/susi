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
    }
    default_options = {"shared": False, "require_signed_binary": False}

    exports_sources = "CMakeLists.txt", "src/*", "include/*"

    def requirements(self):
        self.requires("openssl/3.6.1")
        self.requires("nlohmann_json/[~3.11]")
        self.requires("libcurl/[>=7.85 <9]")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["SUSI_REQUIRE_SIGNED_BINARY"] = self.options.require_signed_binary
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