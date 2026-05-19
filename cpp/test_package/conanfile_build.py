from conan import ConanFile

# Minimal conanfile used by build.rs to install susi's CMake integration files
# into a cargo OUT_DIR for the integration test build.  Unlike conanfile.py this
# file does NOT use cmake_layout (generators go directly to --output-folder) and
# does NOT rely on tested_reference_str (which is only set inside conan create).
class SusiTestBuildConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"

    def requirements(self):
        self.requires("susi/1.0.0")
