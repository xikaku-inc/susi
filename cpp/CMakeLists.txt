cmake_minimum_required(VERSION 3.16)

# This CMakeLists.txt can be used standalone or included via add_subdirectory().
# It creates a static library target "susi" that your application can link against.
#
# Requirements:
#   - OpenSSL (for RSA-SHA256 verification and hardware fingerprinting)
#   - nlohmann/json (header-only, fetched automatically if not found)
#
# Usage in your project:
#   add_subdirectory(susi/cpp)
#   target_link_libraries(your_target PRIVATE susi)

if(NOT CMAKE_PROJECT_NAME)
    project(susi LANGUAGES CXX)
endif()

# ---------------------------------------------------------------------------
# Startup binary-signature enforcement
# ---------------------------------------------------------------------------
# When ON, the library aborts the host process before main() if the binary is
# not code-signed.  This mirrors the Rust `require-signed-binary` feature.
#
# The variable can be set from three places (highest precedence first):
#   1. Conan: conan install . -o susi/*:require_signed_binary=True
#             → CMakeToolchain sets SUSI_REQUIRE_SIGNED_BINARY as a normal
#               CMake variable, which takes precedence over the cache entry.
#   2. Command line: cmake -DSUSI_REQUIRE_SIGNED_BINARY=ON <source_dir>
#   3. Parent project: set(SUSI_REQUIRE_SIGNED_BINARY ON) before add_subdirectory()
option(SUSI_REQUIRE_SIGNED_BINARY
    "Abort at startup if the binary is not code-signed" OFF)

add_library(susi STATIC src/susi.cpp include/susi.h)
target_include_directories(susi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(susi PUBLIC cxx_std_17)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(susi PRIVATE OpenSSL::SSL OpenSSL::Crypto)
# nlohmann/json
find_package(nlohmann_json REQUIRED)
target_link_libraries(susi PRIVATE nlohmann_json::nlohmann_json)
# libcurl (for server-activated license refresh)
find_package(CURL REQUIRED)
target_link_libraries(susi PRIVATE CURL::libcurl)

# Windows libraries
if(WIN32)
    target_link_libraries(susi PRIVATE cfgmgr32 iphlpapi ole32 oleaut32 setupapi wbemuuid wintrust ws2_32)
endif()

# macOS: IOKit + CoreFoundation (fingerprint)
if(APPLE)
    find_library(IOKIT_LIBRARY IOKit REQUIRED)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    find_library(SECURITY_LIBRARY Security REQUIRED)
    target_link_libraries(susi PRIVATE ${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY} ${SECURITY_LIBRARY})
endif()

if(SUSI_REQUIRE_SIGNED_BINARY)
    target_compile_definitions(susi PUBLIC SUSI_REQUIRE_SIGNED_BINARY=1)
    message(STATUS "susi: startup binary-signature enforcement ENABLED")
endif()

set_target_properties(susi PROPERTIES PUBLIC_HEADER "include/susi.h")
install(TARGETS susi)