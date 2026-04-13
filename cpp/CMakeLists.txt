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

# Windows: WMI (fingerprint) + device enumeration
if(WIN32)
    target_link_libraries(susi PRIVATE wbemuuid ole32 oleaut32 setupapi cfgmgr32)
endif()

# macOS: IOKit + CoreFoundation (fingerprint)
if(APPLE)
    find_library(IOKIT_LIBRARY IOKit REQUIRED)
    find_library(COREFOUNDATION_LIBRARY CoreFoundation REQUIRED)
    target_link_libraries(susi PRIVATE ${IOKIT_LIBRARY} ${COREFOUNDATION_LIBRARY})
endif()

set_target_properties(susi PROPERTIES PUBLIC_HEADER "include/susi.h")
install(TARGETS susi)