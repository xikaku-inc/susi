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

add_library(susi STATIC susi.cpp susi.h)
target_include_directories(susi PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(susi PUBLIC cxx_std_17)

# OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(susi PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# nlohmann/json
find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
    target_link_libraries(susi PRIVATE nlohmann_json::nlohmann_json)
else()
    include(FetchContent)
    FetchContent_Declare(json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(json)
    target_link_libraries(susi PRIVATE nlohmann_json::nlohmann_json)
endif()

# Windows network libraries
if(WIN32)
    target_link_libraries(susi PRIVATE iphlpapi ws2_32)
endif()
