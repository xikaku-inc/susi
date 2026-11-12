cmake_minimum_required(VERSION 3.16)
project(susi_tests LANGUAGES CXX)

# Tests for the parts of the library that need neither OpenSSL nor libcurl.
# Build and run from cpp/tests:
#   conan build . --build=missing
#   ctest --preset conan-release --output-on-failure

find_package(Catch2 3 REQUIRED)
include(CTest)
include(Catch)

add_executable(susi_tests file_io_test.cpp ../src/file_io.cpp)
target_include_directories(susi_tests PRIVATE ../src)
target_compile_features(susi_tests PRIVATE cxx_std_17)
target_link_libraries(susi_tests PRIVATE Catch2::Catch2WithMain)
catch_discover_tests(susi_tests)
