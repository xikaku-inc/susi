# Added by the parent directory when SUSI_BUILD_TESTS is ON. Build and run from cpp/:
#   conan build . -o "&:build_tests=True" --build=missing
#   ctest --preset conan-release --output-on-failure

find_package(Catch2 3 REQUIRED)
find_package(httplib REQUIRED)
include(Catch)

add_executable(susi_tests file_io_test.cpp susi_client_test.cpp)
target_include_directories(susi_tests PRIVATE ../src)
target_compile_options(susi_tests PRIVATE "$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
target_link_libraries(susi_tests PRIVATE
    susi
    Catch2::Catch2WithMain
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto)
catch_discover_tests(susi_tests)
