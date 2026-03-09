cmake_minimum_required(VERSION 3.16)
project(PackageTest)

find_package(susi CONFIG REQUIRED)

add_executable(PackageTest main.cpp)
target_link_libraries(PackageTest PRIVATE susi::susi)
target_compile_features(PackageTest PRIVATE cxx_std_17)
