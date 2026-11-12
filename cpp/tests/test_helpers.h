#ifndef SUSI_TEST_HELPERS_H
#define SUSI_TEST_HELPERS_H

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

inline std::filesystem::path emptyTestDir(const std::string& name)
{
    std::filesystem::path dir = std::filesystem::temp_directory_path() / ("susi_cpp_" + name);
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

inline size_t entryCount(const std::filesystem::path& dir)
{
    return static_cast<size_t>(
        std::distance(std::filesystem::directory_iterator(dir), std::filesystem::directory_iterator()));
}

inline void writePlain(const std::filesystem::path& path, const std::string& data)
{
    std::ofstream(path, std::ios::binary) << data;
}

inline std::string readPlain(const std::filesystem::path& path)
{
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Hold a file open the way another reader would, by default sharing all access.
struct HeldFile {
#ifdef _WIN32
    HANDLE h;
    explicit HeldFile(const std::filesystem::path& path,
                      DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        : h(CreateFileW(path.c_str(), GENERIC_READ, share, nullptr, OPEN_EXISTING, 0, nullptr))
    {
        REQUIRE(h != INVALID_HANDLE_VALUE);
    }
    ~HeldFile() { CloseHandle(h); }
    std::string read()
    {
        std::string out;
        char buf[4096];
        DWORD n = 0;
        while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n > 0)
            out.append(buf, n);
        return out;
    }
#else
    std::ifstream f;
    explicit HeldFile(const std::filesystem::path& path) : f(path, std::ios::binary) { REQUIRE(f.is_open()); }
    std::string read() { return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()); }
#endif
};

#endif
