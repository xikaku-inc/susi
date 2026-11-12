#include "file_io.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;
using susi::details::readWholeFile;
using susi::details::writeFileReplace;

namespace {

fs::path emptyTestDir(const std::string& name)
{
    fs::path dir = fs::temp_directory_path() / ("susi_cpp_" + name);
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

size_t entryCount(const fs::path& dir)
{
    return static_cast<size_t>(std::distance(fs::directory_iterator(dir), fs::directory_iterator()));
}

void writePlain(const fs::path& path, const std::string& data)
{
    std::ofstream(path, std::ios::binary) << data;
}

std::string readByName(const fs::path& path)
{
    std::string s;
    REQUIRE(readWholeFile(path, s));
    return s;
}

// Hold a file open the way another reader would, by default sharing all access.
struct HeldFile {
#ifdef _WIN32
    HANDLE h;
    explicit HeldFile(const fs::path& path, DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        : h(CreateFileW(path.c_str(), GENERIC_READ, share, nullptr, OPEN_EXISTING, 0, nullptr))
    {
        REQUIRE(h != INVALID_HANDLE_VALUE);
    }
    ~HeldFile() { CloseHandle(h); }
    std::string read()
    {
        char buf[256];
        DWORD n = 0;
        REQUIRE(ReadFile(h, buf, sizeof(buf), &n, nullptr));
        return std::string(buf, n);
    }
#else
    std::ifstream f;
    explicit HeldFile(const fs::path& path) : f(path, std::ios::binary) { REQUIRE(f.is_open()); }
    std::string read() { return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()); }
#endif
};

} // namespace

TEST_CASE("writeFileReplace creates a missing file")
{
    const fs::path dir = emptyTestDir("replace_create");
    const fs::path path = dir / "license.json";

    REQUIRE(writeFileReplace(path, "new"));

    CHECK(readByName(path) == "new");
    CHECK(entryCount(dir) == 1);
    fs::remove_all(dir);
}

TEST_CASE("writeFileReplace replaces a file that a reader holds open")
{
    const fs::path dir = emptyTestDir("replace_held");
    const fs::path path = dir / "license.json";
    writePlain(path, "old");
    {
        HeldFile held(path);

        REQUIRE(writeFileReplace(path, "new"));

        CHECK(readByName(path) == "new");
        CHECK(held.read() == "old");
    }
    CHECK(entryCount(dir) == 1);
    fs::remove_all(dir);
}

#ifdef _WIN32
TEST_CASE("writeFileReplace fails cleanly when a reader denies delete access")
{
    // MSVC's std::ifstream opens files with this sharing mode.
    const fs::path dir = emptyTestDir("replace_denied");
    const fs::path path = dir / "license.json";
    writePlain(path, "old");
    {
        HeldFile held(path, FILE_SHARE_READ | FILE_SHARE_WRITE);
        CHECK_FALSE(writeFileReplace(path, "new"));
    }
    CHECK(readByName(path) == "old");
    CHECK(entryCount(dir) == 1);
    fs::remove_all(dir);
}
#endif

TEST_CASE("readWholeFile neither sees partial files nor blocks writeFileReplace")
{
    const fs::path dir = emptyTestDir("replace_concurrent");
    const fs::path path = dir / "license.json";
    const std::string a(64 * 1024, 'a');
    const std::string b(100 * 1024, 'b');
    REQUIRE(writeFileReplace(path, a));

    // Catch2 assertions aren't thread-safe, so the writer only counts.
    std::atomic<int> failedWrites{0};
    std::atomic<bool> done{false};
    std::thread writer([&] {
        for (int i = 0; i < 200; ++i)
            if (!writeFileReplace(path, i % 2 == 0 ? b : a))
                ++failedWrites;
        done = true;
    });
    int reads = 0;
    int badReads = 0;
    while (!done) {
        std::string s;
        if (!readWholeFile(path, s) || (s != a && s != b))
            ++badReads;
        ++reads;
    }
    writer.join();

    CHECK(failedWrites == 0);
    CHECK(badReads == 0);
    CHECK(reads > 0);
    CHECK(entryCount(dir) == 1);
    fs::remove_all(dir);
}
