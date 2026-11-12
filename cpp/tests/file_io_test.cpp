#include "file_io.h"
#include "test_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using susi::details::readWholeFile;
using susi::details::writeFileReplace;

namespace {

std::string readByName(const fs::path& path)
{
    std::string s;
    REQUIRE(readWholeFile(path, s));
    return s;
}

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
