#include "file_io.h"

#include <atomic>
#include <fstream>
#include <iterator>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstring>
#include <vector>
#else
#include <unistd.h>
#endif

namespace susi::details {

#ifdef _WIN32
bool readWholeFile(const std::filesystem::path& path, std::string& out)
{
    // std::ifstream doesn't share delete access, which would make writeFileReplace fail.
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    out.clear();
    char buf[4096];
    bool ok = true;
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(h, buf, sizeof(buf), &n, nullptr)) {
            ok = false;
            break;
        }
        if (n == 0)
            break;
        out.append(buf, n);
    }
    CloseHandle(h);
    return ok;
}

static bool renameReplace(const std::filesystem::path& from, const std::filesystem::path& to)
{
    if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING))
        return true;
    // MoveFileExW fails while a reader holds the target open, even one sharing delete access.
    // POSIX semantics replace the name and leave open handles on the old file.
    if (GetLastError() != ERROR_ACCESS_DENIED)
        return false;
    HANDLE h = CreateFileW(from.c_str(), DELETE | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    const std::wstring name = std::filesystem::absolute(to).native();
    const DWORD nameBytes = static_cast<DWORD>(name.size() * sizeof(wchar_t));
    std::vector<char> buf(sizeof(FILE_RENAME_INFO) + nameBytes);
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    info->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
    info->RootDirectory = nullptr;
    info->FileNameLength = nameBytes;
    std::memcpy(info->FileName, name.data(), nameBytes);
    const BOOL ok = SetFileInformationByHandle(h, FileRenameInfoEx, info, static_cast<DWORD>(buf.size()));
    CloseHandle(h);
    return ok != 0;
}

static unsigned long processId()
{
    return GetCurrentProcessId();
}
#else
bool readWholeFile(const std::filesystem::path& path, std::string& out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
        return false;
    out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return !f.bad();
}

static bool renameReplace(const std::filesystem::path& from, const std::filesystem::path& to)
{
    std::error_code ec;
    std::filesystem::rename(from, to, ec);
    return !ec;
}

static unsigned long processId()
{
    return static_cast<unsigned long>(getpid());
}
#endif

bool writeFileReplace(const std::filesystem::path& path, const std::string& data)
{
    static std::atomic<unsigned> counter{0};
    std::filesystem::path tmp = path;
    tmp += "." + std::to_string(processId()) + "." + std::to_string(counter++) + ".tmp";
    bool ok;
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        ok = f.is_open() && f.write(data.data(), static_cast<std::streamsize>(data.size())) && f.flush();
    }
    ok = ok && renameReplace(tmp, path);
    if (!ok) {
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
    }
    return ok;
}

} // namespace susi::details
