#ifndef SUSI_FILE_IO_H
#define SUSI_FILE_IO_H

#include <filesystem>
#include <string>

namespace susi::details {

/// Read the whole file. Other processes can replace or delete the file while it is open here.
bool readWholeFile(const std::filesystem::path& path, std::string& out);

/// Write data to a temporary file next to path and rename it over path, so that readers see
/// either the old or the new file, never a partial one. On Windows this also succeeds while
/// readers hold path open, as long as they opened it with FILE_SHARE_DELETE (as readWholeFile
/// and Rust's std::fs::File do).
bool writeFileReplace(const std::filesystem::path& path, const std::string& data);

} // namespace susi::details

#endif
