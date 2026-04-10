// Integration test binary for the susi C++ client.
//
// Runs against a live susi-server and verifies the full activate →
// verify round-trip.  Exits 0 on success, 1 on any failure.
//
// Usage:
//   PackageTest --server-url <url> --public-key-file <path> --license-key <key>
//
// The susi Rust integration test (crates/susi_server/tests/integration.rs)
// drives this binary automatically when conan is available.  It can also be
// run manually against a running server for ad-hoc testing.
#include <susi.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

static void fail(const std::string& msg)
{
    std::cerr << "[susi-cpp-test] FAIL: " << msg << "\n";
    std::exit(1);
}

static std::string readFile(const std::string& path)
{
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("cannot open: " + path);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool haveHelpArg(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--help"
            || std::string(argv[i]) == "-h")
            return true;
    return false;
}

static std::string parseArg(int argc, char** argv, const std::string& flag)
{
    for (int i = 1; i < argc - 1; ++i)
        if (std::string(argv[i]) == flag)
            return argv[i + 1];
    throw std::runtime_error("missing argument: " + flag);
}

int main(int argc, char** argv)
{
    const char helpMessage[] = 
        "Usage: PackageTest"
        " --server-url <url>"
        " --public-key-file <path>"
        " --license-key <key>\n";
    if (haveHelpArg(argc, argv)) {
        std::cout << helpMessage;
        return 0;
    }

    std::string serverUrl, publicKeyFile, licenseKey;
    try {
        serverUrl     = parseArg(argc, argv, "--server-url");
        publicKeyFile = parseArg(argc, argv, "--public-key-file");
        licenseKey    = parseArg(argc, argv, "--license-key");
    } catch (const std::exception& e) {
        std::cerr << helpMessage
                  << "Error: " << e.what() << "\n";
        return 1;
    }

    std::string publicKey;
    try {
        publicKey = readFile(publicKeyFile);
    } catch (const std::exception& e) {
        fail(e.what());
    }

    // The license file lives next to the public key file.
    std::string licenseFile = publicKeyFile + ".license.json";

    SusiClient client(publicKey, serverUrl);

    // -----------------------------------------------------------------------
    // Test 1: verify_and_refresh — should activate and return Valid
    // -----------------------------------------------------------------------
    std::cout << "[susi-cpp-test] Test 1: checkLicenseAndRefresh\n";
    auto status = client.checkLicenseAndRefresh(licenseFile, licenseKey);
    if (!client.isValid())
        fail("checkLicenseAndRefresh: expected Valid, got non-valid status");

    std::cout << "  product:  " << client.product()  << "\n";
    std::cout << "  customer: " << client.customer() << "\n";
    std::cout << "  features:";
    for (const auto& f : client.features())
        std::cout << " " << f;
    std::cout << "\n";

    if (!client.hasFeature("imu_optical_fusion"))
        fail("expected feature 'imu_optical_fusion' not present");
    if (client.hasFeature("vehicular_fusion"))
        fail("unexpected feature 'vehicular_fusion' present");

    // -----------------------------------------------------------------------
    // Test 2: lease renewal — calling again must still be Valid
    // -----------------------------------------------------------------------
    std::cout << "[susi-cpp-test] Test 2: lease renewal\n";
    SusiClient client2(publicKey, serverUrl);
    status = client2.checkLicenseAndRefresh(licenseFile, licenseKey);
    if (!client2.isValid())
        fail("lease renewal: expected Valid");

    // -----------------------------------------------------------------------
    // Test 3: offline fallback — checkLicense from the cached file
    // -----------------------------------------------------------------------
    std::cout << "[susi-cpp-test] Test 3: offline fallback (cached file)\n";
    SusiClient client3(publicKey);
    status = client3.checkLicense(licenseFile);
    if (!client3.isValid())
        fail("offline fallback: expected Valid from cached file");

    std::cout << "[susi-cpp-test] All tests passed.\n";
    return 0;
}
