#include <httplib.h>

#include "susi.h"
#include "test_helpers.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <chrono>
#include <ctime>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace susi::details {
// Defined in susi.cpp: hash two hardware IDs into a machine code, empty if either ID is empty.
std::string machineCodeFromIds(const std::string& id1, const std::string& id2);
}

namespace fs = std::filesystem;
using json = nlohmann::json;
using Status = SusiClient::LicenseStatus;
using namespace std::chrono_literals;

namespace Catch {
template <>
struct StringMaker<Status> {
    static std::string convert(Status s)
    {
        switch (s) {
        case Status::Valid: return "Valid";
        case Status::ValidGracePeriod: return "ValidGracePeriod";
        case Status::Expired: return "Expired";
        case Status::LeaseExpired: return "LeaseExpired";
        case Status::InvalidMachine: return "InvalidMachine";
        case Status::InvalidSignature: return "InvalidSignature";
        case Status::InvalidLicenseKey: return "InvalidLicenseKey";
        case Status::Revoked: return "Revoked";
        case Status::UnsignedBinary: return "UnsignedBinary";
        case Status::Deactivated: return "Deactivated";
        case Status::NotActivated: return "NotActivated";
        case Status::TokenNotFound: return "TokenNotFound";
        case Status::FileNotFound: return "FileNotFound";
        case Status::Error: return "Error";
        }
        return std::to_string(static_cast<int>(s));
    }
};
} // namespace Catch

namespace {

struct Key {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    std::string publicPem;

    Key()
    {
        REQUIRE(pkey);
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        REQUIRE(PEM_write_bio_PUBKEY(bio.get(), pkey) == 1);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio.get(), &data);
        publicPem.assign(data, static_cast<size_t>(len));
    }
    ~Key() { EVP_PKEY_free(pkey); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
};

// Key generation is slow, so each key is created once.
const Key& serverKey()
{
    static Key key;
    return key;
}

const Key& otherKey()
{
    static Key key;
    return key;
}

std::string sign(const Key& key, const std::string& data)
{
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    REQUIRE(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.pkey) == 1);
    const auto* bytes = reinterpret_cast<const unsigned char*>(data.data());
    size_t len = 0;
    REQUIRE(EVP_DigestSign(ctx.get(), nullptr, &len, bytes, data.size()) == 1);
    std::vector<unsigned char> signature(len);
    REQUIRE(EVP_DigestSign(ctx.get(), signature.data(), &len, bytes, data.size()) == 1);
    std::string base64(4 * ((len + 2) / 3), '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&base64[0]), signature.data(), static_cast<int>(len));
    base64.resize(static_cast<size_t>(n));
    return base64;
}

// Format a time relative to now the way the server does: RFC 3339 in UTC, with fractional seconds.
std::string timeFromNow(std::chrono::system_clock::duration offset)
{
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + offset);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[40];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.123456789Z", &tm);
    return buf;
}

json validPayload()
{
    return {
        {"id", "test-id"},
        {"product", "TestProduct"},
        {"customer", "Test Corp"},
        {"license_key", "AAAA-BBBB-CCCC-DDDD"},
        {"created", timeFromNow(0s)},
        {"expires", timeFromNow(24h * 365)},
        {"features", json::array({"feature_a", "feature_b"})},
        {"machine_codes", json::array()},
        {"lease_expires", nullptr},
        {"lease_grace_period", nullptr},
        {"require_signed_binary", false},
    };
}

std::string signedLicense(const json& payload, const Key& key = serverKey())
{
    const std::string data = payload.dump();
    return json{{"license_data", data}, {"signature", sign(key, data)}}.dump(2);
}

const std::vector<std::string> validFeatures{"feature_a", "feature_b"};

// 2xx bodies that aren't a signed license, e.g. from a captive portal.
auto notALicense()
{
    return Catch::Generators::values<std::string>({
        "<html><body>Please log in to the hotel Wi-Fi</body></html>",
        "",
        R"({"status": "ok"})",
        R"({"license_data": 5, "signature": "AAAA"})",
    });
}

struct CacheFile {
    fs::path dir;
    fs::path path;
    explicit CacheFile(const std::string& name) : dir(emptyTestDir(name)), path(dir / "license.json") {}
    ~CacheFile()
    {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

const unsigned char* bytes(const std::string& s)
{
    return reinterpret_cast<const unsigned char*>(s.data());
}

// Encrypt a token like susi-admin export-token: AES-256-GCM, key = HKDF-SHA256 of the USB serial.
std::string encryptToken(const std::string& plaintext, const std::string& serial)
{
    const std::string salt = "susi-token-v1";
    const std::string info = "license-encryption";
    unsigned char key[32];
    size_t keyLen = sizeof(key);
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kdf(
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
    REQUIRE(EVP_PKEY_derive_init(kdf.get()) == 1);
    REQUIRE(EVP_PKEY_CTX_set_hkdf_md(kdf.get(), EVP_sha256()) == 1);
    REQUIRE(EVP_PKEY_CTX_set1_hkdf_salt(kdf.get(), bytes(salt), static_cast<int>(salt.size())) == 1);
    REQUIRE(EVP_PKEY_CTX_set1_hkdf_key(kdf.get(), bytes(serial), static_cast<int>(serial.size())) == 1);
    REQUIRE(EVP_PKEY_CTX_add1_hkdf_info(kdf.get(), bytes(info), static_cast<int>(info.size())) == 1);
    REQUIRE(EVP_PKEY_derive(kdf.get(), key, &keyLen) == 1);

    unsigned char nonce[12];
    REQUIRE(RAND_bytes(nonce, sizeof(nonce)) == 1);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    REQUIRE(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key, nonce) == 1);
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len = 0;
    REQUIRE(EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, bytes(plaintext), static_cast<int>(plaintext.size())) == 1);
    int finalLen = 0;
    REQUIRE(EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &finalLen) == 1);
    unsigned char tag[16];
    REQUIRE(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) == 1);

    std::string blob(reinterpret_cast<const char*>(nonce), sizeof(nonce));
    blob.append(reinterpret_cast<const char*>(ciphertext.data()), static_cast<size_t>(len + finalLen));
    blob.append(reinterpret_cast<const char*>(tag), sizeof(tag));
    return blob;
}

// A directory standing in for the mount point of a USB stick.
struct UsbStick {
    fs::path dir;
    SusiClient::UsbDevice device;
    UsbStick(const std::string& name, const std::string& serial)
        : dir(emptyTestDir(name)), device{serial, dir.string(), name} {}
    ~UsbStick()
    {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    void writeToken(const std::string& blob)
    {
        fs::create_directories(dir / ".susi");
        writePlain(dir / ".susi" / "license.bin", blob);
    }
};

json tokenPayload(const std::string& serial)
{
    json payload = validPayload();
    payload["machine_codes"] = json::array({"usb:" + serial});
    return payload;
}

// Answer every POST with a fixed response and record the last request.
class CannedServer {
public:
    CannedServer(int status, std::string body)
    {
        m_server.Post(".*", [this, status, body](const httplib::Request& req, httplib::Response& res) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_path = req.path;
                m_body = req.body;
            }
            res.status = status;
            res.set_content(body, "application/json");
        });
        m_port = m_server.bind_to_any_port("127.0.0.1");
        REQUIRE(m_port > 0);
        m_thread = std::thread([this] { m_server.listen_after_bind(); });
        m_server.wait_until_ready();
    }
    ~CannedServer()
    {
        m_server.stop();
        m_thread.join();
    }
    CannedServer(const CannedServer&) = delete;
    CannedServer& operator=(const CannedServer&) = delete;

    std::string url() const { return "http://127.0.0.1:" + std::to_string(m_port) + "/api/v1"; }
    std::string path()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_path;
    }
    json requestBody()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return json::parse(m_body);
    }

private:
    httplib::Server m_server;
    std::thread m_thread;
    std::mutex m_mutex;
    std::string m_path;
    std::string m_body;
    int m_port = 0;
};

} // namespace

TEST_CASE("verifyFile accepts a valid license", "[verifyFile]")
{
    CacheFile cache("valid");
    writePlain(cache.path, signedLicense(validPayload()));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyFile(cache.path) == Status::Valid);
    CHECK(client.isValid());
    CHECK(client.product() == "TestProduct");
    CHECK(client.customer() == "Test Corp");
    CHECK(client.features() == validFeatures);
    CHECK(client.hasFeature("feature_b"));
    CHECK_FALSE(client.hasFeature("feature_c"));
    CHECK(client.isLeaseValid());
    CHECK_FALSE(client.isInGracePeriod());
    CHECK_FALSE(client.isLeaseExpired());
}

TEST_CASE("verifyFile accepts a license without expiry date", "[verifyFile]")
{
    CacheFile cache("perpetual");
    json payload = validPayload();
    payload["expires"] = nullptr;
    writePlain(cache.path, signedLicense(payload));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyFile(cache.path) == Status::Valid);
}

TEST_CASE("verifyFile rejects an expired license", "[verifyFile]")
{
    CacheFile cache("expired");
    json payload = validPayload();
    payload["expires"] = timeFromNow(-1h);
    writePlain(cache.path, signedLicense(payload));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyFile(cache.path) == Status::Expired);
    CHECK_FALSE(client.isValid());
    CHECK(client.features().empty());
}

TEST_CASE("verifyFile rejects licenses that fail signature verification", "[verifyFile]")
{
    CacheFile cache("signature");
    SusiClient client(serverKey().publicPem);

    SECTION("signed with another key")
    {
        writePlain(cache.path, signedLicense(validPayload(), otherKey()));
    }
    SECTION("license data changed after signing")
    {
        json license = json::parse(signedLicense(validPayload()));
        json payload = json::parse(license["license_data"].get<std::string>());
        payload["features"].push_back("feature_c");
        license["license_data"] = payload.dump();
        writePlain(cache.path, license.dump());
    }
    SECTION("signature isn't base64")
    {
        json license = json::parse(signedLicense(validPayload()));
        license["signature"] = "not base64!";
        writePlain(cache.path, license.dump());
    }

    CHECK(client.verifyFile(cache.path) == Status::InvalidSignature);
    CHECK_FALSE(client.isValid());
}

TEST_CASE("verifyFile reports malformed license files as errors", "[verifyFile]")
{
    CacheFile cache("malformed");
    SusiClient client(serverKey().publicPem);
    std::string contents;

    SECTION("not JSON") { contents = "not json"; }
    SECTION("not an object") { contents = "[]"; }
    SECTION("missing license data") { contents = R"({"signature": "AAAA"})"; }
    SECTION("license data isn't a string") { contents = R"({"license_data": 5, "signature": "AAAA"})"; }
    SECTION("signature isn't a string") { contents = R"({"license_data": "{}", "signature": 5})"; }
    SECTION("signed license data isn't JSON")
    {
        contents = json{{"license_data", "not json"}, {"signature", sign(serverKey(), "not json")}}.dump();
    }

    writePlain(cache.path, contents);
    CHECK(client.verifyFile(cache.path) == Status::Error);
    CHECK_FALSE(client.isValid());
}

TEST_CASE("verifyFile reports a missing file", "[verifyFile]")
{
    CacheFile cache("missing");
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyFile(cache.path) == Status::FileNotFound);
    CHECK_FALSE(client.isValid());
}

TEST_CASE("verifyFile rejects a license for another machine", "[verifyFile]")
{
    CacheFile cache("other_machine");
    json payload = validPayload();
    payload["machine_codes"] = json::array({std::string(64, '0')});
    writePlain(cache.path, signedLicense(payload));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyFile(cache.path) == Status::InvalidMachine);
    CHECK_FALSE(client.isValid());
}

TEST_CASE("verifyFile enforces the lease and its grace period", "[verifyFile]")
{
    CacheFile cache("lease");
    SusiClient client(serverKey().publicPem);
    json payload = validPayload();

    SECTION("lease not expired")
    {
        payload["lease_expires"] = timeFromNow(72h);
        writePlain(cache.path, signedLicense(payload));
        CHECK(client.verifyFile(cache.path) == Status::Valid);
        CHECK(client.isLeaseValid());
        CHECK_FALSE(client.isInGracePeriod());
        CHECK_FALSE(client.isLeaseExpired());
    }
    SECTION("lease expired, within the default grace period of 24 hours")
    {
        payload["lease_expires"] = timeFromNow(-1h);
        writePlain(cache.path, signedLicense(payload));
        CHECK(client.verifyFile(cache.path) == Status::ValidGracePeriod);
        CHECK(client.isValid());
        CHECK_FALSE(client.isLeaseValid());
        CHECK(client.isInGracePeriod());
        CHECK_FALSE(client.isLeaseExpired());
    }
    SECTION("lease expired, past the default grace period")
    {
        payload["lease_expires"] = timeFromNow(-25h);
        writePlain(cache.path, signedLicense(payload));
        CHECK(client.verifyFile(cache.path) == Status::LeaseExpired);
        CHECK_FALSE(client.isValid());
        CHECK(client.isLeaseExpired());
    }
    SECTION("lease expired, within a custom grace period")
    {
        payload["lease_expires"] = timeFromNow(-3h);
        payload["lease_grace_period"] = 4;
        writePlain(cache.path, signedLicense(payload));
        CHECK(client.verifyFile(cache.path) == Status::ValidGracePeriod);
    }
    SECTION("lease expired, past a custom grace period")
    {
        payload["lease_expires"] = timeFromNow(-3h);
        payload["lease_grace_period"] = 2;
        writePlain(cache.path, signedLicense(payload));
        CHECK(client.verifyFile(cache.path) == Status::LeaseExpired);
    }
}

TEST_CASE("verifyFile enforces require_signed_binary", "[verifyFile]")
{
    CacheFile cache("signed_binary");
    json payload = validPayload();
    payload["require_signed_binary"] = true;
    writePlain(cache.path, signedLicense(payload));
    SusiClient client(serverKey().publicPem);

#if defined(_WIN32)
    // The test executable isn't Authenticode-signed.
    CHECK(client.verifyFile(cache.path) == Status::UnsignedBinary);
#elif defined(__linux__)
    // Linux has no binary signature check.
    CHECK(client.verifyFile(cache.path) == Status::Valid);
#else
    SKIP("Depends on how the test executable is signed");
#endif
}

TEST_CASE("verifyFile accepts a public key without PEM armor", "[verifyFile]")
{
    std::string base64Key;
    std::istringstream lines(serverKey().publicPem);
    for (std::string line; std::getline(lines, line);) {
        if (line.rfind("-----", 0) != 0)
            base64Key += line;
    }
    CacheFile cache("raw_key");
    writePlain(cache.path, signedLicense(validPayload()));
    SusiClient client(base64Key);

    CHECK(client.verifyFile(cache.path) == Status::Valid);
}

TEST_CASE("verifyFile clears the result of the previous check", "[verifyFile]")
{
    CacheFile cache("reset");
    writePlain(cache.path, signedLicense(validPayload()));
    SusiClient client(serverKey().publicPem);
    REQUIRE(client.verifyFile(cache.path) == Status::Valid);

    fs::remove(cache.path);

    CHECK(client.verifyFile(cache.path) == Status::FileNotFound);
    CHECK_FALSE(client.isValid());
    CHECK(client.features().empty());
    CHECK(client.product().empty());
}


TEST_CASE("activate activates and stores the license", "[activate]")
{
    const std::string license = signedLicense(validPayload());
    CannedServer server(200, license);
    CacheFile cache("activate_store");
    SusiClient client(serverKey().publicPem, server.url());

    CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    CHECK(client.isValid());
    CHECK(client.features() == validFeatures);
    CHECK(readPlain(cache.path) == license);
    CHECK(entryCount(cache.dir) == 1);
    CHECK(server.path() == "/api/v1/activate");
    const json request = server.requestBody();
    CHECK(request.at("license_key") == "AAAA-BBBB-CCCC-DDDD");
    CHECK_FALSE(request.at("machine_code").get<std::string>().empty());
    CHECK(request.at("friendly_name").is_string());
}

TEST_CASE("activate sends the given friendly name", "[activate]")
{
    CannedServer server(200, signedLicense(validPayload()));
    CacheFile cache("activate_name");
    SusiClient client(serverKey().publicPem, server.url());

    REQUIRE(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD", "Lab PC 3") == Status::Valid);
    CHECK(server.requestBody().at("friendly_name") == "Lab PC 3");
}

TEST_CASE("activate maps server rejections and stores nothing", "[activate]")
{
    struct Rejection {
        int status;
        const char* message;
        Status expected;
    };
    const Rejection rejection = GENERATE(values<Rejection>({
        {403, "License has been revoked", Status::Revoked},
        {403, "Machine was removed by an administrator; re-activation is blocked for 1440 more minutes",
         Status::Deactivated},
        {403, "License has expired", Status::Expired},
        {403, "Machine limit reached (max 2)", Status::InvalidMachine},
        {403, "Binary signing certificate chain does not terminate at the trusted CA", Status::UnsignedBinary},
        {404, "License key not found", Status::InvalidLicenseKey},
        {500, "Internal error", Status::Error},
    }));
    CAPTURE(rejection.status, rejection.message);
    CannedServer server(rejection.status, json{{"error", rejection.message}}.dump());
    CacheFile cache("activate_rejected");
    SusiClient client(serverKey().publicPem, server.url());

    CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == rejection.expected);
    CHECK_FALSE(client.isValid());
    CHECK_FALSE(fs::exists(cache.path));
}

TEST_CASE("activate fails without a reachable server", "[activate]")
{
    CacheFile cache("activate_offline");

    SECTION("server unreachable")
    {
        // Nothing listens on port 1.
        SusiClient client(serverKey().publicPem, "http://127.0.0.1:1/api/v1");
        CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Error);
    }
    SECTION("no server configured")
    {
        SusiClient client(serverKey().publicPem);
        CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Error);
    }
    SECTION("success response that isn't a license")
    {
        const std::string body = GENERATE(notALicense());
        CAPTURE(body);
        CannedServer server(200, body);
        SusiClient client(serverKey().publicPem, server.url());
        CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Error);
    }

    CHECK_FALSE(fs::exists(cache.path));
}

TEST_CASE("Online checks keep the cached license when the response doesn't verify", "[activate][verify]")
{
    const std::string cached = signedLicense(validPayload());
    CannedServer server(200, signedLicense(validPayload(), otherKey()));
    CacheFile cache("online_bad_response");
    writePlain(cache.path, cached);
    SusiClient client(serverKey().publicPem, server.url());

    SECTION("activate")
    {
        CHECK(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::InvalidSignature);
    }
    SECTION("verifyAndRefresh")
    {
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::InvalidSignature);
    }

    CHECK_FALSE(client.isValid());
    CHECK(readPlain(cache.path) == cached);
}

TEST_CASE("verifyAndRefresh without a cached license reports NotActivated", "[verify]")
{
    CannedServer server(200, signedLicense(validPayload()));
    CacheFile cache("verify_not_activated");
    SusiClient client(serverKey().publicPem, server.url());

    CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::NotActivated);
    CHECK_FALSE(client.isValid());
    CHECK(server.path().empty());
    CHECK_FALSE(fs::exists(cache.path));
}

TEST_CASE("verifyAndRefresh renews and stores the license", "[verify]")
{
    json payload = validPayload();
    payload["lease_expires"] = timeFromNow(1h);
    CacheFile cache("verify_store");
    writePlain(cache.path, signedLicense(payload));
    payload["lease_expires"] = timeFromNow(72h);
    const std::string renewed = signedLicense(payload);
    CannedServer server(200, renewed);
    SusiClient client(serverKey().publicPem, server.url());

    CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    CHECK(client.features() == validFeatures);
    CHECK(readPlain(cache.path) == renewed);
    CHECK(entryCount(cache.dir) == 1);
    CHECK(server.path() == "/api/v1/verify");
    const json request = server.requestBody();
    CHECK(request.at("license_key") == "AAAA-BBBB-CCCC-DDDD");
    CHECK_FALSE(request.at("machine_code").get<std::string>().empty());
    CHECK_FALSE(request.contains("friendly_name"));
}

TEST_CASE("verifyAndRefresh replaces a cached license that a reader holds open", "[verify]")
{
    json payload = validPayload();
    const std::string oldLicense = signedLicense(payload);
    payload["lease_expires"] = timeFromNow(72h);
    const std::string newLicense = signedLicense(payload);
    CannedServer server(200, newLicense);
    CacheFile cache("verify_held");
    writePlain(cache.path, oldLicense);
    SusiClient client(serverKey().publicPem, server.url());
    HeldFile held(cache.path);

    CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    CHECK(readPlain(cache.path) == newLicense);
    CHECK(held.read() == oldLicense);
}

TEST_CASE("verifyAndRefresh maps server rejections and removes the cached license", "[verify]")
{
    struct Rejection {
        int status;
        const char* message;
        Status expected;
    };
    const Rejection rejection = GENERATE(values<Rejection>({
        {403, "License has been revoked", Status::Revoked},
        {403, "Machine not authorized for this license", Status::Deactivated},
        {403, "License has expired", Status::Expired},
        {403, "Binary signing certificate chain does not terminate at the trusted CA", Status::UnsignedBinary},
        {404, "License key not found", Status::InvalidLicenseKey},
    }));
    CAPTURE(rejection.status, rejection.message);
    CannedServer server(rejection.status, json{{"error", rejection.message}}.dump());
    CacheFile cache("verify_rejected");
    writePlain(cache.path, signedLicense(validPayload()));
    SusiClient client(serverKey().publicPem, server.url());

    CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == rejection.expected);
    CHECK_FALSE(client.isValid());
    CHECK_FALSE(fs::exists(cache.path));
}

TEST_CASE("verifyAndRefresh falls back to the cached license", "[verify]")
{
    CacheFile cache("verify_fallback");
    const std::string cached = signedLicense(validPayload());
    writePlain(cache.path, cached);

    SECTION("server error")
    {
        CannedServer server(500, R"({"error": "Internal error"})");
        SusiClient client(serverKey().publicPem, server.url());
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    }
    SECTION("rejection the client doesn't act on")
    {
        CannedServer server(403, json{{"error", "Machine limit reached (max 2)"}}.dump());
        SusiClient client(serverKey().publicPem, server.url());
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    }
    SECTION("success response that isn't a license")
    {
        const std::string body = GENERATE(notALicense());
        CAPTURE(body);
        CannedServer server(200, body);
        SusiClient client(serverKey().publicPem, server.url());
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    }
    SECTION("server unreachable")
    {
        // Nothing listens on port 1.
        SusiClient client(serverKey().publicPem, "http://127.0.0.1:1/api/v1");
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    }
    SECTION("no server configured")
    {
        SusiClient client(serverKey().publicPem);
        CHECK(client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    }

    CHECK(readPlain(cache.path) == cached);
}

TEST_CASE("verifyFile accepts a license for the machine code sent to the server", "[activate]")
{
    CannedServer server(200, signedLicense(validPayload()));
    CacheFile cache("machine_code");
    SusiClient client(serverKey().publicPem, server.url());
    REQUIRE(client.activate(cache.path, "AAAA-BBBB-CCCC-DDDD") == Status::Valid);
    const std::string machineCode = server.requestBody().at("machine_code").get<std::string>();

    json payload = validPayload();
    payload["machine_codes"] = json::array({machineCode});
    writePlain(cache.path, signedLicense(payload));

    CHECK(client.verifyFile(cache.path) == Status::Valid);
}

#ifdef _WIN32
TEST_CASE("verifyAndRefresh doesn't throw when the cached license can't be removed", "[verify]")
{
    CannedServer server(403, R"({"error": "License has been revoked"})");
    CacheFile cache("verify_locked");
    writePlain(cache.path, signedLicense(validPayload()));
    SusiClient client(serverKey().publicPem, server.url());
    // MSVC's std::ifstream opens files like this, and removing the file then fails.
    HeldFile held(cache.path, FILE_SHARE_READ | FILE_SHARE_WRITE);

    Status status = Status::Valid;
    REQUIRE_NOTHROW(status = client.verifyAndRefresh(cache.path, "AAAA-BBBB-CCCC-DDDD"));
    CHECK(status == Status::Revoked);
}
#endif

TEST_CASE("machineCodeFromIds refuses incomplete hardware IDs", "[machineCode]")
{
    using susi::details::machineCodeFromIds;
    CHECK(machineCodeFromIds("", "").empty());
    CHECK(machineCodeFromIds("", "CPUID-ABC123").empty());
    CHECK(machineCodeFromIds("BIOS-UUID-0001", "").empty());
    CHECK(machineCodeFromIds("---", "CPUID-ABC123").empty());
}

TEST_CASE("machineCodeFromIds hashes the normalized IDs", "[machineCode]")
{
    using susi::details::machineCodeFromIds;
    // SHA-256 of "biosuuid0001|cpuidabc123", as susi_core::fingerprint computes it.
    const std::string expected = "7b20c46578b75b6b05d1375158760355c94198f24602e78266bf3cb41c686a03";
    CHECK(machineCodeFromIds("BIOS-UUID-0001", "CPUID-ABC123") == expected);
    CHECK(machineCodeFromIds("biosuuid0001", "cpuidabc123") == expected);
    CHECK(machineCodeFromIds("BIOS--UUID--0001", "CPUID-ABC-123") == expected);
    CHECK(machineCodeFromIds("BIOS-UUID-9999", "CPUID-ABC123") != expected);
}

TEST_CASE("verifyTokenOn accepts a valid token", "[verifyToken]")
{
    UsbStick stick("token_valid", "SERIAL-A");
    stick.writeToken(encryptToken(signedLicense(tokenPayload("SERIAL-A")), "SERIAL-A"));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyTokenOn({stick.device}) == Status::Valid);
    CHECK(client.isValid());
    CHECK(client.features() == validFeatures);
}

TEST_CASE("verifyTokenOn reports why a token is invalid", "[verifyToken]")
{
    UsbStick stick("token_invalid", "SERIAL-A");
    json payload = tokenPayload("SERIAL-A");
    const Key* key = &serverKey();
    Status expected = Status::Valid;

    SECTION("expired")
    {
        payload["expires"] = timeFromNow(-1h);
        expected = Status::Expired;
    }
    SECTION("bound to another USB stick")
    {
        payload["machine_codes"] = json::array({"usb:SERIAL-B"});
        expected = Status::InvalidMachine;
    }
    SECTION("signed with another key")
    {
        key = &otherKey();
        expected = Status::InvalidSignature;
    }

    stick.writeToken(encryptToken(signedLicense(payload, *key), "SERIAL-A"));
    SusiClient client(serverKey().publicPem);
    CHECK(client.verifyTokenOn({stick.device}) == expected);
    CHECK_FALSE(client.isValid());
    CHECK(client.features().empty());
}

TEST_CASE("verifyTokenOn prefers a valid token over an invalid one", "[verifyToken]")
{
    UsbStick expired("token_prefer_expired", "SERIAL-A");
    json payload = tokenPayload("SERIAL-A");
    payload["expires"] = timeFromNow(-1h);
    expired.writeToken(encryptToken(signedLicense(payload), "SERIAL-A"));
    UsbStick valid("token_prefer_valid", "SERIAL-B");
    valid.writeToken(encryptToken(signedLicense(tokenPayload("SERIAL-B")), "SERIAL-B"));
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyTokenOn({expired.device, valid.device}) == Status::Valid);
    CHECK(client.isValid());
}

TEST_CASE("verifyTokenOn reports an error for a token it can't decrypt", "[verifyToken]")
{
    UsbStick stick("token_undecryptable", "SERIAL-A");
    SECTION("encrypted for another USB stick")
    {
        stick.writeToken(encryptToken(signedLicense(tokenPayload("SERIAL-A")), "SERIAL-B"));
    }
    SECTION("corrupted")
    {
        std::string blob = encryptToken(signedLicense(tokenPayload("SERIAL-A")), "SERIAL-A");
        blob.back() ^= 0x01;
        stick.writeToken(blob);
    }
    SECTION("too short") { stick.writeToken("short"); }
    SusiClient client(serverKey().publicPem);

    CHECK(client.verifyTokenOn({stick.device}) == Status::Error);
    CHECK_FALSE(client.isValid());
}

TEST_CASE("verifyTokenOn reports an invalid token over one it can't decrypt", "[verifyToken]")
{
    UsbStick expired("token_mixed_expired", "SERIAL-A");
    json payload = tokenPayload("SERIAL-A");
    payload["expires"] = timeFromNow(-1h);
    expired.writeToken(encryptToken(signedLicense(payload), "SERIAL-A"));
    UsbStick undecryptable("token_mixed_undecryptable", "SERIAL-B");
    undecryptable.writeToken(encryptToken(signedLicense(tokenPayload("SERIAL-B")), "SERIAL-C"));
    SusiClient client(serverKey().publicPem);

    const bool expiredFirst = GENERATE(true, false);
    CAPTURE(expiredFirst);
    const std::vector<SusiClient::UsbDevice> devices = expiredFirst
        ? std::vector<SusiClient::UsbDevice>{expired.device, undecryptable.device}
        : std::vector<SusiClient::UsbDevice>{undecryptable.device, expired.device};
    CHECK(client.verifyTokenOn(devices) == Status::Expired);
}

TEST_CASE("verifyTokenOn reports TokenNotFound without a token", "[verifyToken]")
{
    SusiClient client(serverKey().publicPem);

    SECTION("no USB devices")
    {
        CHECK(client.verifyTokenOn({}) == Status::TokenNotFound);
    }
    SECTION("USB device without a token")
    {
        UsbStick stick("token_none", "SERIAL-A");
        CHECK(client.verifyTokenOn({stick.device}) == Status::TokenNotFound);
    }
    CHECK_FALSE(client.isValid());
}
