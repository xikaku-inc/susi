#include "susi.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <curl/curl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <softpub.h>
#include <wintrust.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "wintrust.lib")
#else
#include <climits>
#include <dirent.h>
#include <unistd.h>
#include <unordered_map>
#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>
#include <mach-o/dyld.h>
#include <sys/mount.h>
#endif
#endif

using json = nlohmann::json;

#ifndef SUSI_LOG
#define SUSI_LOG(fmt, ...) fprintf(stderr, "[susi] " fmt "\n", ##__VA_ARGS__)
#endif

// ---------------------------------------------------------------------------
// Base64 decoding (OpenSSL)
// ---------------------------------------------------------------------------
static std::vector<unsigned char> base64Decode(const std::string& encoded)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
    bmem = BIO_push(b64, bmem);

    std::vector<unsigned char> out(encoded.size());
    int len = BIO_read(bmem, out.data(), static_cast<int>(out.size()));
    BIO_free_all(bmem);

    if (len < 0) return {};
    out.resize(static_cast<size_t>(len));
    return out;
}

// ---------------------------------------------------------------------------
// Hex encoding
// ---------------------------------------------------------------------------
static std::string hexEncode(const unsigned char* data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex[(data[i] >> 4) & 0x0F]);
        result.push_back(hex[data[i] & 0x0F]);
    }
    return result;
}

// ---------------------------------------------------------------------------
// RSA-SHA256 signature verification using OpenSSL EVP API
// ---------------------------------------------------------------------------
static bool verifySignature(
    const std::string& publicKeyPem,
    const std::string& data,
    const std::vector<unsigned char>& signature)
{
    BIO* bio = BIO_new_mem_buf(publicKeyPem.data(), static_cast<int>(publicKeyPem.size()));
    if (!bio) return false;

    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool valid = false;

    if (ctx) {
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
            EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1 &&
            EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1) {
            valid = true;
        }
        EVP_MD_CTX_free(ctx);
    }

    EVP_PKEY_free(pkey);
    return valid;
}

// ---------------------------------------------------------------------------
// Hardware fingerprinting (must match susi_core::fingerprint)
// ---------------------------------------------------------------------------
#ifdef _WIN32
static std::vector<std::string> getMacAddresses()
{
    std::vector<std::string> macs;

    ULONG bufLen = 15000;
    std::vector<unsigned char> buffer;

    for (;;) {
        buffer.resize(bufLen);
        ULONG ret = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &bufLen);

        if (ret == ERROR_SUCCESS) break;
        if (ret == ERROR_BUFFER_OVERFLOW) continue;
        return macs;
    }

    auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    while (adapter) {
        if (adapter->PhysicalAddressLength == 6) {
            bool allZero = true;
            for (DWORD i = 0; i < 6; ++i) {
                if (adapter->PhysicalAddress[i] != 0) {
                    allZero = false;
                    break;
                }
            }
            if (!allZero) {
                macs.push_back(hexEncode(adapter->PhysicalAddress, 6));
            }
        }
        adapter = adapter->Next;
    }

    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
    return macs;
}

static std::string getHostname()
{
    DWORD size = 0;
    GetComputerNameExW(ComputerNamePhysicalDnsHostname, nullptr, &size);

    std::vector<wchar_t> buf(size);
    if (!GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.data(), &size)) {
        return "";
    }

    int needed = WideCharToMultiByte(CP_UTF8, 0, buf.data(), static_cast<int>(size), nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf.data(), static_cast<int>(size), result.data(), needed, nullptr, nullptr);
    return result;
}
#else
static std::vector<std::string> getMacAddresses()
{
    std::vector<std::string> macs;

    DIR* dir = opendir("/sys/class/net");
    if (!dir) return macs;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "lo" || name == "." || name == "..") continue;

        std::string path = "/sys/class/net/" + name + "/address";
        std::ifstream f(path);
        if (!f.is_open()) continue;

        std::string mac;
        std::getline(f, mac);

        while (!mac.empty() && (mac.back() == '\n' || mac.back() == '\r' || mac.back() == ' '))
            mac.pop_back();

        std::transform(mac.begin(), mac.end(), mac.begin(), ::tolower);

        if (mac.empty() || mac == "00:00:00:00:00:00") continue;

        std::string normalized;
        for (char c : mac) {
            if (c != ':') normalized.push_back(c);
        }
        macs.push_back(normalized);
    }
    closedir(dir);

    std::sort(macs.begin(), macs.end());
    macs.erase(std::unique(macs.begin(), macs.end()), macs.end());
    return macs;
}

static std::string getHostname()
{
    std::ifstream f("/etc/hostname");
    if (f.is_open()) {
        std::string hostname;
        std::getline(f, hostname);
        while (!hostname.empty() && (hostname.back() == '\n' || hostname.back() == '\r' || hostname.back() == ' '))
            hostname.pop_back();
        return hostname;
    }

    char buf[256] = {};
    if (gethostname(buf, sizeof(buf)) == 0) {
        return std::string(buf);
    }
    return "";
}
#endif

static std::string getMachineCode()
{
    auto macs = getMacAddresses();
    std::string hostname = getHostname();

    std::sort(macs.begin(), macs.end());
    macs.push_back(hostname);

    std::string combined;
    for (size_t i = 0; i < macs.size(); ++i) {
        if (i > 0) combined += "|";
        combined += macs[i];
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(combined.data()), combined.size(), hash);
    return hexEncode(hash, SHA256_DIGEST_LENGTH);
}

// ---------------------------------------------------------------------------
// ISO 8601 date parsing (enough for RFC 3339 timestamps from our licenses)
// ---------------------------------------------------------------------------
static time_t parseIsoTimestamp(const std::string& str)
{
    std::tm tm = {};
#ifdef _WIN32
    int parsed = sscanf_s(str.c_str(), "%d-%d-%dT%d:%d:%d",
#else
    int parsed = sscanf(str.c_str(), "%d-%d-%dT%d:%d:%d",
#endif
                        &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                        &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (parsed >= 6) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
#ifdef _WIN32
        return _mkgmtime(&tm);
#else
        return timegm(&tm);
#endif
    }
    return -1;
}

static bool isExpired(const json& payload)
{
    if (!payload.contains("expires") || payload.at("expires").is_null()) {
        return false; // perpetual
    }

    std::string expiresStr = payload.at("expires").get<std::string>();
    time_t expires = parseIsoTimestamp(expiresStr);
    if (expires == -1) {
        SUSI_LOG("Could not parse expires date: %s", expiresStr.c_str());
        return true; // fail safe
    }
    return time(nullptr) > expires;
}

// ---------------------------------------------------------------------------
// HTTP helper for server activation
// ---------------------------------------------------------------------------
static size_t curlWriteCallback(char* ptr, size_t size, size_t nmemb, std::string* data)
{
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

static void initCurl()
{
    static std::once_flag flag;
    std::call_once(flag, [] {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        atexit([] { curl_global_cleanup(); });
    });
}

static long httpPost(const std::string& url, const std::string& body, std::string& response)
{
    initCurl();

    CURL* curl = curl_easy_init();
    if (!curl) return 0;

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        SUSI_LOG("HTTP request failed: %s", curl_easy_strerror(res));
        return 0;
    }
    return httpCode;
}


std::string SusiClient::getPublicKeyPem()
{
    std::string key(m_publicKey);
    if (key.empty() || key.find("-----BEGIN") != std::string::npos) {
        return key;
    }

    // Wrap raw base64 DER in PEM headers
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    for (size_t i = 0; i < key.size(); i += 64) {
        pem += key.substr(i, 64) + "\n";
    }
    pem += "-----END PUBLIC KEY-----\n";
    return pem;
}

// ---------------------------------------------------------------------------
// Binary signing verification
// ---------------------------------------------------------------------------
static bool isBinarySigned()
{
#if defined(_WIN32)
    wchar_t exePath[MAX_PATH] = {};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
        return false;

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = exePath;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG;

    LONG result = WinVerifyTrust(nullptr, &action, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);

    return result == ERROR_SUCCESS;
#elif defined(__APPLE__)
    char exePath[PATH_MAX] = {};
    uint32_t size = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &size) != 0)
        return false;

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        nullptr, reinterpret_cast<const UInt8*>(exePath), strlen(exePath), false);
    if (!url)
        return false;

    SecStaticCodeRef code = nullptr;
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != errSecSuccess || !code)
        return false;

    status = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, nullptr);
    CFRelease(code);
    return status == errSecSuccess;
#else
    return true; // No standard binary signing on Linux
#endif
}

// ---------------------------------------------------------------------------
// Startup enforcement (compile with -DSUSI_REQUIRE_SIGNED_BINARY=1)
// ---------------------------------------------------------------------------
// When SUSI_REQUIRE_SIGNED_BINARY is defined at compile time, a static object
// is instantiated before main() whose constructor aborts the process if the
// binary is not code-signed.  This ensures an attacker cannot reach any
// application logic — including the license verification code — with a
// tampered binary.
//
// Enable in CMake:
//   cmake -DSUSI_REQUIRE_SIGNED_BINARY=ON ...
// Enable manually:
//   add_compile_definitions(SUSI_REQUIRE_SIGNED_BINARY=1)
#ifdef SUSI_REQUIRE_SIGNED_BINARY
namespace {
struct SusiSignatureEnforcer {
    SusiSignatureEnforcer() {
        if (!isBinarySigned()) {
            fprintf(stderr,
                "[susi] FATAL: Binary signature check failed at startup. "
                "This binary has not been code-signed or has been tampered with.\n");
            fflush(stderr);
            abort();
        }
    }
};
static SusiSignatureEnforcer g_susiSignatureEnforcer;
}
#endif

// ---------------------------------------------------------------------------
// Shared license verify logic
// ---------------------------------------------------------------------------
SusiClient::LicenseStatus SusiClient::verifySignedLicenseJson(const std::string& signedLicenseStr, const std::string& activationCode)
{
    json signedLicense;
    try {
        signedLicense = json::parse(signedLicenseStr);
    } catch (const json::exception& e) {
        SUSI_LOG("Invalid license format: %s", e.what());
        return LicenseStatus::Error;
    }

    if (!signedLicense.contains("license_data") || !signedLicense.contains("signature")) {
        SUSI_LOG("License missing required fields (license_data, signature)");
        return LicenseStatus::Error;
    }

    std::string licenseData = signedLicense.at("license_data").get<std::string>();
    std::string signatureB64 = signedLicense.at("signature").get<std::string>();

    // Decode signature from base64
    auto signatureBytes = base64Decode(signatureB64);
    if (signatureBytes.empty()) {
        SUSI_LOG("Failed to decode license signature");
        return LicenseStatus::InvalidSignature;
    }

    // Verify RSA-SHA256 signature
    if (!verifySignature(getPublicKeyPem(), licenseData, signatureBytes)) {
        SUSI_LOG("License has an invalid signature");
        return LicenseStatus::InvalidSignature;
    }

    // Parse the verified payload
    json payload;
    try {
        payload = json::parse(licenseData);
    } catch (const json::exception& e) {
        SUSI_LOG("Failed to parse license payload: %s", e.what());
        return LicenseStatus::Error;
    }

    // Check expiry
    if (isExpired(payload)) {
        SUSI_LOG("License expired: %s", payload.value("expires", std::string("unknown")).c_str());
        return LicenseStatus::Expired;
    }

    // Check machine code
    std::string codeToCheck = activationCode;
    if (payload.contains("machine_codes") && payload.at("machine_codes").is_array()) {
        const auto& codes = payload.at("machine_codes");
        if (!codes.empty()) {
            if(codeToCheck.empty()){
                codeToCheck = getMachineCode();
            }
            bool found = false;
            for (const auto& code : codes) {
                if (code.is_string() && code.get<std::string>() == codeToCheck) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                SUSI_LOG("License not valid for this machine (code: %s)", codeToCheck.c_str());
                return LicenseStatus::InvalidMachine;
            }
        }
    }

    // Check lease expiry
    bool inGracePeriod = false;
    if (payload.contains("lease_expires") && !payload.at("lease_expires").is_null()) {
        std::string leaseStr = payload.at("lease_expires").get<std::string>();
        time_t leaseExpires = parseIsoTimestamp(leaseStr);
        if (leaseExpires == -1) {
            SUSI_LOG("Could not parse lease_expires: %s", leaseStr.c_str());
            return LicenseStatus::Error;
        }
        m_leaseExpiresEpoch = static_cast<int64_t>(leaseExpires);
        time_t now = time(nullptr);
        time_t graceEnd = leaseExpires + static_cast<time_t>(m_graceHours * 3600);
        if (now > graceEnd) {
            SUSI_LOG("Lease expired (at %s, grace period exhausted)", leaseStr.c_str());
            return LicenseStatus::LeaseExpired;
        }
        if (now > leaseExpires) {
            SUSI_LOG("Lease expired at %s, in grace period - renew soon!", leaseStr.c_str());
            inGracePeriod = true;
        }
    }

    // Check binary signing requirement
    if (payload.value("require_signed_binary", false) && !isBinarySigned()) {
        SUSI_LOG("License requires a signed binary, but this binary is unsigned or tampered");
        return LicenseStatus::UnsignedBinary;
    }

    // Extract information
    if (payload.contains("features") && payload.at("features").is_array()) {
        for (const auto& f : payload.at("features")) {
            if (f.is_string()) {
                m_features.push_back(f.get<std::string>());
            }
        }
    }

    m_product = payload.value("product", std::string("unknown"));
    m_customer = payload.value("customer", std::string("unknown"));
    
    // Log success
    std::string expiresDisplay;
    if (payload.contains("expires") && !payload.at("expires").is_null()) {
        expiresDisplay = payload.at("expires").get<std::string>();
    } else {
        expiresDisplay = "perpetual";
    }

    SUSI_LOG("License valid for '%s' (customer: %s, expires: %s)",
             m_product.c_str(), m_customer.c_str(), expiresDisplay.c_str());

    if (!m_features.empty()) {
        std::string featureList;
        for (size_t i = 0; i < m_features.size(); ++i) {
            if (i > 0) featureList += ", ";
            featureList += m_features[i];
        }
        SUSI_LOG("Licensed features: %s", featureList.c_str());
    }

    return inGracePeriod ? LicenseStatus::ValidGracePeriod : LicenseStatus::Valid;
}

// ---------------------------------------------------------------------------
// License check from file
// ---------------------------------------------------------------------------
SusiClient::LicenseStatus SusiClient::checkLicense(const std::filesystem::path& licensePath)
{
    m_features.clear();
    m_product.clear();
    m_customer.clear();
    m_leaseExpiresEpoch = 0;

    std::ifstream licenseFile(licensePath);
    if (!licenseFile.is_open()) {
        SUSI_LOG("License file not found: %s", licensePath.string().c_str());
        m_isValid = false;
        return LicenseStatus::FileNotFound;
    }

    std::string licenseContents((std::istreambuf_iterator<char>(licenseFile)), std::istreambuf_iterator<char>());
    auto status = verifySignedLicenseJson(licenseContents);
    m_isValid = (status == LicenseStatus::Valid || status == LicenseStatus::ValidGracePeriod);
    return status;
}

// ---------------------------------------------------------------------------
// Online license check
// ---------------------------------------------------------------------------
SusiClient::LicenseStatus SusiClient::checkLicenseAndRefresh(const std::filesystem::path& licensePath, const std::string& licenseKey)
{
    m_features.clear();
    m_product.clear();
    m_customer.clear();
    m_leaseExpiresEpoch = 0;

    if (!m_serverUrl.empty()) {
        std::string url = m_serverUrl;
        if (!url.empty() && url.back() == '/') url.pop_back();
        url += "/activate";

        json body;
        body["license_key"] = licenseKey;
        body["machine_code"] = getMachineCode();
        body["friendly_name"] = getHostname();

        std::string response;
        long httpCode = httpPost(url, body.dump(), response);
        if (httpCode >= 200 && httpCode < 300) {
            auto status = verifySignedLicenseJson(response);
            m_isValid = (status == LicenseStatus::Valid || status == LicenseStatus::ValidGracePeriod);

            if (m_isValid) {
                std::ofstream f(licensePath);
                if (f.is_open()) {
                    f << response;
                }
            }

            return status;
        } else if (httpCode == 403) {
            std::filesystem::remove(licensePath);
            m_isValid = false;

            if (response.find("revoked") != std::string::npos){
                SUSI_LOG("License has been revoked - removing chached file");
                return LicenseStatus::Revoked;
            } else if (response.find("expired") != std::string::npos) {
                SUSI_LOG("License has expired - removing chached file");
                return LicenseStatus::Expired;
            } else if (response.find("Machine limit") != std::string::npos){
                SUSI_LOG("License machine limit exceeded - removing chached file");
                return LicenseStatus::InvalidMachine;
            } else {
                SUSI_LOG("Server rejected license (HTTP 403) - removing cached file");
                return LicenseStatus::Error;
            }
        } else if (httpCode == 404) {
            SUSI_LOG("License not found on server (HTTP 404) - removing cached file");
            std::filesystem::remove(licensePath);
            m_isValid = false;
            return LicenseStatus::InvalidLicenseKey;
        } else {
            SUSI_LOG("Online license refresh failed, falling back to cached file");
        }
    } else {
        SUSI_LOG("No server supplied. Online license check will fail. Falling back to cached file.");
    }

    // Fall back to local file
    std::ifstream licenseFile(licensePath);
    if (!licenseFile.is_open()) {
        SUSI_LOG("Cached license file cannot be found: %s", licensePath.string().c_str());
        m_isValid = false;
        return LicenseStatus::FileNotFound;
    }

    std::string licenseContents((std::istreambuf_iterator<char>(licenseFile)), std::istreambuf_iterator<char>());
    auto status = verifySignedLicenseJson(licenseContents);
    m_isValid = (status == LicenseStatus::Valid || status == LicenseStatus::ValidGracePeriod);
    return status;
}

// ---------------------------------------------------------------------------
// USB hardware token support
// ---------------------------------------------------------------------------

struct UsbDeviceInfo {
    std::string serial;
    std::string mountPath;
    std::string name;
};

#ifdef _WIN32
// UTF-16 (no trailing null) -> UTF-8; matches Linux sysfs serial trimming in spirit.
static std::string wideToUtf8Span(const wchar_t* wstr, size_t wcharCount)
{
    if (!wstr || wcharCount == 0)
        return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, static_cast<int>(wcharCount), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, static_cast<int>(wcharCount), out.data(), needed, nullptr, nullptr);
    return out;
}

static bool win32GetVolumeDiskNumber(HANDLE hVolume, DWORD& outDiskNumber)
{
    alignas(VOLUME_DISK_EXTENTS) BYTE buf[512] = {};
    DWORD br = 0;
    if (!DeviceIoControl(hVolume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buf, sizeof(buf), &br, nullptr))
        return false;
    auto* vde = reinterpret_cast<VOLUME_DISK_EXTENTS*>(buf);
    if (vde->NumberOfDiskExtents < 1)
        return false;
    outDiskNumber = vde->Extents[0].DiskNumber;
    return true;
}

// USB instance serial from PnP (USBSTOR\...\SERIAL&0), aligned with Linux sysfs .../serial.
static std::string win32UsbInstanceSerialForDiskNumber(DWORD diskNumber)
{
    HDEVINFO devs = SetupDiGetClassDevsW(&GUID_DEVINTERFACE_DISK, nullptr, nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devs == INVALID_HANDLE_VALUE)
        return {};

    std::string serialUtf8;
    SP_DEVICE_INTERFACE_DATA ifData = {};
    ifData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD idx = 0; SetupDiEnumDeviceInterfaces(devs, nullptr, &GUID_DEVINTERFACE_DISK, idx, &ifData); ++idx) {
        DWORD required = 0;
        SetupDiGetDeviceInterfaceDetailW(devs, &ifData, nullptr, 0, &required, nullptr);
        if (required < sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W))
            continue;

        std::vector<BYTE> detailBuf(required);
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_W*>(detailBuf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        SP_DEVINFO_DATA devInfo = {};
        devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
        if (!SetupDiGetDeviceInterfaceDetailW(devs, &ifData, detail, required, nullptr, &devInfo))
            continue;

        HANDLE hDisk = CreateFileW(detail->DevicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDisk == INVALID_HANDLE_VALUE)
            continue;

        STORAGE_DEVICE_NUMBER sdn = {};
        DWORD br = 0;
        const BOOL gotNum = DeviceIoControl(hDisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0,
            &sdn, sizeof(sdn), &br, nullptr);
        CloseHandle(hDisk);
        if (!gotNum || sdn.DeviceNumber != diskNumber)
            continue;

        DEVINST devInst = devInfo.DevInst;
        for (int depth = 0; depth < 32 && devInst != 0; ++depth) {
            wchar_t instId[512];
            if (CM_Get_Device_IDW(devInst, instId, static_cast<ULONG>(sizeof(instId) / sizeof(instId[0])), 0) != CR_SUCCESS)
                break;

            std::wstring id(instId);
            static const wchar_t kUsbStor[] = L"USBSTOR\\";
            constexpr size_t kUsbStorLen = sizeof(kUsbStor) / sizeof(kUsbStor[0]) - 1;
            if (id.size() >= kUsbStorLen && _wcsnicmp(id.c_str(), kUsbStor, kUsbStorLen) == 0) {
                const size_t lastSlash = id.rfind(L'\\');
                if (lastSlash != std::wstring::npos && lastSlash + 1 < id.size()) {
                    std::wstring tail = id.substr(lastSlash + 1);
                    std::wstring ser;
                    const size_t amp = tail.rfind(L'&');
                    if (amp != std::wstring::npos && amp > 0)
                        ser = tail.substr(0, amp);
                    else
                        ser = tail;
                    while (!ser.empty() && (ser.back() == L' ' || ser.back() == L'\t'))
                        ser.pop_back();
                    serialUtf8 = wideToUtf8Span(ser.data(), ser.size());
                }
                break;
            }

            DEVINST parent = 0;
            if (CM_Get_Parent(&parent, devInst, 0) != CR_SUCCESS)
                break;
            devInst = parent;
        }
        break;
    }

    SetupDiDestroyDeviceInfoList(devs);
    return serialUtf8;
}

static std::vector<UsbDeviceInfo> enumerateUsbDevices()
{
    std::vector<UsbDeviceInfo> devices;

    wchar_t driveStrings[512];
    DWORD len = GetLogicalDriveStringsW(sizeof(driveStrings) / sizeof(wchar_t), driveStrings);
    if (len == 0) return devices;

    for (wchar_t* drive = driveStrings; *drive != L'\0'; drive += wcslen(drive) + 1) {
        if (GetDriveTypeW(drive) != DRIVE_REMOVABLE) continue;

        wchar_t devicePath[16];
        swprintf_s(devicePath, L"\\\\.\\%c:", drive[0]);

        HANDLE hVolume = CreateFileW(
            devicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVolume == INVALID_HANDLE_VALUE) continue;

        DWORD diskNumber = 0;
        if (!win32GetVolumeDiskNumber(hVolume, diskNumber)) {
            CloseHandle(hVolume);
            continue;
        }
        CloseHandle(hVolume);

        std::string serial = win32UsbInstanceSerialForDiskNumber(diskNumber);
        if (serial.empty()) continue;

        wchar_t volumeName[MAX_PATH + 1] = {};
        GetVolumeInformationW(drive, volumeName, MAX_PATH + 1,
            nullptr, nullptr, nullptr, nullptr, 0);

        int needed = WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, nullptr, 0, nullptr, nullptr);
        std::string label(needed > 0 ? needed - 1 : 0, '\0');
        if (needed > 0)
            WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, label.data(), needed, nullptr, nullptr);

        needed = WideCharToMultiByte(CP_UTF8, 0, drive, -1, nullptr, 0, nullptr, nullptr);
        std::string mountPath(needed > 0 ? needed - 1 : 0, '\0');
        if (needed > 0)
            WideCharToMultiByte(CP_UTF8, 0, drive, -1, mountPath.data(), needed, nullptr, nullptr);

        devices.push_back({serial, mountPath, label.empty() ? "USB Drive" : label});
    }
    return devices;
}
#elif defined(__APPLE__)
static std::string cfStringToStd(CFStringRef ref)
{
    if (!ref) return {};
    char buf[512];
    if (CFStringGetCString(ref, buf, sizeof(buf), kCFStringEncodingUTF8))
        return buf;
    return {};
}

// Walk up the IOKit service plane to find "USB Serial Number" (iSerialNumber descriptor).
// Matches the serial extracted from USBSTOR device ID on Windows.
static std::string ioUsbSerialForService(io_service_t service)
{
    std::string serial;
    io_service_t cur = service;
    IOObjectRetain(cur);
    for (int depth = 0; depth < 12 && cur != IO_OBJECT_NULL; ++depth) {
        CFStringRef prop = (CFStringRef)IORegistryEntryCreateCFProperty(
            cur, CFSTR("USB Serial Number"), kCFAllocatorDefault, 0);
        if (prop) {
            serial = cfStringToStd(prop);
            CFRelease(prop);
            IOObjectRelease(cur);
            break;
        }
        io_service_t parent = IO_OBJECT_NULL;
        kern_return_t kr = IORegistryEntryGetParentEntry(cur, kIOServicePlane, &parent);
        IOObjectRelease(cur);
        if (kr != KERN_SUCCESS) break;
        cur = parent;
    }
    return serial;
}

static std::vector<UsbDeviceInfo> enumerateUsbDevices()
{
    std::vector<UsbDeviceInfo> devices;

    // Build map: /dev/diskNsM -> mount point
    std::unordered_map<std::string, std::string> mountMap;
    int fsCount = getfsstat(nullptr, 0, MNT_NOWAIT);
    if (fsCount > 0) {
        std::vector<struct statfs> stats(static_cast<size_t>(fsCount));
        fsCount = getfsstat(stats.data(), static_cast<int>(fsCount * sizeof(struct statfs)), MNT_NOWAIT);
        for (int i = 0; i < fsCount; ++i)
            mountMap[stats[i].f_mntfromname] = stats[i].f_mntonname;
    }

    // Enumerate whole removable IOMedia entries (one per USB disk, not per partition)
    CFMutableDictionaryRef matching = IOServiceMatching("IOMedia");
    CFDictionarySetValue(matching, CFSTR("Removable"), kCFBooleanTrue);
    CFDictionarySetValue(matching, CFSTR("Whole"), kCFBooleanTrue);

    io_iterator_t iter = IO_OBJECT_NULL;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iter) != KERN_SUCCESS)
        return devices;

    io_service_t media;
    while ((media = IOIteratorNext(iter)) != IO_OBJECT_NULL) {
        CFStringRef bsdRef = (CFStringRef)IORegistryEntryCreateCFProperty(
            media, CFSTR("BSD Name"), kCFAllocatorDefault, 0);
        std::string bsdName = cfStringToStd(bsdRef);
        if (bsdRef) CFRelease(bsdRef);

        if (bsdName.empty()) { IOObjectRelease(media); continue; }

        std::string serial = ioUsbSerialForService(media);
        if (serial.empty()) { IOObjectRelease(media); continue; }

        // Find mount point: try partitions diskNs1..s9, then whole disk
        std::string mountPoint;
        for (int p = 1; p <= 9 && mountPoint.empty(); ++p) {
            auto it = mountMap.find("/dev/" + bsdName + "s" + std::to_string(p));
            if (it != mountMap.end()) mountPoint = it->second;
        }
        if (mountPoint.empty()) {
            auto it = mountMap.find("/dev/" + bsdName);
            if (it != mountMap.end()) mountPoint = it->second;
        }
        if (mountPoint.empty()) { IOObjectRelease(media); continue; }

        // Volume name = last path component of mount point (e.g. /Volumes/MY_DRIVE -> MY_DRIVE)
        std::string name = mountPoint;
        auto slash = name.rfind('/');
        if (slash != std::string::npos) name = name.substr(slash + 1);
        if (name.empty()) name = "USB Drive";

        devices.push_back({serial, mountPoint, name});
        IOObjectRelease(media);
    }
    IOObjectRelease(iter);
    return devices;
}
#elif defined(__linux__)
static std::vector<UsbDeviceInfo> enumerateUsbDevices()
{
    std::vector<UsbDeviceInfo> devices;

    // Parse /proc/mounts
    std::unordered_map<std::string, std::string> mounts;
    std::ifstream mountsFile("/proc/mounts");
    std::string line;
    while (std::getline(mountsFile, line)) {
        std::istringstream iss(line);
        std::string dev, mount;
        iss >> dev >> mount;
        mounts[dev] = mount;
    }

    DIR* blockDir = opendir("/sys/block");
    if (!blockDir) return devices;

    struct dirent* entry;
    while ((entry = readdir(blockDir)) != nullptr) {
        std::string blockName = entry->d_name;
        if (blockName.substr(0, 2) != "sd") continue;

        // Check removable
        std::string remPath = "/sys/block/" + blockName + "/removable";
        std::ifstream remFile(remPath);
        std::string remVal;
        if (!remFile.is_open() || !std::getline(remFile, remVal) || remVal != "1") continue;

        // Walk sysfs for USB serial
        std::string devLink = "/sys/block/" + blockName + "/device";
        char realPath[PATH_MAX];
        if (!realpath(devLink.c_str(), realPath)) continue;

        std::string serial;
        std::string cur(realPath);
        for (int i = 0; i < 6; ++i) {
            std::string serialFile = cur + "/serial";
            std::ifstream sf(serialFile);
            if (sf.is_open()) {
                std::getline(sf, serial);
                while (!serial.empty() && isspace(serial.back())) serial.pop_back();
                if (!serial.empty()) break;
            }
            auto pos = cur.rfind('/');
            if (pos == std::string::npos) break;
            cur = cur.substr(0, pos);
        }
        if (serial.empty()) continue;

        // Find mount point
        std::string devPath = "/dev/" + blockName;
        std::string mountPoint;
        for (int p = 1; p <= 9; ++p) {
            auto it = mounts.find(devPath + std::to_string(p));
            if (it != mounts.end()) { mountPoint = it->second; break; }
        }
        if (mountPoint.empty()) {
            auto it = mounts.find(devPath);
            if (it != mounts.end()) mountPoint = it->second;
        }
        if (mountPoint.empty()) continue;

        std::string modelPath = "/sys/block/" + blockName + "/device/model";
        std::string model = "USB Drive";
        std::ifstream mf(modelPath);
        if (mf.is_open()) {
            std::getline(mf, model);
            while (!model.empty() && isspace(model.back())) model.pop_back();
        }

        devices.push_back({serial, mountPoint, model});
    }
    closedir(blockDir);
    return devices;
}
#else
static std::vector<UsbDeviceInfo> enumerateUsbDevices()
{
    return {};
}
#endif

// HKDF-SHA256 (extract-then-expand, compatible with OpenSSL 1.1.1+)
static bool hkdfSha256(
    const unsigned char* salt, size_t saltLen,
    const unsigned char* ikm, size_t ikmLen,
    const unsigned char* info, size_t infoLen,
    unsigned char* okm, size_t okmLen)
{
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    unsigned char prk[32];
    unsigned int prkLen = 0;
    if (!HMAC(EVP_sha256(), salt, static_cast<int>(saltLen),
              ikm, ikmLen, prk, &prkLen))
        return false;

    // Expand
    unsigned char t[32] = {};
    size_t tLen = 0;
    size_t offset = 0;
    unsigned char counter = 1;

    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    while (offset < okmLen) {
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0),
            OSSL_PARAM_construct_end()
        };
        EVP_MAC_init(ctx, prk, prkLen, params);
        if (tLen > 0) EVP_MAC_update(ctx, t, tLen);
        EVP_MAC_update(ctx, info, infoLen);
        EVP_MAC_update(ctx, &counter, 1);
        size_t len = sizeof(t);
        EVP_MAC_final(ctx, t, &len, len);
        EVP_MAC_CTX_free(ctx);
        tLen = len;

        size_t copyLen = (std::min)(tLen, okmLen - offset);
        memcpy(okm + offset, t, copyLen);
        offset += copyLen;
        counter++;
    }
    EVP_MAC_free(mac);
    return true;
}

static bool deriveTokenKey(const std::string& serial, unsigned char keyOut[32])
{
    const char* salt = "susi-token-v1";
    const char* info = "license-encryption";
    return hkdfSha256(
        reinterpret_cast<const unsigned char*>(salt), strlen(salt),
        reinterpret_cast<const unsigned char*>(serial.data()), serial.size(),
        reinterpret_cast<const unsigned char*>(info), strlen(info),
        keyOut, 32);
}

static std::string decryptToken(const std::vector<unsigned char>& blob, const std::string& serial)
{
    const size_t NONCE_SIZE = 12;
    const size_t TAG_SIZE = 16;

    if (blob.size() < NONCE_SIZE + TAG_SIZE) return {};

    unsigned char key[32];
    if (!deriveTokenKey(serial, key)) return {};

    const unsigned char* nonce = blob.data();
    size_t ctLen = blob.size() - NONCE_SIZE - TAG_SIZE;
    const unsigned char* ciphertext = blob.data() + NONCE_SIZE;
    const unsigned char* tag = blob.data() + NONCE_SIZE + ctLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<unsigned char> out(ctLen + 16);
    int len = 0;
    std::string plaintext;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_SIZE, nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext, static_cast<int>(ctLen)) == 1) {
        int ptLen = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                const_cast<unsigned char*>(tag)) == 1 &&
            EVP_DecryptFinal_ex(ctx, out.data() + ptLen, &len) == 1) {
            ptLen += len;
            plaintext.assign(reinterpret_cast<char*>(out.data()), ptLen);
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

SusiClient::LicenseStatus SusiClient::checkLicenseToken()
{
    m_features.clear();
    m_product.clear();
    m_customer.clear();
    m_leaseExpiresEpoch = 0;

    auto devices = enumerateUsbDevices();
    if (devices.empty()) {
        SUSI_LOG("No USB mass storage devices found");
        m_isValid = false;
        return LicenseStatus::TokenNotFound;
    }

    for (const auto& dev : devices) {
        std::string tokenPath = dev.mountPath;
        if (!tokenPath.empty() && tokenPath.back() != '/' && tokenPath.back() != '\\') {
#ifdef _WIN32
            tokenPath += "\\";
#else
            tokenPath += "/";
#endif
        }
        tokenPath += ".susi";
#ifdef _WIN32
        tokenPath += "\\license.bin";
#else
        tokenPath += "/license.bin";
#endif

        std::ifstream f(tokenPath, std::ios::binary);
        if (!f.is_open()) continue;

        std::vector<unsigned char> blob(
            (std::istreambuf_iterator<char>(f)),
            std::istreambuf_iterator<char>());
        f.close();

        std::string decrypted = decryptToken(blob, dev.serial);
        if (decrypted.empty()) continue;

        std::string usbActivationCode = "usb:" + dev.serial;

        LicenseStatus status = verifySignedLicenseJson(decrypted, usbActivationCode);
        if (status != LicenseStatus::Valid && status != LicenseStatus::ValidGracePeriod) {
            continue;
        }

        SUSI_LOG("License token: device '%s' (serial: %s)", dev.name.c_str(), dev.serial.c_str());
        m_isValid = true;
        return status;
    }

    SUSI_LOG("No valid USB license token found");
    m_isValid = false;
    return LicenseStatus::TokenNotFound;
}

bool SusiClient::hasFeature(const std::string& feature) const
{
    return std::find(m_features.begin(), m_features.end(), feature) != m_features.end();
}

bool SusiClient::isLeaseValid() const
{
    if (m_leaseExpiresEpoch == 0) return true; // no lease enforcement
    return time(nullptr) < static_cast<time_t>(m_leaseExpiresEpoch);
}

bool SusiClient::isInGracePeriod() const
{
    if (m_leaseExpiresEpoch == 0) return false;
    time_t now = time(nullptr);
    time_t expires = static_cast<time_t>(m_leaseExpiresEpoch);
    time_t graceEnd = expires + static_cast<time_t>(m_graceHours * 3600);
    return now >= expires && now < graceEnd;
}

bool SusiClient::isLeaseExpired() const
{
    if (m_leaseExpiresEpoch == 0) return false;
    time_t now = time(nullptr);
    time_t graceEnd = static_cast<time_t>(m_leaseExpiresEpoch) + static_cast<time_t>(m_graceHours * 3600);
    return now >= graceEnd;
}
