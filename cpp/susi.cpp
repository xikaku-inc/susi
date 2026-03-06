#include "susi.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <openssl/hmac.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winioctl.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <climits>
#include <dirent.h>
#include <unistd.h>
#include <unordered_map>
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
// SusiClient::checkLicense
// ---------------------------------------------------------------------------

// Default embedded public key.
// Replace this with your actual public key generated via: susi-admin keygen
// When empty, license check is skipped (development mode).
static const char* DEFAULT_PUBLIC_KEY = "";

static std::string getPublicKeyPem()
{
    std::string key(DEFAULT_PUBLIC_KEY);
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

bool SusiClient::checkLicense(std::string jsonLicenseInfo)
{
    m_features.clear();
    m_leaseExpiresEpoch = 0;

    json info;
    try {
        info = json::parse(jsonLicenseInfo);
    } catch (const json::exception& e) {
        SUSI_LOG("Could not parse license info JSON: %s", e.what());
        return false;
    }

    std::string licenseFilePath = "license.json";
    if (info.contains("LicenseFile") && info.at("LicenseFile").is_string()) {
        licenseFilePath = info.at("LicenseFile").get<std::string>();
    }

    // Load signed license file
    std::ifstream licenseFile(licenseFilePath);
    if (!licenseFile.is_open()) {
        SUSI_LOG("License file not found: %s", licenseFilePath.c_str());
        return false;
    }

    json signedLicense;
    try {
        signedLicense = json::parse(licenseFile);
    } catch (const json::exception& e) {
        SUSI_LOG("Invalid license file format: %s", e.what());
        return false;
    }

    if (!signedLicense.contains("license_data") || !signedLicense.contains("signature")) {
        SUSI_LOG("License file missing required fields (license_data, signature)");
        return false;
    }

    std::string licenseData = signedLicense.at("license_data").get<std::string>();
    std::string signatureB64 = signedLicense.at("signature").get<std::string>();

    // Decode signature from base64
    auto signatureBytes = base64Decode(signatureB64);
    if (signatureBytes.empty()) {
        SUSI_LOG("Failed to decode license signature");
        return false;
    }

    // Verify RSA-SHA256 signature
    if (!verifySignature(getPublicKeyPem(), licenseData, signatureBytes)) {
        SUSI_LOG("License file has an invalid signature");
        return false;
    }

    // Parse the verified payload
    json payload;
    try {
        payload = json::parse(licenseData);
    } catch (const json::exception& e) {
        SUSI_LOG("Failed to parse license payload: %s", e.what());
        return false;
    }

    // Check expiry
    if (isExpired(payload)) {
        std::string expiresStr = payload.value("expires", std::string("unknown"));
        SUSI_LOG("License expired: %s", expiresStr.c_str());
        return false;
    }

    // Check machine code
    if (payload.contains("machine_codes") && payload.at("machine_codes").is_array()) {
        auto& codes = payload.at("machine_codes");
        if (!codes.empty()) {
            std::string localCode = getMachineCode();
            bool found = false;
            for (const auto& code : codes) {
                if (code.is_string() && code.get<std::string>() == localCode) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                SUSI_LOG("License not valid for this machine (code: %s)", localCode.c_str());
                return false;
            }
        }
    }

    // Check lease expiry
    if (payload.contains("lease_expires") && !payload.at("lease_expires").is_null()) {
        std::string leaseStr = payload.at("lease_expires").get<std::string>();
        time_t leaseExpires = parseIsoTimestamp(leaseStr);
        if (leaseExpires == -1) {
            SUSI_LOG("Could not parse lease_expires: %s", leaseStr.c_str());
            return false;
        }
        m_leaseExpiresEpoch = static_cast<int64_t>(leaseExpires);
        time_t now = time(nullptr);
        time_t graceEnd = leaseExpires + static_cast<time_t>(m_graceHours * 3600);
        if (now > graceEnd) {
            SUSI_LOG("Lease expired (at %s, grace period exhausted)", leaseStr.c_str());
            return false;
        }
        if (now > leaseExpires) {
            SUSI_LOG("Lease expired at %s, in grace period — renew soon!", leaseStr.c_str());
        }
    }

    // Extract features
    if (payload.contains("features") && payload.at("features").is_array()) {
        for (const auto& f : payload.at("features")) {
            if (f.is_string()) {
                m_features.push_back(f.get<std::string>());
            }
        }
    }

    // Log success
    std::string product = payload.value("product", std::string("unknown"));
    std::string customer = payload.value("customer", std::string("unknown"));
    std::string expiresDisplay;
    if (payload.contains("expires") && !payload.at("expires").is_null()) {
        expiresDisplay = payload.at("expires").get<std::string>();
    } else {
        expiresDisplay = "perpetual";
    }

    SUSI_LOG("License valid for '%s' (customer: %s, expires: %s)",
             product.c_str(), customer.c_str(), expiresDisplay.c_str());

    if (!m_features.empty()) {
        std::string featureList;
        for (size_t i = 0; i < m_features.size(); ++i) {
            if (i > 0) featureList += ", ";
            featureList += m_features[i];
        }
        SUSI_LOG("Licensed features: %s", featureList.c_str());
    }

    return true;
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

        HANDLE hDevice = CreateFileW(
            devicePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDevice == INVALID_HANDLE_VALUE) continue;

        STORAGE_PROPERTY_QUERY query = {};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        BYTE buffer[1024] = {};
        DWORD returned = 0;
        BOOL ok = DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query), buffer, sizeof(buffer), &returned, nullptr);
        CloseHandle(hDevice);
        if (!ok) continue;

        auto* desc = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);
        if (desc->SerialNumberOffset == 0 || desc->SerialNumberOffset >= sizeof(buffer)) continue;

        std::string serial(reinterpret_cast<char*>(buffer + desc->SerialNumberOffset));
        while (!serial.empty() && (serial.back() == ' ' || serial.back() == '\0'))
            serial.pop_back();
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
#else
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

    while (offset < okmLen) {
        HMAC_CTX* ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk, static_cast<int>(prkLen), EVP_sha256(), nullptr);
        if (tLen > 0) HMAC_Update(ctx, t, tLen);
        HMAC_Update(ctx, info, infoLen);
        HMAC_Update(ctx, &counter, 1);
        unsigned int len = 0;
        HMAC_Final(ctx, t, &len);
        HMAC_CTX_free(ctx);
        tLen = len;

        size_t copyLen = (std::min)(tLen, okmLen - offset);
        memcpy(okm + offset, t, copyLen);
        offset += copyLen;
        counter++;
    }
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

bool SusiClient::checkLicenseToken()
{
    m_features.clear();
    m_leaseExpiresEpoch = 0;

    auto devices = enumerateUsbDevices();
    if (devices.empty()) {
        SUSI_LOG("No USB mass storage devices found");
        return false;
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

        json signedLicense;
        try {
            signedLicense = json::parse(decrypted);
        } catch (...) {
            continue;
        }

        if (!signedLicense.contains("license_data") || !signedLicense.contains("signature"))
            continue;

        std::string licenseData = signedLicense.at("license_data").get<std::string>();
        std::string signatureB64 = signedLicense.at("signature").get<std::string>();

        auto signatureBytes = base64Decode(signatureB64);
        if (signatureBytes.empty()) continue;

        if (!verifySignature(getPublicKeyPem(), licenseData, signatureBytes))
            continue;

        json payload;
        try {
            payload = json::parse(licenseData);
        } catch (...) {
            continue;
        }

        if (isExpired(payload)) continue;

        // Token-bound: no machine_codes check (machine_codes is empty)

        // Extract features
        if (payload.contains("features") && payload.at("features").is_array()) {
            for (const auto& feat : payload.at("features")) {
                if (feat.is_string())
                    m_features.push_back(feat.get<std::string>());
            }
        }

        std::string product = payload.value("product", std::string("unknown"));
        std::string customer = payload.value("customer", std::string("unknown"));
        SUSI_LOG("License valid via USB token '%s' (serial: %s, product: %s, customer: %s)",
                 dev.name.c_str(), dev.serial.c_str(), product.c_str(), customer.c_str());
        return true;
    }

    SUSI_LOG("No valid USB license token found");
    return false;
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
