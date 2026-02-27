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

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <dirent.h>
#include <unistd.h>
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
static bool isExpired(const json& payload)
{
    if (!payload.contains("expires") || payload.at("expires").is_null()) {
        return false; // perpetual
    }

    std::string expiresStr = payload.at("expires").get<std::string>();

    std::tm tm = {};
#ifdef _WIN32
    int parsed = sscanf_s(expiresStr.c_str(), "%d-%d-%dT%d:%d:%d",
#else
    int parsed = sscanf(expiresStr.c_str(), "%d-%d-%dT%d:%d:%d",
#endif
                        &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                        &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    if (parsed >= 6) {
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;

#ifdef _WIN32
        time_t expires = _mkgmtime(&tm);
#else
        time_t expires = timegm(&tm);
#endif
        time_t now = time(nullptr);
        return now > expires;
    }

    SUSI_LOG("Could not parse expires date: %s", expiresStr.c_str());
    return true; // fail safe: treat unparseable as expired
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

    if (std::string(DEFAULT_PUBLIC_KEY).empty()) {
        SUSI_LOG("No public key compiled in, skipping license check");
        return true;
    }

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

bool SusiClient::hasFeature(const std::string& feature) const
{
    return std::find(m_features.begin(), m_features.end(), feature) != m_features.end();
}
