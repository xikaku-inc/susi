#ifndef SUSI_H
#define SUSI_H

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

class SusiClient {
public:
    enum class LicenseStatus {
        Valid,
        ValidGracePeriod,
        Expired,
        LeaseExpired,
        InvalidMachine,
        InvalidSignature,
        InvalidLicenseKey,
        Revoked,
        TokenNotFound,
        FileNotFound,
        Error,
    };
    enum class LicenseMethod {
        File,
        Token,
        Server
    };
private:
    bool m_isValid = false;
    std::vector<std::string> m_features;
    std::string m_product;
    std::string m_customer;
    int64_t m_leaseExpiresEpoch = 0; // 0 = no lease
    int64_t m_graceHours = 24;
    std::string m_publicKey;
    std::string m_serverUrl;
    std::vector<LicenseMethod> m_allowedLicenseMethods;
public:
    SusiClient(std::string publicKey) : m_publicKey(std::move(publicKey)) {
        m_allowedLicenseMethods = { LicenseMethod::Token, LicenseMethod::File };
    }
    /// Create a client with an activation server URL (e.g. "https://license.example.com/api/v1").
    SusiClient(std::string publicKey, std::string serverUrl)
        : m_publicKey(std::move(publicKey)), m_serverUrl(std::move(serverUrl)) {
        m_allowedLicenseMethods = { LicenseMethod::Server, LicenseMethod::Token, LicenseMethod::File };
    }
    /// Create a client from a properties file
    SusiClient(std::string publicKey, std::filesystem::path propertiesPath);

    std::string getPublicKeyPem();

    /// Checks the license file at the given path.
    LicenseStatus checkLicense(const std::filesystem::path& licensePath);
    /// Checks for a license token on attached USB devices, and verifies it if found.
    LicenseStatus checkLicenseToken();
    /// Contact the activation server to refresh the lease, then verify the license.
    /// Falls back to the cached local file if the server is unreachable.
    LicenseStatus checkLicenseAndRefresh(const std::filesystem::path& licenseCachePath, const std::string& licenseKey, const std::string& friendlyName = "");

    bool isValid() const { return m_isValid; }

    const std::vector<std::string>& features() const { return m_features; }

    bool hasFeature(const std::string& feature) const;

    const std::string& product() const { return m_product; }
    
    const std::string& customer() const { return m_customer; }

    /// Returns true if there is an active lease that has not yet expired.
    bool isLeaseValid() const;

    /// Returns true if the lease is expired but within the grace period.
    bool isInGracePeriod() const;

    /// Returns true if the lease is expired past the grace period.
    bool isLeaseExpired() const;

    void setGraceHours(int64_t hours) { m_graceHours = hours; }

    const std::vector<LicenseMethod>& allowedLicenseMethods() const { return m_allowedLicenseMethods; }
private:
    /// Verifies the signature of the signed license JSON string and returns the license status.
    /// If activation code is not provided, the local machine code is used.
    LicenseStatus verifySignedLicenseJson(const std::string& signedLicenseStr, const std::string& activationCode = "");
};

#endif
