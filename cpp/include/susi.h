#ifndef SUSI_H
#define SUSI_H

#include <cstdint>
#include <string>
#include <vector>

class SusiClient {
    std::vector<std::string> m_features;
    int64_t m_leaseExpiresEpoch = 0; // 0 = no lease
    int64_t m_graceHours = 24;
    std::string m_publicKey;
    std::string m_serverUrl;

public:
    SusiClient(std::string publicKey) : m_publicKey(std::move(publicKey)) {}
    /// Create a client with an activation server URL (e.g. "https://license.example.com/api/v1").
    SusiClient(std::string publicKey, std::string serverUrl)
        : m_publicKey(std::move(publicKey)), m_serverUrl(std::move(serverUrl)) {}

    std::string getPublicKeyPem();

    /// Checks if license is signed correctly and still valid.
    /// If no activation code is given to check against, the local machine code is used.
    bool verifySignedLicenseJson(std::string signedLicenseStr, std::string activationCode = "");
    bool checkLicense(std::string jsonLicenseInfo);
    bool checkLicenseToken();
    /// Contact the activation server to refresh the lease, then verify the license.
    /// Falls back to the cached local file if the server is unreachable.
    bool checkLicenseAndRefresh(const std::string& licensePath, const std::string& licenseKey);

    const std::vector<std::string>& features() const { return m_features; }

    bool hasFeature(const std::string& feature) const;

    /// Returns true if there is an active lease that has not yet expired.
    bool isLeaseValid() const;

    /// Returns true if the lease is expired but within the grace period.
    bool isInGracePeriod() const;

    /// Returns true if the lease is expired past the grace period.
    bool isLeaseExpired() const;

    void setGraceHours(int64_t hours) { m_graceHours = hours; }
};

#endif
