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
        /// The license requires a signed binary, but this binary is unsigned or tampered.
        UnsignedBinary,
        /// This machine was removed from the license by an administrator. Unlike Revoked,
        /// only this machine slot is affected. Re-activation is blocked for the tombstone window.
        Deactivated,
        /// No cached license exists, so this machine has never been activated (or was deactivated).
        NotActivated,
        TokenNotFound,
        FileNotFound,
        Error,
    };

    struct UsbDevice {
        std::string serial;
        std::string mountPath;
        std::string name;
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

public:
    SusiClient(std::string publicKey) : m_publicKey(std::move(publicKey)) {}
    /// Create a client with an activation server URL (e.g. "https://license.example.com/api/v1").
    SusiClient(std::string publicKey, std::string serverUrl)
        : m_publicKey(std::move(publicKey)), m_serverUrl(std::move(serverUrl)) {}

    std::string getPublicKeyPem();

    /// Verifies the license file at the given path.
    LicenseStatus verifyFile(const std::filesystem::path& licensePath);
    /// Checks for a license token on attached USB devices, and verifies it if found.
    LicenseStatus verifyToken();
    /// Verifies the tokens on the given USB devices. A readable but invalid token reports its
    /// own status (e.g. Expired), a token that can't be decrypted reports Error, and
    /// TokenNotFound means none of the devices carries a token.
    LicenseStatus verifyTokenOn(const std::vector<UsbDevice>& devices);
    /// Activates this machine on the license server (claims a machine slot), stores the
    /// signed license at the given path and verifies it. Call this when the user explicitly
    /// activates. An empty friendly name falls back to the hostname.
    LicenseStatus activate(const std::filesystem::path& licensePath, const std::string& licenseKey,
        const std::string& friendlyName = "");
    /// Renews the lease of an already activated machine via the server, stores the refreshed
    /// license and verifies it. Never activates: returns NotActivated if no cached license exists,
    /// and Deactivated (removing the cache) if the machine was removed from the license.
    /// Falls back to the cached license if the server is unreachable.
    LicenseStatus verifyAndRefresh(const std::filesystem::path& licensePath, const std::string& licenseKey);

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
private:
    /// Verifies the signature of the signed license JSON string and returns the license status.
    /// If activation code is not provided, the local machine code is used.
    LicenseStatus verifySignedLicenseJson(const std::string& signedLicenseStr, const std::string& activationCode = "");
    /// Verifies a signed license received from the server and stores it at the given path if valid.
    LicenseStatus storeServerLicense(const std::filesystem::path& licensePath, const std::string& signedLicenseStr);
};

#endif
