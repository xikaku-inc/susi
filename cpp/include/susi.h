#ifndef SUSI_H
#define SUSI_H

#include <cstdint>
#include <string>
#include <vector>

class SusiClient {
    std::vector<std::string> m_features;
    int64_t m_leaseExpiresEpoch = 0; // 0 = no lease
    int64_t m_graceHours = 24;

public:
    bool checkLicense(std::string jsonLicenseInfo);
    bool checkLicenseToken();

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
