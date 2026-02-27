#ifndef SUSI_H
#define SUSI_H

#include <string>
#include <vector>

class SusiClient {
    std::vector<std::string> m_features;

public:
    bool checkLicense(std::string jsonLicenseInfo);

    const std::vector<std::string>& features() const { return m_features; }

    bool hasFeature(const std::string& feature) const;
};

#endif
