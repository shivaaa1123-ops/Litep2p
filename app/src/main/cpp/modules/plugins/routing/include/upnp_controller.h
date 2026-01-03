#pragma once

#include "nat_traversal.h"
#include <string>
#include <mutex>

class UpnpController : public IUpnpController {
public:
    UpnpController();
    ~UpnpController() override;

    bool isAvailable() const override;
    bool addPortMapping(uint16_t internal_port,
                        uint16_t external_port,
                        const std::string& protocol,
                        int lease_seconds,
                        std::string& mapping_id) override;
    bool removePortMapping(const std::string& mapping_id) override;

private:
    bool executeCommand(const std::string& cmd, std::string& output) const;
    bool m_available;
};
