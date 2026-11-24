#pragma once

#include <windows.h>

#include <string>
#include <vector>

#include "identity.h"

struct NetAdapter {
    std::wstring guid;        // NetCfgInstanceId, {XXXXXXXX-...}
    std::wstring description; // friendly driver description
    std::wstring instanceId;  // PCI\VEN_... (empty for root-enumerated)
    std::wstring driverKey;   // Class\{4d36e972...}\NNNN
    bool supportsNetworkAddress = false;
};

class NetworkSpoofer {
public:
    // Present, physical-ish adapters only.
    static std::vector<NetAdapter> Enumerate();

    // Writes NetworkAddress for every enumerated adapter, using (and filling)
    // the MAC table stored in the identity. Returns the number written.
    static bool Apply(Identity& identity, bool dryRun, size_t& written, std::wstring& error);

    // Clears NetworkAddress from every adapter in the profile.
    static bool Restore(const Identity& identity, bool dryRun, std::wstring& error);

    // Cycles the NDIS miniport so the new address is read by the driver.
    static bool RestartAdapters(const std::vector<std::wstring>& guids, std::wstring& error);

    // Live permanent/current address as reported by the hardware key.
    static std::wstring ReadAssignedMac(const std::wstring& guid);
};
