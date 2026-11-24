#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

struct MacAssignment {
    std::wstring adapterGuid;
    std::string mac; // 12 uppercase hex characters, no separators
    std::wstring description;
};

struct Identity {
    uint64_t seed = 0;
    uint64_t created = 0;

    std::string machineGuid;
    std::string productId;
    uint32_t installDate = 0;
    std::string hwProfileGuid;
    std::string sqmMachineId;
    std::string computerName;
    std::string susClientId;
    std::string computerHardwareId;

    std::string systemUuid;
    std::string systemSerial;
    std::string baseboardSerial;
    std::string chassisSerial;

    std::string biosVendor;
    std::string biosVersion;
    std::string biosReleaseDate;

    std::string systemManufacturer;
    std::string systemProductName;
    std::string systemVersion;
    std::string systemFamily;
    std::string systemSku;

    std::string baseboardManufacturer;
    std::string baseboardProduct;
    std::string baseboardVersion;

    std::string chassisManufacturer;
    std::string chassisVersion;
    std::string processorSerial;

    std::array<std::string, 32> diskSerials{};
    std::array<std::string, 26> volumeSerials{};
    std::array<std::string, 8> memorySerials{};

    std::vector<MacAssignment> adapters;

    const MacAssignment* FindAdapter(const std::wstring& guid) const;
};

Identity GenerateIdentity(uint64_t seed);
bool SaveIdentity(const std::wstring& path, const Identity& identity, std::wstring& error);
bool LoadIdentity(const std::wstring& path, Identity& identity, std::wstring& error);

// Finds the adapter in the profile or appends a freshly generated MAC for it.
MacAssignment& EnsureAdapterMac(Identity& identity, const std::wstring& guid,
                                const std::wstring& description);

std::string MacWithSeparators(const std::string& mac);
