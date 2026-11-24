#pragma once

#include <windows.h>

#include <string>
#include <vector>

#include "identity.h"

struct DiskSerialInfo {
    int index = -1;
    std::wstring model;
    std::wstring serial;
    bool present = false;
};

struct VolumeSerialInfo {
    wchar_t letter = 0;
    std::wstring root;
    std::wstring label;
    DWORD serial = 0;
    bool present = false;
};

// Reads the values back through the same path an anti-cheat would use:
// IOCTL_STORAGE_QUERY_PROPERTY on \\.\PhysicalDriveN, GetVolumeInformation on
// the mounted root, plus the firmware table as exposed through the registry.
class Verifier {
public:
    static std::vector<DiskSerialInfo> Disks();
    static std::vector<VolumeSerialInfo> Volumes();

    // Returns the raw ATA IDENTIFY serial for a disk, read via SMART.
    static std::wstring SmartSerial(int diskIndex);

    // Registry-backed firmware view: size of the value plus whether it still
    // carries the live UUID the driver replaced.
    static bool SmbiosServed(std::wstring& detail);

    static void PrintIdentity(const Identity& identity);
    /*
     * Compares every readable surface against the profile. A value that does
     * not match is, by definition, the machine's real one: it lands in
     * problems masked, never in clear text. maskedValues counts them.
     */
    static bool Compare(const Identity& identity, std::vector<std::wstring>& problems,
                        size_t* maskedValues = nullptr);
};
