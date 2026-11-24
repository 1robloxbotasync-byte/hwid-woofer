#pragma once

#include <windows.h>

#include <cstddef>
#include <string>
#include <vector>

#include "identity.h"

/*
 * SMBIOS table, user mode.
 *
 * mssmbios caches the raw firmware table at boot and publishes it as
 * HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData. Every
 * user-mode SMBIOS consumer (the WMI MSSmBios provider, Win32_BIOS,
 * Win32_BaseBoard, Win32_PhysicalMemory) reads that one value, and so does
 * GetSystemFirmwareTable('RSMB').
 *
 * The driver rewrites it from ring 0. This does the same rewrite from ring 3,
 * which is what lets the firmware surface work on a machine whose boot policy
 * refuses the driver. Original bytes are captured once, DPAPI-sealed, and put
 * back by Restore().
 */
namespace smbios {

struct Result {
    size_t fields = 0;         // profile fields the table carries afterwards
    size_t changed = 0;        // fields this run rewrote
    size_t bytes = 0;          // bytes served after the rewrite
    bool alreadyProfile = false;
    bool capturedOriginals = false;
};

// Rewrites SMBiosData from the identity. Fails without writing when the value
// is missing, not binary, or does not parse as a structure table.
bool Apply(const Identity& identity, bool dryRun, Result& result, std::wstring& error);

// Writes the captured firmware table back. A table that was already spoofed
// when this tool first ran is never captured, so Restore() reports instead of
// writing a spoof back over the machine's real one.
bool Restore(bool dryRun, size_t& bytes, std::wstring& error);

struct State {
    bool readable = false;
    bool originals = false;    // an originals file exists
    bool spoofed = false;      // served table differs from the captured originals
    bool servesProfile = false;
    size_t bytes = 0;
    size_t matchedFields = 0;
    size_t profileFields = 0;
};

// identity may be null when the caller has no profile to compare against.
State Inspect(const Identity* identity);

std::wstring OriginalsPath();

/*
 * Boot reapply without a driver: a SYSTEM ONSTART scheduled task that runs
 * "hwidspoof --reapply --no-driver --no-network". Perma mode uses it so the
 * identity survives reboot on machines where the kernel image cannot load.
 */
bool InstallBootTask(const std::wstring& executable, std::wstring& error);
bool RemoveBootTask(std::wstring& error);
bool BootTaskInstalled();

} // namespace smbios
