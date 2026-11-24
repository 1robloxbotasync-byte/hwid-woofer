#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "identity.h"

/*
 * Registry half of the spoofer.
 *
 * Everything here writes to HKLM only. A snapshot of the original values is
 * taken the first time Apply() runs and stored next to the executable, so
 * Restore() can put the machine back byte for byte without a reboot into
 * System Restore or a registry export.
 */

struct RegSnapshotEntry {
    std::wstring subkey;
    std::wstring value;
    DWORD type = 0;
    bool present = false;
    std::vector<uint8_t> data;
};

class RegistrySpoofer {
public:
    // Captures originals (once) and writes every identity-backed value.
    bool Apply(const Identity& identity, bool dryRun, std::wstring& error);

    // Restores the captured snapshot and removes the backup file.
    bool Restore(bool dryRun, std::wstring& error);

    // Compares live values against the profile. A value that differs is the
    // real one, so it is reported masked; maskedValues counts them.
    static bool Verify(const Identity& identity, std::vector<std::wstring>& problems,
                       size_t* maskedValues = nullptr);

    // Mirrors identity into HKLM\HARDWARE\DESCRIPTION\System\BIOS. The kernel
    // rebuilds that key from firmware at boot, so the driver rewrites it too;
    // doing it here makes the change visible without waiting for a reboot.
    static bool ApplyHardwareBios(const Identity& identity, bool dryRun);

    // Rewrites the monitor serial inside every cached EDID blob.
    static bool ApplyDisplayEdid(const Identity& identity, bool dryRun);

    static std::wstring BackupPath();
    static bool BackupExists();

private:
    static void TargetList(const Identity& identity,
                           std::vector<std::pair<std::wstring, std::wstring>>& targets);

    bool captured_ = false;
    std::vector<RegSnapshotEntry> snapshot_;
};

// Reads a raw HKLM value of any type.
bool ReadRawValue(const std::wstring& subkey, const std::wstring& value, DWORD& type,
                  std::vector<uint8_t>& data, bool& present, std::wstring& error);

// Writes a raw HKLM value of any type.
bool WriteRawValue(const std::wstring& subkey, const std::wstring& value, DWORD type,
                   const std::vector<uint8_t>& data, std::wstring& error);

std::wstring ReadStringValue(const std::wstring& subkey, const std::wstring& value);
uint32_t ReadDwordValue(const std::wstring& subkey, const std::wstring& value);

// UTF-16 payload with a trailing NUL, ready for REG_SZ writes.
std::vector<uint8_t> MakeStringData(const std::wstring& text);
std::vector<uint8_t> MakeDwordData(uint32_t value);
std::wstring StringFromData(const std::vector<uint8_t>& data);
