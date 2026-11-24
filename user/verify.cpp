#include "verify.h"

#include "network.h"
#include "registry.h"
#include "util.h"

#include "../shared/hwid_ioctl.h"

#include <ntddscsi.h>
#include <winioctl.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

/*
 * The 10.0.26100 SDK dropped IOCTL_SMART_RCV_DRIVE_DATA from ntddscsi.h even
 * though storahci still implements it. Same value as the DDK ever had.
 */
#ifndef IOCTL_SMART_RCV_DRIVE_DATA
#define IOCTL_SMART_RCV_DRIVE_DATA \
    CTL_CODE(IOCTL_DISK_BASE, 0x001E, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

namespace {

constexpr wchar_t kSmbiosKey[] = L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data";

std::wstring ReadDiskSerial(HANDLE device)
{
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    std::vector<uint8_t> buffer(4096, 0);
    DWORD returned = 0;
    if (!DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                         buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        return L"";
    }
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return L"";
    }

    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    if (descriptor->SerialNumberOffset == 0 ||
        descriptor->SerialNumberOffset >= returned) {
        return L"";
    }
    const char* serial = reinterpret_cast<const char*>(buffer.data()) +
                         descriptor->SerialNumberOffset;
    const size_t limit = returned - descriptor->SerialNumberOffset;
    std::string text(serial, strnlen(serial, limit));
    return util::ToWide(util::TrimAscii(text));
}

std::wstring ReadDiskModel(HANDLE device)
{
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    std::vector<uint8_t> buffer(4096, 0);
    DWORD returned = 0;
    if (!DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                         buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        return L"";
    }
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return L"";
    }
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    if (descriptor->ProductIdOffset == 0 || descriptor->ProductIdOffset >= returned) {
        return L"";
    }
    const char* model = reinterpret_cast<const char*>(buffer.data()) + descriptor->ProductIdOffset;
    const size_t limit = returned - descriptor->ProductIdOffset;
    return util::ToWide(util::TrimAscii(std::string(model, strnlen(model, limit))));
}

/*
 * Minimal SMBIOS reader. The firmware table is the surface every WMI class
 * (Win32_BIOS, Win32_BaseBoard, Win32_PhysicalMemory, Win32_ComputerSystemProduct)
 * ultimately reads, so verifying it is the honest test of whether the driver
 * actually replaced the real serials.
 */
struct FirmwareField {
    std::wstring name;
    std::wstring expected;
    std::wstring live;
};

std::wstring SmbiosString(const std::vector<uint8_t>& data, size_t formattedOffset,
                          size_t formattedLength, uint8_t index)
{
    if (index == 0 || formattedOffset + formattedLength > data.size()) {
        return L"";
    }

    size_t cursor = formattedOffset + formattedLength;
    for (uint8_t current = 1; current < index; current++) {
        while (cursor < data.size() && data[cursor] != 0) {
            cursor++;
        }
        if (cursor >= data.size()) {
            return L"";
        }
        cursor++;
    }
    const size_t start = cursor;
    while (cursor < data.size() && data[cursor] != 0) {
        cursor++;
    }
    if (cursor == start || cursor > data.size()) {
        return L"";
    }
    return util::ToWide(util::TrimAscii(std::string(
        reinterpret_cast<const char*>(data.data()) + start, cursor - start)));
}

std::wstring SmbiosUuid(const std::vector<uint8_t>& data, size_t offset)
{
    if (offset + 16 > data.size()) {
        return L"";
    }
    const uint8_t* raw = data.data() + offset;
    bool any = false;
    bool allOnes = true;
    for (int index = 0; index < 16; index++) {
        if (raw[index] != 0) {
            any = true;
        }
        if (raw[index] != 0xFF) {
            allOnes = false;
        }
    }
    if (!any || allOnes) {
        return L"";
    }

    wchar_t text[40]{};
    swprintf_s(text, L"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9],
               raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]);
    return text;
}

void AddFirmwareString(std::vector<FirmwareField>& fields, const wchar_t* name,
                       const std::wstring& expected, const std::vector<uint8_t>& data,
                       size_t offset, size_t length, size_t fieldOffset)
{
    if (fieldOffset >= length) {
        return;
    }
    FirmwareField field;
    field.name = name;
    field.expected = expected;
    field.live = SmbiosString(data, offset, length, data[offset + fieldOffset]);
    if (!field.live.empty()) {
        fields.push_back(std::move(field));
    }
}

std::vector<FirmwareField> ReadFirmwareFields(const Identity& identity)
{
    std::vector<FirmwareField> fields;

    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    std::wstring error;
    if (!ReadRawValue(kSmbiosKey, L"SMBiosData", type, data, present, error) || !present ||
        data.size() < 16) {
        return fields;
    }

    /*
     * mssmbios stores an 8-byte header before the table on some builds. Walk
     * four structures from each candidate; the header looks like a type-0
     * structure with an impossible length, so a chain check rejects it.
     */
    size_t cursor = data.size();
    {
        const size_t limit = data.size() < 128 ? data.size() : 128;
        for (size_t offset = 0; offset + 4 <= limit; offset++) {
            if (data[offset] != 0) {
                continue;
            }
            const size_t firstLength = data[offset + 1];
            if (firstLength < 0x12 || firstLength > 0x40) {
                continue;
            }
            size_t candidate = offset;
            bool valid = true;
            for (int step = 0; step < 4; step++) {
                if (candidate + 4 > data.size()) {
                    valid = false;
                    break;
                }
                const size_t length = data[candidate + 1];
                if (length < 4 || candidate + length > data.size()) {
                    valid = false;
                    break;
                }
                size_t next = candidate + length;
                while (next + 1 < data.size() && !(data[next] == 0 && data[next + 1] == 0)) {
                    next++;
                }
                if (next + 1 >= data.size()) {
                    valid = false;
                    break;
                }
                candidate = next + 2;
            }
            if (valid) {
                cursor = offset;
                break;
            }
        }
    }
    if (cursor >= data.size()) {
        return fields;
    }

    size_t memoryIndex = 0;
    for (size_t structs = 0; structs < 512 && cursor + 4 <= data.size(); structs++) {
        const uint8_t structType = data[cursor];
        const size_t length = data[cursor + 1];
        if (length < 4 || cursor + length > data.size()) {
            break;
        }

        switch (structType) {
        case 0: // BIOS information
            AddFirmwareString(fields, L"BIOS vendor", util::ToWide(identity.biosVendor), data,
                              cursor, length, 0x04);
            AddFirmwareString(fields, L"BIOS version", util::ToWide(identity.biosVersion), data,
                              cursor, length, 0x05);
            AddFirmwareString(fields, L"BIOS release date",
                              util::ToWide(identity.biosReleaseDate), data, cursor, length, 0x08);
            break;
        case 1: { // System information
            AddFirmwareString(fields, L"system manufacturer",
                              util::ToWide(identity.systemManufacturer), data, cursor, length,
                              0x04);
            AddFirmwareString(fields, L"system product", util::ToWide(identity.systemProductName),
                              data, cursor, length, 0x05);
            AddFirmwareString(fields, L"system serial", util::ToWide(identity.systemSerial), data,
                              cursor, length, 0x07);
            if (length >= 0x18) {
                FirmwareField uuid;
                uuid.name = L"system uuid";
                uuid.expected = util::ToWide(identity.systemUuid);
                uuid.live = SmbiosUuid(data, cursor + 0x08);
                if (!uuid.live.empty()) {
                    fields.push_back(std::move(uuid));
                }
            }
            break;
        }
        case 2: // Baseboard information
            AddFirmwareString(fields, L"baseboard manufacturer",
                              util::ToWide(identity.baseboardManufacturer), data, cursor, length,
                              0x04);
            AddFirmwareString(fields, L"baseboard product",
                              util::ToWide(identity.baseboardProduct), data, cursor, length, 0x05);
            AddFirmwareString(fields, L"baseboard serial",
                              util::ToWide(identity.baseboardSerial), data, cursor, length, 0x07);
            break;
        case 3: // Chassis information
            AddFirmwareString(fields, L"chassis manufacturer",
                              util::ToWide(identity.chassisManufacturer), data, cursor, length,
                              0x04);
            AddFirmwareString(fields, L"chassis serial", util::ToWide(identity.chassisSerial),
                              data, cursor, length, 0x07);
            break;
        case 17: // Memory device
            if (memoryIndex < identity.memorySerials.size()) {
                AddFirmwareString(fields, L"memory serial",
                                  util::ToWide(identity.memorySerials[memoryIndex]), data, cursor,
                                  length, 0x18);
                memoryIndex++;
            }
            break;
        default:
            break;
        }

        size_t next = cursor + length;
        while (next + 1 < data.size() && !(data[next] == 0 && data[next + 1] == 0)) {
            next++;
        }
        if (next + 1 >= data.size()) {
            break;
        }
        cursor = next + 2;
    }

    return fields;
}

} // namespace

std::vector<DiskSerialInfo> Verifier::Disks()
{
    std::vector<DiskSerialInfo> disks;
    for (int index = 0; index < 32; index++) {
        wchar_t path[64]{};
        swprintf_s(path, L"\\\\.\\PhysicalDrive%d", index);

        HANDLE device = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                    OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) {
            continue;
        }

        DiskSerialInfo info;
        info.index = index;
        info.present = true;
        info.model = ReadDiskModel(device);
        info.serial = ReadDiskSerial(device);
        CloseHandle(device);
        disks.push_back(std::move(info));
    }
    return disks;
}

std::vector<VolumeSerialInfo> Verifier::Volumes()
{
    std::vector<VolumeSerialInfo> volumes;
    const DWORD mask = GetLogicalDrives();

    for (int letter = 0; letter < 26; letter++) {
        if ((mask & (1u << letter)) == 0) {
            continue;
        }
        VolumeSerialInfo info;
        info.letter = static_cast<wchar_t>(L'A' + letter);
        info.root = std::wstring(1, info.letter) + L":\\";

        wchar_t label[MAX_PATH + 1]{};
        DWORD serial = 0;
        if (!GetVolumeInformationW(info.root.c_str(), label, MAX_PATH, &serial, nullptr, nullptr,
                                   nullptr, 0)) {
            continue;
        }
        info.present = true;
        info.label = label;
        info.serial = serial;
        volumes.push_back(std::move(info));
    }
    return volumes;
}

std::wstring Verifier::SmartSerial(int diskIndex)
{
    wchar_t path[64]{};
    swprintf_s(path, L"\\\\.\\PhysicalDrive%d", diskIndex);

    HANDLE device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return L"";
    }

    SENDCMDINPARAMS input{};
    input.cBufferSize = 512;
    input.bDriveNumber = static_cast<BYTE>(diskIndex);
    input.irDriveRegs.bDriveHeadReg = static_cast<BYTE>(0xA0 | ((diskIndex & 1) << 4));
    input.irDriveRegs.bCommandReg = 0xEC; // IDENTIFY DEVICE
    input.irDriveRegs.bSectorCountReg = 1;
    input.irDriveRegs.bSectorNumberReg = 1;
    input.irDriveRegs.bCylLowReg = 0;
    input.irDriveRegs.bCylHighReg = 0;

    std::vector<uint8_t> output(FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer) + 512, 0);
    DWORD returned = 0;
    const BOOL ok = DeviceIoControl(device, IOCTL_SMART_RCV_DRIVE_DATA, &input, sizeof(input),
                                    output.data(), static_cast<DWORD>(output.size()), &returned,
                                    nullptr);
    CloseHandle(device);
    if (!ok) {
        return L"";
    }

    auto* params = reinterpret_cast<SENDCMDOUTPARAMS*>(output.data());
    if (params->DriverStatus.bDriverError != 0) {
        return L"";
    }

    // ATA strings are byte-swapped words, space padded.
    wchar_t text[21]{};
    for (int word = 0; word < 10; word++) {
        text[word * 2] = static_cast<wchar_t>(params->bBuffer[20 + word * 2 + 1]);
        text[word * 2 + 1] = static_cast<wchar_t>(params->bBuffer[20 + word * 2]);
    }
    std::wstring result(text);
    while (!result.empty() && result.back() == L' ') {
        result.pop_back();
    }
    return result;
}

bool Verifier::SmbiosServed(std::wstring& detail)
{
    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    std::wstring error;
    if (!ReadRawValue(kSmbiosKey, L"SMBiosData", type, data, present, error)) {
        detail = error;
        return false;
    }
    if (!present) {
        detail = L"SMBiosData value is not present";
        return false;
    }
    wchar_t buffer[128]{};
    swprintf_s(buffer, L"SMBiosData served: %zu bytes (type %lu)", data.size(), type);
    detail = buffer;
    return true;
}

void Verifier::PrintIdentity(const Identity& identity)
{
    const auto line = [](const wchar_t* label, const std::wstring& value) {
        util::Logf(util::Level::Info, L"  %-20ls %ls", label, value.c_str());
    };

    util::Log(util::Level::Info, L"  -- profile --");
    util::Logf(util::Level::Info, L"  %-20ls %016llx", L"seed",
               static_cast<unsigned long long>(identity.seed));
    line(L"machine guid", util::ToWide(identity.machineGuid));
    line(L"product id", util::ToWide(identity.productId));
    line(L"hw profile guid", util::ToWide(identity.hwProfileGuid));
    line(L"sqm machine id", util::ToWide(identity.sqmMachineId));
    line(L"computer name", util::ToWide(identity.computerName));
    line(L"system uuid", util::ToWide(identity.systemUuid));
    line(L"system serial", util::ToWide(identity.systemSerial));
    line(L"baseboard serial", util::ToWide(identity.baseboardSerial));
    line(L"chassis serial", util::ToWide(identity.chassisSerial));
    line(L"system product", util::ToWide(identity.systemProductName));
    line(L"baseboard product", util::ToWide(identity.baseboardProduct));
    line(L"bios version", util::ToWide(identity.biosVersion));

    for (size_t index = 0; index < identity.adapters.size(); index++) {
        const MacAssignment& adapter = identity.adapters[index];
        util::Logf(util::Level::Info, L"  %-20ls %ls (%ls)", L"mac",
                   util::ToWide(MacWithSeparators(adapter.mac)).c_str(),
                   adapter.description.c_str());
    }
}

bool Verifier::Compare(const Identity& identity, std::vector<std::wstring>& problems,
                       size_t* maskedValues)
{
    problems.clear();
    size_t masked = 0;

    const auto noteProfile = [](const std::wstring& label, const std::wstring& value) {
        util::Logf(util::Level::Info, L"  %-22ls %ls  (profile)", label.c_str(), value.c_str());
    };
    const auto noteReal = [&](const std::wstring& label, const std::wstring& live) {
        masked++;
        problems.push_back(label + L" reads " + util::Redact(live) + L"  " + util::RealTag());
    };

    for (const DiskSerialInfo& disk : Disks()) {
        if (disk.index < 0 || disk.index >= HWID_MAX_DISKS) {
            continue;
        }
        const std::wstring expected = util::ToWide(identity.diskSerials[disk.index]);
        if (expected.empty()) {
            continue;
        }

        const std::wstring label = L"disk " + std::to_wstring(disk.index) + L" serial";
        if (disk.serial.empty()) {
            util::Logf(util::Level::Info, L"  %-22ls not exposed", label.c_str());
        } else if (util::SameId(disk.serial, expected)) {
            noteProfile(label, expected);
        } else {
            noteReal(label, disk.serial);
        }

        /* IDENTIFY DEVICE is a second, independent path to the same serial. */
        const std::wstring smart = SmartSerial(disk.index);
        if (!smart.empty()) {
            const std::wstring smartLabel = L"disk " + std::to_wstring(disk.index) + L" SMART";
            if (util::SameId(smart, expected)) {
                noteProfile(smartLabel, expected);
            } else {
                noteReal(smartLabel, smart);
            }
        }
    }

    for (const VolumeSerialInfo& volume : Volumes()) {
        const int index = volume.letter - L'A';
        if (index < 0 || index >= HWID_MAX_VOLUMES) {
            continue;
        }
        const std::string& hex = identity.volumeSerials[static_cast<size_t>(index)];
        if (hex.size() != 8) {
            continue;
        }
        const uint32_t expected = static_cast<uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
        const std::wstring label = L"volume " + volume.root + L" serial";
        if (volume.serial == expected) {
            wchar_t text[16]{};
            swprintf_s(text, L"%08lX", expected);
            noteProfile(label, text);
        } else {
            masked++;
            problems.push_back(label + L" reads " + util::RedactHex32(volume.serial) + L"  " +
                               util::RealTag());
        }
    }

    std::vector<std::wstring> registryProblems;
    size_t registryMasked = 0;
    (void)RegistrySpoofer::Verify(identity, registryProblems, &registryMasked);
    masked += registryMasked;
    for (const std::wstring& problem : registryProblems) {
        problems.push_back(L"registry: " + problem);
    }

    const std::vector<FirmwareField> firmware = ReadFirmwareFields(identity);
    if (firmware.empty()) {
        util::Log(util::Level::Info, L"  firmware table         not readable on this account");
    }
    for (const FirmwareField& field : firmware) {
        if (util::SameId(field.live, field.expected)) {
            noteProfile(L"firmware " + field.name, field.expected);
        } else {
            noteReal(L"firmware " + field.name, field.live);
        }
    }

    for (const MacAssignment& adapter : identity.adapters) {
        const std::wstring live = NetworkSpoofer::ReadAssignedMac(adapter.adapterGuid);
        if (live.empty()) {
            continue;
        }
        const std::wstring label = L"mac " + adapter.description;
        if (util::SameId(live, util::ToWide(adapter.mac))) {
            noteProfile(label, util::ToWide(adapter.mac));
        } else {
            noteReal(label, live);
        }
    }

    if (maskedValues != nullptr) {
        *maskedValues = masked;
    }
    return problems.empty();
}
