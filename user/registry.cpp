#include "registry.h"

#include "util.h"

#include <dpapi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

namespace {

constexpr wchar_t kCryptography[] = L"SOFTWARE\\Microsoft\\Cryptography";
constexpr wchar_t kCurrentVersion[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
constexpr wchar_t kSqmClient[] = L"SOFTWARE\\Microsoft\\SQMClient";
constexpr wchar_t kHwProfiles[] =
    L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001";
constexpr wchar_t kWindowsUpdate[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate";
constexpr wchar_t kSystemInformation[] =
    L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation";
constexpr wchar_t kComputerName[] =
    L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName";
constexpr wchar_t kActiveComputerName[] =
    L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName";

constexpr DWORD kAccess = KEY_READ | KEY_WRITE | KEY_WOW64_64KEY;

bool OpenForWrite(const std::wstring& subkey, HANDLE& key, std::wstring& error)
{
    HKEY handle = nullptr;
    const LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, nullptr,
                                           REG_OPTION_NON_VOLATILE, kAccess, nullptr,
                                           &handle, nullptr);
    if (status != ERROR_SUCCESS) {
        error = L"RegCreateKeyEx(" + subkey + L") failed: " + util::FormatWin32Error(status);
        return false;
    }
    key = handle;
    return true;
}

std::wstring EscapeColumns(const std::wstring& text)
{
    std::wstring out = text;
    for (wchar_t& ch : out) {
        if (ch == L'\t' || ch == L'\r' || ch == L'\n') {
            ch = L' ';
        }
    }
    return out;
}

/*
 * Monitor EDID. `Enum\DISPLAY\*\*\Device Parameters\EDID` is where every
 * component that wants a monitor identity reads it, and the 32-bit serial at
 * offset 0x0C is what gets hashed. Each 128-byte block ends in a checksum
 * that must be recomputed or the blob is rejected as corrupt.
 */
static uint32_t DeriveEdidSerial(uint64_t seed, const std::wstring& monitorId, size_t index)
{
    uint64_t state = seed ^ 0x9E3779B97F4A7C15ull;
    for (const wchar_t ch : monitorId) {
        state ^= static_cast<uint64_t>(ch);
        state *= 0x100000001B3ull;
    }
    state ^= static_cast<uint64_t>(index) * 0xBF58476D1CE4E5B9ull;
    state ^= state >> 30;
    state *= 0xBF58476D1CE4E5B9ull;
    state ^= state >> 27;
    state *= 0x94D049BB133111EBull;
    state ^= state >> 31;
    return static_cast<uint32_t>(state);
}

static void ResealEdid(std::vector<uint8_t>& edid)
{
    for (size_t block = 0; block + 128 <= edid.size(); block += 128) {
        uint32_t sum = 0;
        for (size_t index = 0; index < 127; index++) {
            sum += edid[block + index];
        }
        edid[block + 127] = static_cast<uint8_t>((256 - (sum & 0xFF)) & 0xFF);
    }
}

static bool EnumChildKeys(const std::wstring& path, std::vector<std::wstring>& names,
                          std::wstring& error)
{
    names.clear();
    HKEY key = nullptr;
    const LSTATUS opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                                         KEY_READ | KEY_WOW64_64KEY, &key);
    if (opened != ERROR_SUCCESS) {
        error.clear();
        return true;
    }

    for (DWORD index = 0;; index++) {
        wchar_t name[512]{};
        DWORD length = static_cast<DWORD>(std::size(name));
        const LSTATUS status = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr,
                                             nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (status != ERROR_SUCCESS) {
            error = L"RegEnumKeyEx(" + path + L") failed: " + util::FormatWin32Error(status);
            RegCloseKey(key);
            return false;
        }
        names.emplace_back(name, length);
    }
    RegCloseKey(key);
    error.clear();
    return true;
}

/*
 * The backup holds the machine's original hardware identity in clear text if
 * it is written as a plain ini. It is encrypted with DPAPI instead: the same
 * user on the same machine can read it for --restore, and nobody else can
 * lift the real serials out of the file.
 */
constexpr char kBackupMagic[8] = {'H', 'W', 'I', 'D', 'B', 'A', 'K', '1'};

std::vector<uint8_t> ProtectBackup(const std::string& plain)
{
    DATA_BLOB input{};
    input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()));
    input.cbData = static_cast<DWORD>(plain.size());
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"hwidspoof registry backup", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return {};
    }
    std::vector<uint8_t> blob(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return blob;
}

bool UnprotectBackup(const std::vector<uint8_t>& blob, std::string& plain)
{
    if (blob.empty()) {
        return false;
    }
    DATA_BLOB input{};
    input.pbData = const_cast<BYTE*>(blob.data());
    input.cbData = static_cast<DWORD>(blob.size());
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &output)) {
        return false;
    }
    plain.assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
    LocalFree(output.pbData);
    return true;
}

bool WriteEncryptedBackup(const std::wstring& path, const std::string& plain,
                          std::wstring& error)
{
    const std::vector<uint8_t> blob = ProtectBackup(plain);
    if (blob.empty()) {
        error = L"Registry backup encryption failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }

    std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error = L"Cannot create registry backup at " + path;
        return false;
    }
    const uint32_t length = static_cast<uint32_t>(plain.size());
    out.write(kBackupMagic, sizeof(kBackupMagic));
    out.write(reinterpret_cast<const char*>(&length), sizeof(length));
    out.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    if (!out.good()) {
        error = L"Registry backup write failed";
        return false;
    }
    return true;
}

} // namespace

bool ReadRawValue(const std::wstring& subkey, const std::wstring& value, DWORD& type,
                  std::vector<uint8_t>& data, bool& present, std::wstring& error)
{
    data.clear();
    type = 0;
    present = false;

    HKEY key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0,
                                   KEY_READ | KEY_WOW64_64KEY, &key);
    if (status == ERROR_FILE_NOT_FOUND) {
        error.clear();
        return true;
    }
    if (status != ERROR_SUCCESS) {
        error = L"RegOpenKeyEx(" + subkey + L") failed: " + util::FormatWin32Error(status);
        return false;
    }

    DWORD size = 0;
    status = RegQueryValueExW(key, value.c_str(), nullptr, &type, nullptr, &size);
    if (status == ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        error.clear();
        return true;
    }
    if (status != ERROR_SUCCESS) {
        RegCloseKey(key);
        error = L"RegQueryValueEx(" + subkey + L"\\" + value + L") failed: " +
                util::FormatWin32Error(status);
        return false;
    }

    data.resize(size == 0 ? 0 : size);
    if (size != 0) {
        status = RegQueryValueExW(key, value.c_str(), nullptr, &type, data.data(), &size);
    }
    RegCloseKey(key);

    if (status != ERROR_SUCCESS) {
        data.clear();
        error = L"RegQueryValueEx (second pass) failed: " + util::FormatWin32Error(status);
        return false;
    }
    data.resize(size);
    present = true;
    error.clear();
    return true;
}

bool WriteRawValue(const std::wstring& subkey, const std::wstring& value, DWORD type,
                   const std::vector<uint8_t>& data, std::wstring& error)
{
    HANDLE raw = nullptr;
    if (!OpenForWrite(subkey, raw, error)) {
        return false;
    }
    HKEY key = static_cast<HKEY>(raw);

    const LSTATUS status = RegSetValueExW(key, value.c_str(), 0, type,
                                          data.empty() ? nullptr : data.data(),
                                          static_cast<DWORD>(data.size()));
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        error = L"RegSetValueEx(" + subkey + L"\\" + value + L") failed: " +
                util::FormatWin32Error(status);
        return false;
    }
    error.clear();
    return true;
}

std::wstring ReadStringValue(const std::wstring& subkey, const std::wstring& value)
{
    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    std::wstring error;
    if (!ReadRawValue(subkey, value, type, data, present, error) || !present) {
        return L"";
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return L"";
    }
    return StringFromData(data);
}

uint32_t ReadDwordValue(const std::wstring& subkey, const std::wstring& value)
{
    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    std::wstring error;
    if (!ReadRawValue(subkey, value, type, data, present, error) || !present) {
        return 0;
    }
    if (type != REG_DWORD || data.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t result = 0;
    memcpy(&result, data.data(), sizeof(result));
    return result;
}

std::vector<uint8_t> MakeStringData(const std::wstring& text)
{
    std::vector<uint8_t> data((text.size() + 1) * sizeof(wchar_t), 0);
    if (!text.empty()) {
        memcpy(data.data(), text.data(), text.size() * sizeof(wchar_t));
    }
    return data;
}

std::vector<uint8_t> MakeDwordData(uint32_t value)
{
    std::vector<uint8_t> data(sizeof(value));
    memcpy(data.data(), &value, sizeof(value));
    return data;
}

std::wstring StringFromData(const std::vector<uint8_t>& data)
{
    if (data.size() < sizeof(wchar_t)) {
        return L"";
    }
    const size_t chars = data.size() / sizeof(wchar_t);
    std::wstring text(reinterpret_cast<const wchar_t*>(data.data()), chars);
    while (!text.empty() && text.back() == L'\0') {
        text.pop_back();
    }
    return text;
}

std::wstring RegistrySpoofer::BackupPath()
{
    return util::JoinPath(util::ExeDirectory(), L"backup.ini");
}

bool RegistrySpoofer::BackupExists()
{
    return util::FileExists(BackupPath());
}

void RegistrySpoofer::TargetList(const Identity& identity,
                                 std::vector<std::pair<std::wstring, std::wstring>>& targets)
{
    targets.clear();
    targets.emplace_back(kCryptography, L"MachineGuid");
    targets.emplace_back(kCurrentVersion, L"ProductId");
    targets.emplace_back(kCurrentVersion, L"InstallDate");
    targets.emplace_back(kHwProfiles, L"HwProfileGuid");
    targets.emplace_back(kSqmClient, L"MachineId");
    targets.emplace_back(kWindowsUpdate, L"SusClientId");
    targets.emplace_back(kSystemInformation, L"ComputerHardwareId");
    targets.emplace_back(kSystemInformation, L"SystemManufacturer");
    targets.emplace_back(kSystemInformation, L"SystemProductName");
    targets.emplace_back(kSystemInformation, L"SystemSKU");
    targets.emplace_back(kSystemInformation, L"SystemVersion");
    targets.emplace_back(kComputerName, L"ComputerName");
    targets.emplace_back(kActiveComputerName, L"ComputerName");

    // Keep the identity referenced so the signature stays honest if the list
    // ever grows to depend on generated values.
    (void)identity;
}

/*
 * Every cached EDID blob, as (device-parameters-key, "EDID") pairs, so the
 * originals land in backup.ini and --restore can put them back. Monitors come
 * and go between runs, which is why this is enumerated, not stored.
 */
static void CollectEdidTargets(std::vector<std::pair<std::wstring, std::wstring>>& targets)
{
    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
    std::wstring error;
    std::vector<std::wstring> monitors;
    if (!EnumChildKeys(root, monitors, error)) {
        return;
    }
    for (const std::wstring& monitor : monitors) {
        std::vector<std::wstring> instances;
        if (!EnumChildKeys(root + L"\\" + monitor, instances, error)) {
            continue;
        }
        for (const std::wstring& instance : instances) {
            targets.emplace_back(root + L"\\" + monitor + L"\\" + instance +
                                     L"\\Device Parameters",
                                 L"EDID");
        }
    }
}

bool RegistrySpoofer::Apply(const Identity& identity, bool dryRun, std::wstring& error)
{
    std::vector<std::pair<std::wstring, std::wstring>> targets;
    TargetList(identity, targets);
    CollectEdidTargets(targets);

    if (!captured_) {
        if (!BackupExists()) {
            for (const auto& target : targets) {
                RegSnapshotEntry entry;
                entry.subkey = target.first;
                entry.value = target.second;
                if (!ReadRawValue(entry.subkey, entry.value, entry.type, entry.data,
                                  entry.present, error)) {
                    return false;
                }
                snapshot_.push_back(std::move(entry));
            }

            if (!dryRun) {
                std::ostringstream body;
                body << "[backup]\nformat=2\ncount=" << snapshot_.size() << "\n";
                for (const RegSnapshotEntry& entry : snapshot_) {
                    const std::wstring subkey = EscapeColumns(entry.subkey);
                    const std::wstring value = EscapeColumns(entry.value);
                    const std::string hex = util::HexEncode(entry.data);
                    body << "entry=" << util::ToUtf8(subkey) << '\t' << util::ToUtf8(value)
                         << '\t' << entry.type << '\t' << (entry.present ? 1 : 0) << '\t'
                         << hex << '\n';
                }
                if (!WriteEncryptedBackup(RegistrySpoofer::BackupPath(), body.str(), error)) {
                    return false;
                }
            }
            captured_ = true;
        } else {
            util::Log(util::Level::Info,
                      L"Existing registry backup kept; originals were captured earlier.");
            captured_ = true;
        }
    }

    struct Write {
        const wchar_t* subkey;
        const wchar_t* value;
        DWORD type;
        std::vector<uint8_t> data;
    };

    const std::wstring machineGuid = util::ToWide(identity.machineGuid);
    const std::wstring productId = util::ToWide(identity.productId);

    std::vector<Write> writes;
    writes.push_back({kCryptography, L"MachineGuid", REG_SZ, MakeStringData(machineGuid)});
    writes.push_back({kCurrentVersion, L"ProductId", REG_SZ, MakeStringData(productId)});
    writes.push_back({kCurrentVersion, L"InstallDate", REG_DWORD,
                      MakeDwordData(identity.installDate)});
    writes.push_back({kHwProfiles, L"HwProfileGuid", REG_SZ,
                      MakeStringData(util::ToWide(identity.hwProfileGuid))});
    writes.push_back({kSqmClient, L"MachineId", REG_SZ,
                      MakeStringData(util::ToWide(identity.sqmMachineId))});
    writes.push_back({kWindowsUpdate, L"SusClientId", REG_SZ,
                      MakeStringData(util::ToWide(identity.susClientId))});
    writes.push_back({kSystemInformation, L"ComputerHardwareId", REG_SZ,
                      MakeStringData(util::ToWide(identity.computerHardwareId))});
    writes.push_back({kSystemInformation, L"SystemManufacturer", REG_SZ,
                      MakeStringData(util::ToWide(identity.systemManufacturer))});
    writes.push_back({kSystemInformation, L"SystemProductName", REG_SZ,
                      MakeStringData(util::ToWide(identity.systemProductName))});
    writes.push_back({kSystemInformation, L"SystemSKU", REG_SZ,
                      MakeStringData(util::ToWide(identity.systemSku))});
    writes.push_back({kSystemInformation, L"SystemVersion", REG_SZ,
                      MakeStringData(util::ToWide(identity.systemVersion))});
    writes.push_back({kComputerName, L"ComputerName", REG_SZ,
                      MakeStringData(util::ToWide(identity.computerName))});
    writes.push_back({kActiveComputerName, L"ComputerName", REG_SZ,
                      MakeStringData(util::ToWide(identity.computerName))});

    for (const Write& write : writes) {
        const std::wstring current = ReadStringValue(write.subkey, write.value);
        if (write.type == REG_DWORD) {
            const uint32_t value = ReadDwordValue(write.subkey, write.value);
            uint32_t wanted = 0;
            if (write.data.size() >= sizeof(wanted)) {
                memcpy(&wanted, write.data.data(), sizeof(wanted));
            }
            if (value == wanted) {
                continue;
            }
        } else if (current == StringFromData(write.data)) {
            continue;
        }

        if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would set %ls\\%ls", write.subkey,
                       write.value);
            continue;
        }
        if (!WriteRawValue(write.subkey, write.value, write.type, write.data, error)) {
            return false;
        }
        util::Logf(util::Level::Ok, L"  %ls = %ls", write.value,
                   write.type == REG_DWORD
                       ? std::to_wstring(identity.installDate).c_str()
                       : StringFromData(write.data).c_str());
    }

    util::Log(util::Level::Info, L"  compatibility: HARDWARE\\DESCRIPTION\\System\\BIOS");
    ApplyHardwareBios(identity, dryRun);

    util::Log(util::Level::Info, L"  monitors: EDID serials");
    ApplyDisplayEdid(identity, dryRun);

    // Hostname is the one identity element that only lands after a reboot.
    const std::wstring hostName = util::ToWide(identity.computerName);
    if (!hostName.empty()) {
        wchar_t current[256]{};
        DWORD size = static_cast<DWORD>(std::size(current));
        if (GetComputerNameExW(ComputerNamePhysicalDnsHostname, current, &size) &&
            hostName == current) {
            util::Logf(util::Level::Info, L"  hostname already %ls", current);
        } else if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would rename host to %ls",
                       hostName.c_str());
        } else {
            if (!SetComputerNameExW(ComputerNamePhysicalDnsHostname, hostName.c_str())) {
                util::Logf(util::Level::Warn, L"  hostname rename failed: %ls (reboot pending?)",
                           util::FormatWin32Error(GetLastError()).c_str());
            } else {
                util::Logf(util::Level::Ok, L"  hostname scheduled: %ls (takes effect on reboot)",
                           hostName.c_str());
            }
        }
    }

    error.clear();
    return true;
}

bool RegistrySpoofer::ApplyHardwareBios(const Identity& identity, bool dryRun)
{
    const std::wstring key = L"HARDWARE\\DESCRIPTION\\System\\BIOS";

    const auto writeString = [&](const wchar_t* name, const std::string& value) {
        if (value.empty()) {
            return;
        }
        const std::wstring wide = util::ToWide(value);
        if (ReadStringValue(key, name) == wide) {
            return;
        }
        if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: BIOS\\%ls = %ls", name, wide.c_str());
            return;
        }
        std::wstring error;
        if (!WriteRawValue(key, name, REG_SZ, MakeStringData(wide), error)) {
            util::Logf(util::Level::Warn, L"  %ls", error.c_str());
            return;
        }
        util::Logf(util::Level::Ok, L"  BIOS\\%ls = %ls", name, wide.c_str());
    };

    writeString(L"SystemManufacturer", identity.systemManufacturer);
    writeString(L"SystemProductName", identity.systemProductName);
    writeString(L"SystemVersion", identity.systemVersion);
    writeString(L"SystemFamily", identity.systemFamily);
    writeString(L"SystemSKU", identity.systemSku);
    writeString(L"BaseBoardManufacturer", identity.baseboardManufacturer);
    writeString(L"BaseBoardProduct", identity.baseboardProduct);
    writeString(L"BaseBoardVersion", identity.baseboardVersion);
    writeString(L"BIOSVendor", identity.biosVendor);
    writeString(L"BIOSVersion", identity.biosVersion);
    writeString(L"BIOSReleaseDate", identity.biosReleaseDate);

    if (!identity.biosVersion.empty()) {
        std::vector<uint8_t> multi = MakeStringData(util::ToWide(identity.biosVersion));
        multi.insert(multi.end(), sizeof(wchar_t), 0);
        if (dryRun) {
            util::Log(util::Level::Info, L"  dry-run: BIOS\\SystemBiosVersion (multi-sz)");
        } else {
            std::wstring error;
            if (!WriteRawValue(key, L"SystemBiosVersion", REG_MULTI_SZ, multi, error)) {
                util::Logf(util::Level::Warn, L"  %ls", error.c_str());
            }
        }
    }

    return true;
}

bool RegistrySpoofer::ApplyDisplayEdid(const Identity& identity, bool dryRun)
{
    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
    std::wstring error;
    std::vector<std::wstring> monitors;
    if (!EnumChildKeys(root, monitors, error)) {
        util::Logf(util::Level::Warn, L"  %ls", error.c_str());
        return false;
    }

    size_t patched = 0;
    for (const std::wstring& monitor : monitors) {
        std::vector<std::wstring> instances;
        if (!EnumChildKeys(root + L"\\" + monitor, instances, error)) {
            continue;
        }
        for (const std::wstring& instance : instances) {
            const std::wstring key =
                root + L"\\" + monitor + L"\\" + instance + L"\\Device Parameters";
            DWORD type = 0;
            std::vector<uint8_t> edid;
            bool present = false;
            if (!ReadRawValue(key, L"EDID", type, edid, present, error) || !present ||
                type != REG_BINARY || edid.size() < 128) {
                continue;
            }

            const uint32_t serial = DeriveEdidSerial(identity.seed, monitor, patched);
            if (edid[12] == static_cast<uint8_t>(serial) &&
                edid[13] == static_cast<uint8_t>(serial >> 8) &&
                edid[14] == static_cast<uint8_t>(serial >> 16) &&
                edid[15] == static_cast<uint8_t>(serial >> 24)) {
                continue;
            }
            edid[12] = static_cast<uint8_t>(serial);
            edid[13] = static_cast<uint8_t>(serial >> 8);
            edid[14] = static_cast<uint8_t>(serial >> 16);
            edid[15] = static_cast<uint8_t>(serial >> 24);
            ResealEdid(edid);

            if (dryRun) {
                util::Logf(util::Level::Info, L"  dry-run: EDID %ls\\%ls serial %08lX",
                           monitor.c_str(), instance.c_str(), serial);
                patched++;
                continue;
            }
            if (!WriteRawValue(key, L"EDID", REG_BINARY, edid, error)) {
                util::Logf(util::Level::Warn, L"  %ls", error.c_str());
                continue;
            }
            util::Logf(util::Level::Ok, L"  EDID %ls serial %08lX", monitor.c_str(), serial);
            patched++;
        }
    }

    if (patched == 0) {
        util::Log(util::Level::Info, L"  no monitor EDID to change");
    }
    return true;
}

bool RegistrySpoofer::Restore(bool dryRun, std::wstring& error)
{
    if (!util::FileExists(RegistrySpoofer::BackupPath())) {
        util::Log(util::Level::Info, L"No registry backup present; nothing to restore.");
        error.clear();
        return true;
    }

    std::vector<uint8_t> file;
    if (!util::ReadAllBytes(RegistrySpoofer::BackupPath(), file)) {
        error = L"Cannot read registry backup";
        return false;
    }

    std::string backupText;
    if (file.size() >= sizeof(kBackupMagic) + sizeof(uint32_t) &&
        memcmp(file.data(), kBackupMagic, sizeof(kBackupMagic)) == 0) {
        const std::vector<uint8_t> blob(
            file.begin() + sizeof(kBackupMagic) + sizeof(uint32_t), file.end());
        if (!UnprotectBackup(blob, backupText)) {
            error = L"Registry backup cannot be decrypted by this account";
            return false;
        }
    } else {
        /* Pre-encryption backups were plain text; still restorable. */
        backupText.assign(reinterpret_cast<const char*>(file.data()), file.size());
    }

    std::istringstream in(backupText);
    std::string line;
    size_t restored = 0;
    while (std::getline(in, line)) {
        line = util::TrimAscii(line);
        if (line.rfind("entry=", 0) != 0) {
            continue;
        }
        const std::string payload = line.substr(6);
        std::vector<std::string> fields;
        std::string current;
        for (char ch : payload) {
            if (ch == '\t') {
                fields.push_back(current);
                current.clear();
            } else {
                current.push_back(ch);
            }
        }
        fields.push_back(current);
        if (fields.size() < 5) {
            continue;
        }

        const std::wstring subkey = util::ToWide(fields[0]);
        const std::wstring value = util::ToWide(fields[1]);
        const DWORD type = static_cast<DWORD>(std::strtoul(fields[2].c_str(), nullptr, 10));
        const bool present = fields[3] == "1";
        const std::vector<uint8_t> data = util::HexDecode(fields[4]);

        if (!present) {
            continue;
        }
        if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would restore %ls\\%ls", subkey.c_str(),
                       value.c_str());
            restored++;
            continue;
        }
        if (!WriteRawValue(subkey, value, type, data, error)) {
            return false;
        }
        /*
         * The value written here is the machine's true one. It goes into the
         * log masked, same rule as verification: shape, never bytes.
         */
        const std::wstring original =
            type == REG_DWORD && data.size() >= sizeof(uint32_t)
                ? util::RedactHex32(*reinterpret_cast<const uint32_t*>(data.data()))
                : util::Redact(StringFromData(data));
        util::Logf(util::Level::Ok, L"  restored %ls -> %ls  %ls", value.c_str(),
                   original.c_str(), util::RealTag().c_str());
        restored++;
    }

    if (!dryRun) {
        DeleteFileW(RegistrySpoofer::BackupPath().c_str());
    }
    util::Logf(util::Level::Ok, L"Registry values restored: %zu", restored);
    error.clear();
    return true;
}

bool RegistrySpoofer::Verify(const Identity& identity,
                             std::vector<std::wstring>& problems,
                             size_t* maskedValues)
{
    problems.clear();
    size_t masked = 0;
    size_t matched = 0;

    /*
     * A live value that is not the profile value is the machine's real one.
     * It never leaves this process in clear text: the log gets the shape,
     * not the bytes.
     */
    const auto check = [&problems, &masked, &matched](const wchar_t* label,
                                                      const std::wstring& live,
                                                      const std::wstring& expected) {
        if (live.empty() && expected.empty()) {
            return;
        }
        if (util::SameId(live, expected)) {
            matched++;
            return;
        }
        if (live.empty()) {
            problems.push_back(std::wstring(label) + L" is not set");
            return;
        }
        masked++;
        problems.push_back(std::wstring(label) + L" reads " + util::Redact(live) + L"  " +
                           util::RealTag());
    };

    check(L"MachineGuid", ReadStringValue(kCryptography, L"MachineGuid"),
          util::ToWide(identity.machineGuid));
    check(L"ProductId", ReadStringValue(kCurrentVersion, L"ProductId"),
          util::ToWide(identity.productId));
    check(L"HwProfileGuid", ReadStringValue(kHwProfiles, L"HwProfileGuid"),
          util::ToWide(identity.hwProfileGuid));
    check(L"SQMClient MachineId", ReadStringValue(kSqmClient, L"MachineId"),
          util::ToWide(identity.sqmMachineId));
    check(L"WindowsUpdate SusClientId", ReadStringValue(kWindowsUpdate, L"SusClientId"),
          util::ToWide(identity.susClientId));
    check(L"ComputerHardwareId", ReadStringValue(kSystemInformation, L"ComputerHardwareId"),
          util::ToWide(identity.computerHardwareId));
    check(L"SystemInformation manufacturer",
          ReadStringValue(kSystemInformation, L"SystemManufacturer"),
          util::ToWide(identity.systemManufacturer));
    check(L"SystemInformation product", ReadStringValue(kSystemInformation, L"SystemProductName"),
          util::ToWide(identity.systemProductName));
    check(L"SystemInformation sku", ReadStringValue(kSystemInformation, L"SystemSKU"),
          util::ToWide(identity.systemSku));
    check(L"SystemInformation version", ReadStringValue(kSystemInformation, L"SystemVersion"),
          util::ToWide(identity.systemVersion));
    check(L"ComputerName", ReadStringValue(kComputerName, L"ComputerName"),
          util::ToWide(identity.computerName));
    check(L"ActiveComputerName", ReadStringValue(kActiveComputerName, L"ComputerName"),
          util::ToWide(identity.computerName));

    const uint32_t installDate = ReadDwordValue(kCurrentVersion, L"InstallDate");
    if (installDate != identity.installDate) {
        masked++;
        problems.push_back(L"InstallDate differs from the profile  " + util::RealTag());
    } else {
        matched++;
    }

    /* The BIOS key is rebuilt from firmware every boot; user mode can only
       mirror it, so a real value here means the driver did not rewrite the
       table on this boot. */
    const std::wstring biosKey = L"HARDWARE\\DESCRIPTION\\System\\BIOS";
    check(L"BIOS SystemProductName", ReadStringValue(biosKey, L"SystemProductName"),
          util::ToWide(identity.systemProductName));
    check(L"BIOS BaseBoardProduct", ReadStringValue(biosKey, L"BaseBoardProduct"),
          util::ToWide(identity.baseboardProduct));
    check(L"BIOS BIOSVersion", ReadStringValue(biosKey, L"BIOSVersion"),
          util::ToWide(identity.biosVersion));

    /* Monitor EDID serial, same enumeration order as ApplyDisplayEdid. */
    const std::wstring edidRoot = L"SYSTEM\\CurrentControlSet\\Enum\\DISPLAY";
    std::wstring error;
    std::vector<std::wstring> monitors;
    if (EnumChildKeys(edidRoot, monitors, error)) {
        size_t valid = 0;
        for (const std::wstring& monitor : monitors) {
            std::vector<std::wstring> instances;
            if (!EnumChildKeys(edidRoot + L"\\" + monitor, instances, error)) {
                continue;
            }
            for (const std::wstring& instance : instances) {
                const std::wstring key =
                    edidRoot + L"\\" + monitor + L"\\" + instance + L"\\Device Parameters";
                DWORD type = 0;
                std::vector<uint8_t> edid;
                bool present = false;
                if (!ReadRawValue(key, L"EDID", type, edid, present, error) || !present ||
                    type != REG_BINARY || edid.size() < 128) {
                    continue;
                }
                const uint32_t live = static_cast<uint32_t>(edid[12]) |
                                      (static_cast<uint32_t>(edid[13]) << 8) |
                                      (static_cast<uint32_t>(edid[14]) << 16) |
                                      (static_cast<uint32_t>(edid[15]) << 24);
                const uint32_t expected = DeriveEdidSerial(identity.seed, monitor, valid);
                valid++;
                if (live != expected) {
                    masked++;
                    problems.push_back(L"EDID " + monitor + L" serial " +
                                       util::RedactHex32(live) + L"  " + util::RealTag());
                } else {
                    matched++;
                }
            }
        }
    }

    if (matched > 0) {
        util::Logf(util::Level::Info, L"  registry: %zu value(s) read back as the profile",
                   matched);
    }
    if (maskedValues != nullptr) {
        *maskedValues = masked;
    }
    return problems.empty();
}
