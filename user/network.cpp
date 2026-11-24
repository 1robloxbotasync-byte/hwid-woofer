#include "network.h"

#include "util.h"

#include <devguid.h>
#include <setupapi.h>

#include <algorithm>
#include <vector>

#pragma comment(lib, "setupapi.lib")

namespace {

constexpr wchar_t kNetClassKey[] =
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";

// Bit 0 of the adapter's Characteristics value. Virtual miniports set it.
// Kept for reference: Microsoft's own stacks are filtered by ComponentId.

std::wstring RegString(HKEY key, const wchar_t* name)
{
    wchar_t buffer[512]{};
    DWORD size = sizeof(buffer);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &size) !=
        ERROR_SUCCESS) {
        return L"";
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return L"";
    }
    return buffer;
}

DWORD RegDword(HKEY key, const wchar_t* name, DWORD fallback)
{
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size) !=
            ERROR_SUCCESS ||
        type != REG_DWORD) {
        return fallback;
    }
    return value;
}

bool IsMicrosoftVirtual(const std::wstring& componentId)
{
    if (componentId.size() < 3) {
        return true;
    }
    return _wcsnicmp(componentId.c_str(), L"ms_", 3) == 0;
}

// Only PnP-enumerated hardware buses. Filters out WAN miniports, Wintun,
// Wi-Fi Direct, Hyper-V synthetic NICs and anything else software-enumerated.
bool IsPhysicalBus(const std::wstring& instanceId)
{
    static const wchar_t* kBusPrefixes[] = {L"PCI\\", L"USB\\", L"SD\\", L"BTHENUM\\"};
    for (const wchar_t* prefix : kBusPrefixes) {
        const size_t length = wcslen(prefix);
        if (instanceId.size() >= length && _wcsnicmp(instanceId.c_str(), prefix, length) == 0) {
            return true;
        }
    }
    return false;
}

struct DeviceInfoSet {
    HDEVINFO handle = INVALID_HANDLE_VALUE;
    ~DeviceInfoSet()
    {
        if (handle != INVALID_HANDLE_VALUE) {
            SetupDiDestroyDeviceInfoList(handle);
        }
    }
};

} // namespace

std::vector<NetAdapter> NetworkSpoofer::Enumerate()
{
    std::vector<NetAdapter> adapters;

    DeviceInfoSet set;
    set.handle = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (set.handle == INVALID_HANDLE_VALUE) {
        return adapters;
    }

    for (DWORD index = 0;; index++) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!SetupDiEnumDeviceInfo(set.handle, index, &info)) {
            break;
        }

        HKEY driverKey = SetupDiOpenDevRegKey(set.handle, &info, DICS_FLAG_GLOBAL, 0,
                                              DIREG_DRV, KEY_READ);
        if (driverKey == INVALID_HANDLE_VALUE) {
            continue;
        }

        NetAdapter adapter;
        adapter.guid = RegString(driverKey, L"NetCfgInstanceId");
        adapter.description = RegString(driverKey, L"DriverDesc");
        adapter.supportsNetworkAddress = RegDword(driverKey, L"*IfType", 0) != 0;

        wchar_t instanceBuffer[512]{};
        if (SetupDiGetDeviceInstanceIdW(set.handle, &info, instanceBuffer,
                                        static_cast<DWORD>(std::size(instanceBuffer)),
                                        nullptr)) {
            adapter.instanceId = instanceBuffer;
        }
        RegCloseKey(driverKey);

        if (adapter.guid.empty() || adapter.guid.front() != L'{') {
            continue;
        }
        if (!IsPhysicalBus(adapter.instanceId)) {
            continue;
        }

        // ComponentId lives on the Driver key but is readable only while the
        // key is open, so re-open read-only and filter virtual stacks.
        HKEY componentKey = SetupDiOpenDevRegKey(set.handle, &info, DICS_FLAG_GLOBAL, 0,
                                                 DIREG_DRV, KEY_READ);
        if (componentKey != INVALID_HANDLE_VALUE) {
            const std::wstring componentId = RegString(componentKey, L"ComponentId");
            RegCloseKey(componentKey);
            if (IsMicrosoftVirtual(componentId)) {
                continue;
            }
        }

        adapters.push_back(std::move(adapter));
    }

    return adapters;
}

bool NetworkSpoofer::Apply(Identity& identity, bool dryRun, size_t& written, std::wstring& error)
{
    written = 0;
    const std::vector<NetAdapter> adapters = Enumerate();
    if (adapters.empty()) {
        error = L"No physical network adapters found";
        return false;
    }

    for (const NetAdapter& adapter : adapters) {
        // EnsureAdapterMac either returns the profile entry or mints a
        // deterministic MAC from the seed and the adapter GUID.
        MacAssignment& assignment =
            EnsureAdapterMac(identity, adapter.guid, adapter.description);
        if (assignment.mac.size() != 12) {
            continue;
        }

        const std::wstring dotted = util::ToWide(MacWithSeparators(assignment.mac));
        if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: %ls -> %ls", adapter.description.c_str(),
                       dotted.c_str());
            written++;
            continue;
        }

        HKEY key = nullptr;
        const std::wstring keyPath = std::wstring(kNetClassKey) + L"\\" +
                                     adapter.driverKey.substr(adapter.driverKey.find_last_of(L'\\') + 1);
        const LSTATUS openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                                                 KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &key);
        if (openStatus != ERROR_SUCCESS) {
            util::Logf(util::Level::Warn, L"  cannot open driver key for %ls: %ls",
                       adapter.description.c_str(),
                       util::FormatWin32Error(openStatus).c_str());
            continue;
        }

        const DWORD bytes = static_cast<DWORD>(assignment.mac.size() * sizeof(wchar_t));
        const LSTATUS setStatus =
            RegSetValueExW(key, L"NetworkAddress", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(assignment.mac.c_str()), bytes);
        RegCloseKey(key);

        if (setStatus != ERROR_SUCCESS) {
            util::Logf(util::Level::Warn, L"  NetworkAddress write failed for %ls: %ls",
                       adapter.description.c_str(),
                       util::FormatWin32Error(setStatus).c_str());
            continue;
        }
        util::Logf(util::Level::Ok, L"  %ls -> %ls", adapter.description.c_str(), dotted.c_str());
        written++;
    }

    if (written == 0) {
        error = L"No adapter accepted a NetworkAddress override";
        return false;
    }
    error.clear();
    return true;
}

bool NetworkSpoofer::Restore(const Identity& identity, bool dryRun, std::wstring& error)
{
    const std::vector<NetAdapter> adapters = Enumerate();
    size_t cleared = 0;

    for (const NetAdapter& adapter : adapters) {
        const size_t slash = adapter.driverKey.find_last_of(L'\\');
        if (slash == std::wstring::npos) {
            continue;
        }
        const std::wstring keyPath =
            std::wstring(kNetClassKey) + L"\\" + adapter.driverKey.substr(slash + 1);

        if (dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would clear NetworkAddress on %ls",
                       adapter.description.c_str());
            cleared++;
            continue;
        }

        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                          KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            continue;
        }
        const LSTATUS status = RegDeleteValueW(key, L"NetworkAddress");
        RegCloseKey(key);
        if (status == ERROR_SUCCESS) {
            util::Logf(util::Level::Ok, L"  cleared %ls", adapter.description.c_str());
            cleared++;
        } else if (status != ERROR_FILE_NOT_FOUND) {
            util::Logf(util::Level::Warn, L"  clear failed for %ls: %ls",
                       adapter.description.c_str(),
                       util::FormatWin32Error(status).c_str());
        }
    }

    UNREFERENCED_PARAMETER(identity);
    util::Logf(util::Level::Ok, L"Network addresses cleared: %zu", cleared);
    error.clear();
    return true;
}

bool NetworkSpoofer::RestartAdapters(const std::vector<std::wstring>& guids, std::wstring& error)
{
    if (guids.empty()) {
        error.clear();
        return true;
    }

    DeviceInfoSet set;
    set.handle = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
    if (set.handle == INVALID_HANDLE_VALUE) {
        error = L"SetupDiGetClassDevs failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }

    size_t restarted = 0;
    bool firstFailure = true;

    for (DWORD index = 0;; index++) {
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        if (!SetupDiEnumDeviceInfo(set.handle, index, &info)) {
            break;
        }

        HKEY driverKey = SetupDiOpenDevRegKey(set.handle, &info, DICS_FLAG_GLOBAL, 0, DIREG_DRV,
                                              KEY_READ);
        if (driverKey == INVALID_HANDLE_VALUE) {
            continue;
        }
        const std::wstring guid = RegString(driverKey, L"NetCfgInstanceId");
        const std::wstring description = RegString(driverKey, L"DriverDesc");
        RegCloseKey(driverKey);

        const bool wanted = std::any_of(guids.begin(), guids.end(), [&guid](const std::wstring& g) {
            return _wcsicmp(g.c_str(), guid.c_str()) == 0;
        });
        if (!wanted) {
            continue;
        }

        SP_PROPCHANGE_PARAMS params{};
        params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        params.StateChange = DICS_PROPCHANGE;
        params.Scope = DICS_FLAG_GLOBAL;
        params.HwProfile = 0;

        if (!SetupDiSetClassInstallParams(set.handle, &info, &params.ClassInstallHeader,
                                          sizeof(params)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, set.handle, &info)) {
            const DWORD code = GetLastError();
            if (firstFailure) {
                error = L"Adapter restart failed for " + description + L": " +
                        util::FormatWin32Error(code);
                firstFailure = false;
            }
            continue;
        }
        util::Logf(util::Level::Ok, L"  restarted %ls", description.c_str());
        restarted++;
    }

    if (restarted == 0) {
        if (error.empty()) {
            error = L"No adapter was restarted";
        }
        return false;
    }
    error.clear();
    return true;
}

std::wstring NetworkSpoofer::ReadAssignedMac(const std::wstring& guid)
{
    const std::vector<NetAdapter> adapters = Enumerate();
    for (const NetAdapter& adapter : adapters) {
        if (_wcsicmp(adapter.guid.c_str(), guid.c_str()) != 0) {
            continue;
        }
        const size_t slash = adapter.driverKey.find_last_of(L'\\');
        if (slash == std::wstring::npos) {
            return L"";
        }
        const std::wstring keyPath =
            std::wstring(kNetClassKey) + L"\\" + adapter.driverKey.substr(slash + 1);
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0,
                          KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            return L"";
        }
        const std::wstring value = RegString(key, L"NetworkAddress");
        RegCloseKey(key);
        return value;
    }
    return L"";
}
