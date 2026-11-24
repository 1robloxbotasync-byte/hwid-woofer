#include "driver_client.h"

#include "util.h"

#include <winioctl.h>

#include <vector>

namespace {

constexpr wchar_t kServiceName[] = HWID_SERVICE_NAME;
constexpr wchar_t kServiceDisplayName[] = L"Storage Helper Filter";

struct ScHandle {
    SC_HANDLE handle = nullptr;
    ~ScHandle()
    {
        if (handle != nullptr) {
            CloseServiceHandle(handle);
        }
    }
};

std::wstring NtPath(const std::wstring& path)
{
    if (path.rfind(L"\\??\\", 0) == 0) {
        return path;
    }
    return L"\\??\\" + path;
}

std::wstring InstalledDriverPath()
{
    wchar_t systemDir[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(systemDir, static_cast<UINT>(std::size(systemDir)));
    if (length == 0 || length >= std::size(systemDir)) {
        return HWID_DRIVER_FILE;
    }
    return std::wstring(systemDir) + L"\\drivers\\" + HWID_DRIVER_FILE;
}

bool StartServiceHandle(SC_HANDLE service, DWORD& errorCode)
{
    if (StartServiceW(service, 0, nullptr)) {
        return true;
    }
    errorCode = GetLastError();
    if (errorCode == ERROR_SERVICE_ALREADY_RUNNING) {
        return true;
    }
    return false;
}

/*
 * Why the kernel refused the image, in terms that say what to do next. None
 * of these paths touch boot configuration: the tool never trades machine
 * safety for a load.
 */
std::wstring LoadAdvice(DWORD startError)
{
    if (startError == ERROR_INVALID_IMAGE_HASH) {
        if (util::SecureBootEnabled()) {
            return L". Secure Boot is on, so firmware accepts only a Microsoft-signed image. This "
                   L"build carries a local test signature; have it attestation-signed to load "
                   L"here. Nothing was left installed and boot configuration was not touched.";
        }
        return L". Test signing is off, so Windows refuses the local signature. Enable it yourself "
               L"with 'bcdedit /set testsigning on' and reboot - this tool will not change boot "
               L"policy. Nothing was left installed.";
    }
    if (startError == ERROR_DRIVER_BLOCKED) {
        return L". Memory Integrity or the driver blocklist refused the image. Nothing was left "
               L"installed.";
    }
    if (startError == ERROR_ACCESS_DENIED) {
        return L". Administrator rights are required to load a kernel service.";
    }
    return L".";
}

} // namespace

DriverClient::~DriverClient()
{
    Close();
}

bool DriverClient::InstallAndStart(const std::wstring& driverPath, DWORD startType,
                                   std::wstring& error)
{
    if (!util::FileExists(driverPath)) {
        error = L"Driver file not found: " + driverPath;
        return false;
    }

    /*
     * The service must not point at a user profile folder: perma mode starts
     * this driver before anyone logs in, and a path that moves breaks boot
     * load silently. Copy it where every other kernel driver lives.
     */
    const std::wstring installedPath = InstalledDriverPath();
    const bool copied = _wcsicmp(installedPath.c_str(), driverPath.c_str()) != 0;
    if (copied) {
        if (!CopyFileW(driverPath.c_str(), installedPath.c_str(), FALSE)) {
            error = L"Cannot copy the driver to " + installedPath + L": " +
                    util::FormatWin32Error(GetLastError());
            return false;
        }
    }

    ScHandle scm;
    scm.handle = OpenSCManagerW(nullptr, nullptr,
                                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (scm.handle == nullptr) {
        error = L"OpenSCManager failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }

    const std::wstring imagePath = NtPath(installedPath);

    /*
     * The image is put on trial at DEMAND_START. AUTO_START is written only
     * after the kernel accepts it, so an image firmware would refuse can
     * never end up sitting in the boot path. On any failure the service and
     * the copied file are removed, leaving the machine as it was found.
     */
    ScHandle service;
    service.handle = CreateServiceW(
        scm.handle, kServiceName, kServiceDisplayName,
        SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        imagePath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

    if (service.handle == nullptr) {
        const DWORD createError = GetLastError();
        if (createError != ERROR_SERVICE_EXISTS && createError != ERROR_SERVICE_MARKED_FOR_DELETE) {
            error = L"CreateService failed: " + util::FormatWin32Error(createError);
            return false;
        }

        service.handle = OpenServiceW(scm.handle, kServiceName,
                                      SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS |
                                          SERVICE_CHANGE_CONFIG | DELETE);
        if (service.handle == nullptr) {
            error = L"OpenService failed: " + util::FormatWin32Error(GetLastError());
            return false;
        }

        if (!ChangeServiceConfigW(service.handle, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                  SERVICE_NO_CHANGE, imagePath.c_str(), nullptr, nullptr,
                                  nullptr, nullptr, nullptr, nullptr)) {
            error = L"ChangeServiceConfig failed: " + util::FormatWin32Error(GetLastError());
            return false;
        }
    }

    const auto rollback = [&]() {
        (void)DeleteService(service.handle);
        if (copied) {
            (VOID)DeleteFileW(installedPath.c_str());
        }
    };

    DWORD startError = ERROR_SUCCESS;
    if (!StartServiceHandle(service.handle, startError)) {
        if (startError == ERROR_SERVICE_DISABLED) {
            (void)ChangeServiceConfigW(service.handle, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
                                       SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr,
                                       nullptr, nullptr, nullptr);
            if (!StartServiceHandle(service.handle, startError)) {
                error = L"StartService failed: " + util::FormatWin32Error(startError) +
                        LoadAdvice(startError);
                rollback();
                return false;
            }
        } else {
            error = L"StartService failed: " + util::FormatWin32Error(startError) +
                    LoadAdvice(startError);
            rollback();
            return false;
        }
    }

    if (startType == SERVICE_AUTO_START) {
        if (!ChangeServiceConfigW(service.handle, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                  SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr,
                                  nullptr, nullptr)) {
            error = L"The driver loaded but could not be armed for boot: " +
                    util::FormatWin32Error(GetLastError());
            return false;
        }
    }

    error.clear();
    return true;
}

bool DriverClient::StopAndDelete(std::wstring& error)
{
    ScHandle scm;
    scm.handle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm.handle == nullptr) {
        error = L"OpenSCManager failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }

    ScHandle service;
    service.handle = OpenServiceW(scm.handle, kServiceName,
                                  SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service.handle == nullptr) {
        const DWORD openError = GetLastError();
        if (openError == ERROR_SERVICE_DOES_NOT_EXIST) {
            error.clear();
            return true;
        }
        error = L"OpenService failed: " + util::FormatWin32Error(openError);
        return false;
    }

    SERVICE_STATUS status{};
    if (!ControlService(service.handle, SERVICE_CONTROL_STOP, &status)) {
        const DWORD stopError = GetLastError();
        if (stopError != ERROR_SERVICE_NOT_ACTIVE && stopError != ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
            error = L"ControlService(STOP) failed: " + util::FormatWin32Error(stopError);
        }
    }

    for (int attempt = 0; attempt < 20; attempt++) {
        SERVICE_STATUS_PROCESS processStatus{};
        DWORD needed = 0;
        if (!QueryServiceStatusEx(service.handle, SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&processStatus), sizeof(processStatus),
                                  &needed)) {
            break;
        }
        if (processStatus.dwCurrentState == SERVICE_STOPPED) {
            break;
        }
        Sleep(100);
    }

    if (!DeleteService(service.handle)) {
        const DWORD deleteError = GetLastError();
        if (deleteError != ERROR_SERVICE_MARKED_FOR_DELETE) {
            error = L"DeleteService failed: " + util::FormatWin32Error(deleteError);
            return false;
        }
    }

    /*
     * The image is only removable once the service object is gone. A driver
     * still mapped keeps the file locked, so a failure here is expected when
     * the stop did not complete and is not worth surfacing.
     */
    (VOID)DeleteFileW(InstalledDriverPath().c_str());

    error.clear();
    return true;
}

bool DriverClient::IsRunning()
{
    ScHandle scm;
    scm.handle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm.handle == nullptr) {
        return false;
    }
    ScHandle service;
    service.handle = OpenServiceW(scm.handle, kServiceName, SERVICE_QUERY_STATUS);
    if (service.handle == nullptr) {
        return false;
    }
    SERVICE_STATUS status{};
    return QueryServiceStatus(service.handle, &status) != FALSE &&
           status.dwCurrentState == SERVICE_RUNNING;
}

bool DriverClient::Open(std::wstring& error)
{
    Close();
    device_ = CreateFileW(HWID_USER_PATH, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device_ == INVALID_HANDLE_VALUE) {
        error = L"Open " HWID_USER_PATH L" failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }
    error.clear();
    return true;
}

void DriverClient::Close()
{
    if (device_ != INVALID_HANDLE_VALUE) {
        CloseHandle(device_);
        device_ = INVALID_HANDLE_VALUE;
    }
}

bool DriverClient::SetConfig(const HWID_CONFIG& config, std::wstring& error)
{
    if (!IsOpen()) {
        error = L"Driver device is not open";
        return false;
    }
    DWORD returned = 0;
    if (!DeviceIoControl(device_, HWID_IOCTL_SET_CONFIG,
                         const_cast<HWID_CONFIG*>(&config), sizeof(config),
                         nullptr, 0, &returned, nullptr)) {
        error = L"SET_CONFIG failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }
    error.clear();
    return true;
}

bool DriverClient::GetStatus(HWID_STATUS& status, std::wstring& error)
{
    if (!IsOpen()) {
        error = L"Driver device is not open";
        return false;
    }
    DWORD returned = 0;
    ZeroMemory(&status, sizeof(status));
    if (!DeviceIoControl(device_, HWID_IOCTL_GET_STATUS, nullptr, 0, &status, sizeof(status),
                         &returned, nullptr)) {
        error = L"GET_STATUS failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }
    if (returned < sizeof(status)) {
        error = L"GET_STATUS returned a short buffer";
        return false;
    }
    error.clear();
    return true;
}

bool DriverClient::Clear(std::wstring& error)
{
    if (!IsOpen()) {
        error = L"Driver device is not open";
        return false;
    }
    DWORD returned = 0;
    if (!DeviceIoControl(device_, HWID_IOCTL_CLEAR_CONFIG, nullptr, 0, nullptr, 0, &returned,
                         nullptr)) {
        error = L"CLEAR_CONFIG failed: " + util::FormatWin32Error(GetLastError());
        return false;
    }
    error.clear();
    return true;
}
