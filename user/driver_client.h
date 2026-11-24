#pragma once

#include <windows.h>

#include "../shared/hwid_ioctl.h"

#include <string>

class DriverClient {
public:
    DriverClient() = default;
    ~DriverClient();

    DriverClient(const DriverClient&) = delete;
    DriverClient& operator=(const DriverClient&) = delete;

    static bool InstallAndStart(const std::wstring& driverPath, DWORD startType,
                                std::wstring& error);
    static bool StopAndDelete(std::wstring& error);
    static bool IsRunning();

    bool Open(std::wstring& error);
    void Close();
    bool IsOpen() const { return device_ != INVALID_HANDLE_VALUE; }

    bool SetConfig(const HWID_CONFIG& config, std::wstring& error);
    bool GetStatus(HWID_STATUS& status, std::wstring& error);
    bool Clear(std::wstring& error);

private:
    HANDLE device_ = INVALID_HANDLE_VALUE;
};
