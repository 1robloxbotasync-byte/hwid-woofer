/*
 * hwidspoof-setup.exe - the installer.
 *
 * One self-contained binary: the GUI, the CLI, the driver image and the README
 * are RCDATA resources inside it. Running it asks for elevation once (the
 * manifest), writes the payload into Program Files, registers an uninstall
 * entry and Start Menu shortcut, and gets out of the way.
 *
 * Why not Inno/NSIS: those stubs are themselves a recurring heuristic flag and
 * they need a build dependency. This is ~200 lines of CreateFile/RegSetValueEx
 * compiled by the same toolchain as the thing it installs.
 *
 * The installer never applies an identity. Installing software and rewriting a
 * machine's serials are two different decisions; the second one stays in the
 * UI where it can be seen.
 */
#include <windows.h>
#include <dwmapi.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <windowsx.h>

#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../shared/version.h"

namespace {

/* ------------------------------------------------------------------ */
/* Palette - same bench as the GUI                                     */
/* ------------------------------------------------------------------ */

constexpr COLORREF kBg = RGB(9, 6, 14);
constexpr COLORREF kPanel = RGB(20, 13, 31);
constexpr COLORREF kPanelHover = RGB(30, 20, 46);
constexpr COLORREF kPanelOff = RGB(15, 10, 22);
constexpr COLORREF kAccent = RGB(124, 58, 237);
constexpr COLORREF kAccentHover = RGB(139, 92, 246);
constexpr COLORREF kAccentPress = RGB(104, 45, 205);
constexpr COLORREF kBorder = RGB(47, 31, 70);
constexpr COLORREF kBorderHover = RGB(90, 60, 132);
constexpr COLORREF kText = RGB(236, 229, 248);
constexpr COLORREF kTextDim = RGB(160, 141, 190);
constexpr COLORREF kTextOff = RGB(96, 84, 116);
constexpr COLORREF kOk = RGB(74, 222, 128);
constexpr COLORREF kWarn = RGB(250, 190, 70);
constexpr COLORREF kErr = RGB(255, 92, 122);

constexpr wchar_t kWindowClass[] = L"HwidSpoofSetup";
constexpr wchar_t kInstallDirName[] = L"HWID Spoofer";
constexpr wchar_t kUninstallKey[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\HWIDSpoofer";
constexpr wchar_t kRunOnceKey[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

constexpr int kIdInstall = 2001;
constexpr int kIdUninstall = 2002;
constexpr int kIdClose = 2003;
constexpr int kIdShortcut = 2004;
constexpr int kIdDriver = 2005;

constexpr UINT kMsgRepaint = WM_APP + 2;
constexpr UINT kMsgJobDone = WM_APP + 3;
constexpr UINT kMsgAutoStart = WM_APP + 5;

/* The names are resource identifiers from the generated payload script. */
constexpr wchar_t kPayloadApp[] = L"PAYLOAD_APP";
constexpr wchar_t kPayloadCli[] = L"PAYLOAD_CLI";
constexpr wchar_t kPayloadSys[] = L"PAYLOAD_SYS";
constexpr wchar_t kPayloadReadme[] = L"PAYLOAD_README";

/* ------------------------------------------------------------------ */
/* Globals                                                             */
/* ------------------------------------------------------------------ */

HINSTANCE g_instance = nullptr;
HWND g_window = nullptr;
HFONT g_fontTitle = nullptr;
HFONT g_fontBody = nullptr;
HFONT g_fontSmall = nullptr;
HFONT g_fontButton = nullptr;
HFONT g_fontMono = nullptr;

int g_dpi = 96;
bool g_busy = false;
bool g_installed = false;
bool g_silent = false;
bool g_shortcutWanted = true;
bool g_driverWanted = true;
int g_hover = 0;
int g_pressed = 0;
int g_autoStart = 0; /* 0 none, 1 install, 2 uninstall */
int g_jobKind = 0;   /* 1 install, 2 uninstall; read by JobFinished */
COLORREF g_statusColor = kTextDim;
std::wstring g_statusText;
/* Set by the worker when an install finishes with something worth saying,
   consumed by JobFinished so the status line never claims more than landed. */
std::wstring g_jobNote;
std::wstring g_dirOverride;
std::wstring g_silentLog;
std::wstring g_tempSelf;

CRITICAL_SECTION g_logLock;
bool g_logLockReady = false;

struct LogEntry {
    std::wstring text;
    COLORREF color;
};
std::vector<LogEntry> g_log;

std::thread g_worker;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

int S(int value)
{
    return MulDiv(value, g_dpi, 96);
}

std::wstring FormatWin32(DWORD code)
{
    wchar_t* buffer = nullptr;
    const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                            FORMAT_MESSAGE_IGNORE_INSERTS,
                                        nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0,
                                        nullptr);
    std::wstring text = (length != 0 && buffer != nullptr) ? buffer : L"unknown error";
    if (buffer != nullptr) {
        LocalFree(buffer);
    }
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
        text.pop_back();
    }
    return text;
}

std::wstring ErrorText(const wchar_t* what, DWORD code)
{
    return std::wstring(what) + L" failed: " + FormatWin32(code) + L" (" + std::to_wstring(code) +
           L")";
}

/* An upgrade over a running copy fails with a sharing violation, and "access
   denied" alone sends people looking at permissions instead of the window they
   left open. Name the processes instead of describing the problem. */
std::wstring ProcessesUsing(const std::wstring& fileName)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::wstring();
    }

    std::wstring names;
    const DWORD self = GetCurrentProcessId();
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == self || _wcsicmp(entry.szExeFile, fileName.c_str()) != 0) {
                continue;
            }
            if (!names.empty()) {
                names += L", ";
            }
            names += entry.szExeFile;
            names += L" (pid " + std::to_wstring(entry.th32ProcessID) + L")";
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return names;
}

std::wstring Join(const std::wstring& left, const std::wstring& right)
{
    if (left.empty()) {
        return right;
    }
    std::wstring result = left;
    if (result.back() != L'\\' && result.back() != L'/') {
        result.push_back(L'\\');
    }
    result += right;
    return result;
}

std::wstring DirectoryOf(const std::wstring& path)
{
    const size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

std::wstring SelfPath()
{
    std::wstring buffer(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    buffer.resize(length);
    return buffer;
}

std::wstring Environment(const wchar_t* name)
{
    wchar_t buffer[32768];
    const DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(std::size(buffer)));
    if (length == 0 || length >= std::size(buffer)) {
        return std::wstring();
    }
    return std::wstring(buffer, length);
}

bool FileExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool SamePath(const std::wstring& left, const std::wstring& right)
{
    return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(),
                                static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool IsInside(const std::wstring& path, const std::wstring& directory)
{
    if (directory.empty() || path.size() <= directory.size()) {
        return false;
    }
    if (CompareStringOrdinal(path.c_str(), static_cast<int>(directory.size()), directory.c_str(),
                             static_cast<int>(directory.size()), TRUE) != CSTR_EQUAL) {
        return false;
    }
    return path[directory.size()] == L'\\' || path[directory.size()] == L'/';
}

/* Wide text goes out as UTF-8 so a redirected console (CI, scripts) stays
   readable and a pipe capture in another tool does not mangle it. */
std::string Narrow(const std::wstring& text)
{
    if (text.empty()) {
        return std::string();
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return std::string();
    }
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), result.data(),
                        needed, nullptr, nullptr);
    return result;
}

std::wstring Widen(const std::string& text)
{
    if (text.empty()) {
        return std::wstring();
    }
    UINT codePage = CP_UTF8;
    int needed = MultiByteToWideChar(codePage, MB_ERR_INVALID_CHARS, text.c_str(),
                                     static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        codePage = CP_ACP;
        needed = MultiByteToWideChar(codePage, 0, text.c_str(), static_cast<int>(text.size()),
                                     nullptr, 0);
    }
    if (needed <= 0) {
        return std::wstring();
    }
    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(codePage, 0, text.c_str(), static_cast<int>(text.size()), result.data(),
                        needed);
    return result;
}

std::wstring Trim(const std::wstring& text)
{
    size_t first = 0;
    size_t last = text.size();
    while (first < last && (text[first] == L' ' || text[first] == L'\t' || text[first] == L'\r')) {
        first++;
    }
    while (last > first &&
           (text[last - 1] == L' ' || text[last - 1] == L'\t' || text[last - 1] == L'\r')) {
        last--;
    }
    return text.substr(first, last - first);
}

std::vector<std::wstring> SplitLines(const std::wstring& text)
{
    std::vector<std::wstring> lines;
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find(L'\n', start);
        const size_t stop = end == std::wstring::npos ? text.size() : end;
        std::wstring line = Trim(text.substr(start, stop - start));
        if (!line.empty()) {
            lines.push_back(line);
        }
        if (end == std::wstring::npos) {
            break;
        }
        start = end + 1;
    }
    return lines;
}

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

void LogLine(const std::wstring& text, COLORREF color)
{
    if (g_logLockReady) {
        EnterCriticalSection(&g_logLock);
    }
    g_log.push_back(LogEntry{text, color});
    if (g_log.size() > 600) {
        g_log.erase(g_log.begin(), g_log.begin() + 200);
    }
    if (g_logLockReady) {
        LeaveCriticalSection(&g_logLock);
    }

    if (g_silent) {
        const std::string line = Narrow(text) + "\n";
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        if (out != nullptr && out != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(out, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
        }
        /* A /quiet run is usually launched elevated from a script, and an
           elevated child does not inherit the parent's redirected handle.
           The file is the transcript that survives that. */
        if (!g_silentLog.empty()) {
            HANDLE log = CreateFileW(g_silentLog.c_str(), FILE_APPEND_DATA,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL, nullptr);
            if (log != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                WriteFile(log, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
                CloseHandle(log);
            }
        }
    } else if (g_window != nullptr) {
        PostMessageW(g_window, kMsgRepaint, 0, 0);
    }
}

void LogStep(const std::wstring& text)
{
    LogLine(text, kText);
}

void LogOk(const std::wstring& text)
{
    LogLine(text, kOk);
}

void LogWarn(const std::wstring& text)
{
    LogLine(text, kWarn);
}

void LogError(const std::wstring& text)
{
    LogLine(text, kErr);
}

void LogBlock(const std::wstring& text)
{
    for (const std::wstring& line : SplitLines(text)) {
        LogLine(L"  " + line, kTextDim);
    }
}

/* ------------------------------------------------------------------ */
/* Registry                                                            */
/* ------------------------------------------------------------------ */

bool ReadStringValue(HKEY root, const wchar_t* subKey, const wchar_t* name, std::wstring& value)
{
    value.clear();
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, subKey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return false;
    }
    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes);
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ) && bytes >= 2) {
        std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
        status = RegQueryValueExW(key, name, nullptr, &type,
                                  reinterpret_cast<LPBYTE>(buffer.data()), &bytes);
        if (status == ERROR_SUCCESS) {
            buffer.resize(wcsnlen_s(buffer.c_str(), buffer.size()));
            value = buffer;
        }
    }
    RegCloseKey(key);
    return !value.empty();
}

bool WriteStringValue(HKEY root, const wchar_t* subKey, const wchar_t* name,
                      const std::wstring& value)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    const LSTATUS status =
        RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), bytes);
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

bool WriteDwordValue(HKEY root, const wchar_t* subKey, const wchar_t* name, DWORD value)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(root, subKey, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_WRITE | KEY_WOW64_64KEY, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const LSTATUS status =
        RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

bool InstalledDir(std::wstring& directory)
{
    std::wstring location;
    if (!ReadStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"InstallLocation", location)) {
        return false;
    }
    directory = location;
    return !directory.empty();
}

/* ------------------------------------------------------------------ */
/* Process helper                                                      */
/* ------------------------------------------------------------------ */

bool RunCaptured(const std::wstring& exe, const std::wstring& arguments, std::wstring& output,
                 DWORD& exitCode, std::wstring& error)
{
    output.clear();
    exitCode = static_cast<DWORD>(-1);

    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;

    HANDLE readEnd = nullptr;
    HANDLE writeEnd = nullptr;
    if (!CreatePipe(&readEnd, &writeEnd, &attributes, 0)) {
        error = ErrorText(L"CreatePipe", GetLastError());
        return false;
    }
    SetHandleInformation(readEnd, HANDLE_FLAG_INHERIT, 0);
    HANDLE sink = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes,
                              OPEN_EXISTING, 0, nullptr);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = sink;
    startup.hStdOutput = writeEnd;
    startup.hStdError = writeEnd;

    std::wstring commandLine = L"\"" + exe + L"\"";
    if (!arguments.empty()) {
        commandLine += L" " + arguments;
    }
    std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
    buffer.push_back(L'\0');

    PROCESS_INFORMATION process{};
    const BOOL started =
        CreateProcessW(exe.c_str(), buffer.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                       nullptr, nullptr, &startup, &process);
    const DWORD startError = GetLastError();
    CloseHandle(writeEnd);
    if (sink != INVALID_HANDLE_VALUE) {
        CloseHandle(sink);
    }
    if (!started) {
        CloseHandle(readEnd);
        error = ErrorText(L"CreateProcess", startError);
        return false;
    }

    /* Drain while the child runs: a full pipe blocks it, and a blocked child
       never exits, so read first and wait second. */
    std::string bytes;
    char chunk[4096];
    DWORD got = 0;
    while (ReadFile(readEnd, chunk, sizeof(chunk), &got, nullptr) && got > 0) {
        if (bytes.size() < 256 * 1024) {
            bytes.append(chunk, got);
        }
    }
    CloseHandle(readEnd);

    WaitForSingleObject(process.hProcess, INFINITE);
    GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    output = Widen(bytes);
    return true;
}

/* ------------------------------------------------------------------ */
/* Payloads                                                            */
/* ------------------------------------------------------------------ */

bool HasPayload(const wchar_t* name)
{
    return FindResourceW(g_instance, name, RT_RCDATA) != nullptr;
}

bool ExtractPayload(const wchar_t* name, const std::wstring& target, std::wstring& error)
{
    HRSRC resource = FindResourceW(g_instance, name, RT_RCDATA);
    if (resource == nullptr) {
        error = std::wstring(L"bundled file is missing: ") + name;
        return false;
    }
    const DWORD size = SizeofResource(g_instance, resource);
    HGLOBAL loaded = LoadResource(g_instance, resource);
    const void* data = loaded != nullptr ? LockResource(loaded) : nullptr;
    if (size == 0 || data == nullptr) {
        error = std::wstring(L"bundled file is unreadable: ") + name;
        return false;
    }

    HANDLE file = CreateFileW(target.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD code = GetLastError();
        error = ErrorText((L"cannot write " + target).c_str(), code);
        if (code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED) {
            const size_t slash = target.find_last_of(L"\\/");
            const std::wstring leaf =
                slash == std::wstring::npos ? target : target.substr(slash + 1);
            const std::wstring holders = ProcessesUsing(leaf);
            error += L"\nclose ";
            error += holders.empty() ? leaf : holders;
            error += L" and run the installer again.";
        }
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, data, size, &written, nullptr);
    const DWORD writeError = GetLastError();
    CloseHandle(file);
    if (!ok || written != size) {
        error = ErrorText((L"cannot write " + target).c_str(), ok ? ERROR_WRITE_FAULT : writeError);
        return false;
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Shortcuts                                                           */
/* ------------------------------------------------------------------ */

/* COM apartments belong to the thread that made them. The window initialises
   one on the UI thread; Install runs on g_worker, which had none, so every
   CoCreateInstance there returned CO_E_NOTINITIALIZED while the rest of the
   install quietly succeeded. Each caller now owns its apartment. */
struct ComApartment {
    ComApartment()
        : result(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))
    {
    }
    ~ComApartment()
    {
        if (SUCCEEDED(result)) {
            CoUninitialize();
        }
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

    /* RPC_E_CHANGED_MODE: this thread was already an MTA. In-proc shell
       objects can still be created there, just do not call CoUninitialize. */
    bool Usable() const { return SUCCEEDED(result) || result == RPC_E_CHANGED_MODE; }

    HRESULT result;
};

std::wstring HResultText(HRESULT hr)
{
    wchar_t buffer[16]{};
    swprintf_s(buffer, L"0x%08X", static_cast<unsigned>(hr));
    return buffer;
}

/* IShellLink is the only supported way to write a .lnk: shell32 has to be able
   to resolve it, and the resolver wants the item ID list that comes from the
   shell itself. A hand-built link validates on paper and then launches from
   nowhere — that was measured, not assumed — so the fallback here is a second
   attempt in a second process, never a second file format. */
HRESULT CreateShortcutDirect(const std::wstring& linkPath, const std::wstring& target,
                             const std::wstring& arguments, const std::wstring& workingDirectory,
                             const std::wstring& description)
{
    const ComApartment apartment;
    if (FAILED(apartment.result) && !apartment.Usable()) {
        return apartment.result;
    }

    IShellLinkW* link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                  reinterpret_cast<void**>(&link));
    if (FAILED(hr) || link == nullptr) {
        return FAILED(hr) ? hr : E_POINTER;
    }

    link->SetPath(target.c_str());
    link->SetWorkingDirectory(workingDirectory.c_str());
    if (!arguments.empty()) {
        link->SetArguments(arguments.c_str());
    }
    if (!description.empty()) {
        link->SetDescription(description.c_str());
    }
    link->SetIconLocation(target.c_str(), 0);

    IPersistFile* file = nullptr;
    hr = link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&file));
    if (SUCCEEDED(hr) && file != nullptr) {
        SHCreateDirectoryExW(nullptr, DirectoryOf(linkPath).c_str(), nullptr);
        hr = file->Save(linkPath.c_str(), TRUE);
        file->Release();
    } else if (SUCCEEDED(hr)) {
        hr = E_NOINTERFACE;
    }
    link->Release();
    return hr;
}

/* A new process starts with a new apartment. If this one is poisoned — a hook
   that broke OLE in-process, a policy shim, an STA that was unwound under us —
   the child is still clean, and its exit code reports whether the link landed. */
bool CreateShortcutInChild(const std::wstring& linkPath, const std::wstring& target,
                           const std::wstring& arguments, const std::wstring& workingDirectory,
                           const std::wstring& description)
{
    const std::wstring self = SelfPath();
    std::wstring command = L"\"" + self + L"\" /mklink=\"" + linkPath + L"\" /target=\"" + target +
                           L"\" /workdir=\"" + workingDirectory + L"\" /desc=\"" + description +
                           L"\" /args=\"" + arguments + L"\"";
    std::vector<wchar_t> buffer(command.begin(), command.end());
    buffer.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(self.c_str(), buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) {
        return false;
    }
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    return wait == WAIT_OBJECT_0 && code == 0;
}

bool CreateShortcut(const std::wstring& linkPath, const std::wstring& target,
                    const std::wstring& arguments, const std::wstring& workingDirectory,
                    const std::wstring& description, std::wstring& error)
{
    HRESULT hr = CreateShortcutDirect(linkPath, target, arguments, workingDirectory, description);
    if (SUCCEEDED(hr)) {
        return true;
    }

    const std::wstring reason = HResultText(hr);
    if (CreateShortcutInChild(linkPath, target, arguments, workingDirectory, description)) {
        LogWarn(L"  shell link failed in-process (" + reason + L"), created from a helper process");
        return true;
    }

    error = L"cannot create shortcut " + linkPath + L" (" + reason + L")";
    return false;
}

std::wstring StartMenuLink()
{
    std::wstring programs = Environment(L"ProgramData");
    if (programs.empty()) {
        return std::wstring();
    }
    return Join(programs, L"Microsoft\\Windows\\Start Menu\\Programs\\HWID Spoofer.lnk");
}

std::wstring DesktopLink()
{
    std::wstring desktop = Environment(L"PUBLIC");
    if (desktop.empty()) {
        return std::wstring();
    }
    return Join(desktop, L"Desktop\\HWID Spoofer.lnk");
}

/* One stable path for every silent run, so an elevated install and the
   uninstaller it later spawns append to the same transcript. */
std::wstring SilentLogPath()
{
    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH) {
        return std::wstring();
    }
    return Join(temp, L"hwidspoof-setup.log");
}

void RemoveFile(const std::wstring& path)
{
    if (path.empty() || !FileExists(path)) {
        return;
    }
    if (DeleteFileW(path.c_str())) {
        return;
    }
    /* Locked (running image, held handle): let the next boot finish the job. */
    MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
}

/* ------------------------------------------------------------------ */
/* Install / uninstall                                                 */
/* ------------------------------------------------------------------ */

std::wstring DefaultInstallDir()
{
    if (!g_dirOverride.empty()) {
        return g_dirOverride;
    }
    std::wstring existing;
    if (InstalledDir(existing)) {
        return existing;
    }
    std::wstring programFiles = Environment(L"ProgramFiles");
    if (programFiles.empty()) {
        programFiles = L"C:\\Program Files";
    }
    return Join(programFiles, kInstallDirName);
}

bool EnsureDirectory(const std::wstring& directory, std::wstring& error)
{
    const int result = SHCreateDirectoryExW(nullptr, directory.c_str(), nullptr);
    if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS) {
        error = ErrorText((L"cannot create " + directory).c_str(), static_cast<DWORD>(result));
        return false;
    }
    return true;
}

bool Install(const std::wstring& directory, bool desktopShortcut, bool driverImage,
             std::wstring& error)
{
    LogStep(L"Install location: " + directory);
    if (!EnsureDirectory(directory, error)) {
        return false;
    }

    struct Item {
        const wchar_t* resource;
        const wchar_t* name;
        bool required;
    };
    const Item items[] = {
        {kPayloadApp, L"hwidspoof.exe", true},
        {kPayloadCli, L"hwidspoof-cli.exe", true},
        {kPayloadReadme, L"README.md", false},
        {kPayloadSys, L"storhlp.sys", false},
    };

    uint64_t bytesOnDisk = 0;
    for (const Item& item : items) {
        const std::wstring target = Join(directory, item.name);
        const bool wanted = (item.resource == kPayloadSys) ? driverImage : true;
        if (!HasPayload(item.resource)) {
            if (item.resource == kPayloadSys) {
                LogWarn(L"  storhlp.sys is not bundled with this build - skipping");
            } else if (item.required) {
                error = std::wstring(L"installer payload is incomplete: ") + item.name;
                return false;
            }
            continue;
        }
        if (!wanted) {
            LogWarn(L"  driver image skipped by choice");
            continue;
        }
        if (!ExtractPayload(item.resource, target, error)) {
            return false;
        }
        const HANDLE file = CreateFileW(target.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                        OPEN_EXISTING, 0, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER size{};
            if (GetFileSizeEx(file, &size)) {
                bytesOnDisk += static_cast<uint64_t>(size.QuadPart);
            }
            CloseHandle(file);
        }
        LogOk(L"  " + target);
    }

    /* The uninstall string has to point at something that outlives this run. */
    const std::wstring self = SelfPath();
    const std::wstring installedSetup = Join(directory, L"setup.exe");
    if (!SamePath(self, installedSetup)) {
        if (!CopyFileW(self.c_str(), installedSetup.c_str(), FALSE)) {
            error = ErrorText(L"cannot copy the installer", GetLastError());
            return false;
        }
        LogOk(L"  " + installedSetup);
    }

    const std::wstring targetExe = Join(directory, L"hwidspoof.exe");
    int shortcutsWanted = 0;
    int shortcutsMade = 0;
    const std::wstring menuLink = StartMenuLink();
    if (!menuLink.empty()) {
        shortcutsWanted++;
        if (CreateShortcut(menuLink, targetExe, L"", directory, L"HWID Spoofer", error)) {
            shortcutsMade++;
            LogOk(L"  Start Menu shortcut");
        } else {
            LogWarn(L"  " + error);
        }
    }

    if (desktopShortcut) {
        const std::wstring desktop = DesktopLink();
        if (!desktop.empty()) {
            shortcutsWanted++;
            if (CreateShortcut(desktop, targetExe, L"", directory, L"HWID Spoofer", error)) {
                shortcutsMade++;
                LogOk(L"  Desktop shortcut");
            } else {
                LogWarn(L"  " + error);
            }
        }
    }

    if (shortcutsMade != shortcutsWanted) {
        /* The files and the ARP entry are in place, so this is a warn, not a
           failure — but the status line must not promise a menu entry. */
        g_jobNote = L"Installed, but a shortcut could not be created - see the activity log.";
    }

    const std::wstring uninstallCommand = L"\"" + installedSetup + L"\" /uninstall";
    const std::wstring quietCommand = uninstallCommand + L" /quiet";
    const std::wstring icon = targetExe + L",0";
    const DWORD estimatedKb = static_cast<DWORD>((bytesOnDisk + 1023) / 1024);

    bool registryOk = true;
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"DisplayName",
                                   HWID_PRODUCT_NAME_WIDE);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"DisplayVersion",
                                   HWID_VERSION_WIDE);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"Publisher",
                                   HWID_COMPANY_NAME_WIDE);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"InstallLocation", directory);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"DisplayIcon", icon);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"UninstallString",
                                   uninstallCommand);
    registryOk &= WriteStringValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"QuietUninstallString",
                                   quietCommand);
    registryOk &= WriteDwordValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"NoModify", 1);
    registryOk &= WriteDwordValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"NoRepair", 1);
    registryOk &= WriteDwordValue(HKEY_LOCAL_MACHINE, kUninstallKey, L"EstimatedSize", estimatedKb);
    if (!registryOk) {
        error = L"cannot write the uninstall entry under HKLM\\" + std::wstring(kUninstallKey);
        return false;
    }
    LogOk(L"  Add/Remove Programs entry");

    LogStep(L"Installed " + std::wstring(HWID_PRODUCT_NAME_WIDE) + L" " + HWID_VERSION_WIDE);
    return true;
}

bool RemoveDirectoryContents(const std::wstring& directory, size_t& leftovers)
{
    leftovers = 0;
    const std::wstring pattern = Join(directory, L"*");
    WIN32_FIND_DATAW entry{};
    HANDLE search = FindFirstFileW(pattern.c_str(), &entry);
    if (search == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    }
    do {
        if (wcscmp(entry.cFileName, L".") == 0 || wcscmp(entry.cFileName, L"..") == 0) {
            continue;
        }
        const std::wstring path = Join(directory, entry.cFileName);
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            leftovers++;
            continue;
        }
        if (!DeleteFileW(path.c_str())) {
            MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
            leftovers++;
        }
    } while (FindNextFileW(search, &entry));
    FindClose(search);
    return true;
}

void ScheduleDirectoryCleanup(const std::wstring& directory)
{
    /* A running copy of the app, or a file an engine is holding, keeps the
       directory alive. RunOnce finishes it at the next logon. */
    const std::wstring command = L"cmd.exe /c rmdir /s /q \"" + directory + L"\"";
    WriteStringValue(HKEY_LOCAL_MACHINE, kRunOnceKey, L"HWIDSpooferCleanup", command);
}

bool Uninstall(const std::wstring& directory, std::wstring& error)
{
    if (directory.empty()) {
        error = L"no installation was found";
        return false;
    }
    LogStep(L"Removing " + directory);

    const std::wstring cli = Join(directory, L"hwidspoof-cli.exe");
    if (FileExists(cli)) {
        std::wstring output;
        DWORD exitCode = 0;
        std::wstring runError;

        LogStep(L"Restoring the original identity");
        if (RunCaptured(cli, L"--restore --no-driver --no-network", output, exitCode, runError)) {
            LogBlock(output);
            if (exitCode == 0) {
                LogOk(L"  originals restored");
            } else {
                LogWarn(L"  --restore exited with code " + std::to_wstring(exitCode));
            }
        } else {
            LogWarn(L"  " + runError);
        }

        LogStep(L"Removing the driver service and boot task");
        if (RunCaptured(cli, L"--uninstall --no-driver --no-network", output, exitCode, runError)) {
            LogBlock(output);
            if (exitCode == 0) {
                LogOk(L"  service and task removed");
            } else {
                LogWarn(L"  --uninstall exited with code " + std::to_wstring(exitCode));
            }
        } else {
            LogWarn(L"  " + runError);
        }
    } else {
        LogWarn(L"  hwidspoof-cli.exe is gone; skipping identity restore");
    }

    const std::wstring menuLink = StartMenuLink();
    const std::wstring desktopLink = DesktopLink();
    RemoveFile(menuLink);
    RemoveFile(desktopLink);
    LogOk(L"  shortcuts removed");

    if (RegDeleteTreeW(HKEY_LOCAL_MACHINE, kUninstallKey) == ERROR_SUCCESS) {
        LogOk(L"  Add/Remove Programs entry removed");
    } else {
        LogWarn(L"  Add/Remove Programs entry was already gone");
    }

    size_t leftovers = 0;
    RemoveDirectoryContents(directory, leftovers);
    if (!RemoveDirectoryW(directory.c_str())) {
        if (leftovers == 0) {
            ScheduleDirectoryCleanup(directory);
            LogWarn(L"  directory is still in use; it is removed at the next sign-in");
        } else {
            ScheduleDirectoryCleanup(directory);
            LogWarn(L"  " + std::to_wstring(leftovers) +
                    L" file(s) are held open; the directory is removed at the next sign-in");
        }
    } else {
        LogOk(L"  files removed");
    }

    LogStep(L"Uninstalled");

    /* The image this ran from is a temp copy outside the installation — either
       renamed there by the launcher or copied. It cannot delete itself while it
       runs, so the next boot finishes it. */
    const std::wstring self = g_tempSelf.empty() ? SelfPath() : g_tempSelf;
    if (!IsInside(self, directory)) {
        MoveFileExW(self.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

struct Layout {
    RECT card;
    RECT logCard;
    RECT logText;
    RECT shortcutRow;
    RECT driverRow;
    RECT installButton;
    RECT uninstallButton;
    RECT closeButton;
    RECT statusText;
    int lineHeight;
    int pad;
};

Layout ComputeLayout(const RECT& client)
{
    Layout layout{};
    const int width = client.right;
    const int height = client.bottom;
    layout.pad = S(26);

    layout.card.left = layout.pad;
    layout.card.top = S(86);
    layout.card.right = width - layout.pad;
    layout.card.bottom = layout.card.top + S(216);

    const int left = layout.card.left + S(18);
    layout.shortcutRow.left = left;
    layout.shortcutRow.top = layout.card.top + S(74);
    layout.shortcutRow.right = left + S(300);
    layout.shortcutRow.bottom = layout.shortcutRow.top + S(26);

    layout.driverRow.left = left;
    layout.driverRow.top = layout.card.top + S(106);
    layout.driverRow.right = left + S(360);
    layout.driverRow.bottom = layout.driverRow.top + S(26);

    layout.installButton.left = left;
    layout.installButton.top = layout.card.top + S(150);
    layout.installButton.right = left + S(180);
    layout.installButton.bottom = layout.installButton.top + S(44);

    layout.uninstallButton.left = layout.installButton.right + S(12);
    layout.uninstallButton.top = layout.installButton.top;
    layout.uninstallButton.right = layout.uninstallButton.left + S(150);
    layout.uninstallButton.bottom = layout.installButton.bottom;

    layout.logCard.left = layout.pad;
    layout.logCard.top = layout.card.bottom + S(14);
    layout.logCard.right = width - layout.pad;
    layout.logCard.bottom = height - S(66);

    layout.logText.left = layout.logCard.left + S(16);
    layout.logText.top = layout.logCard.top + S(38);
    layout.logText.right = layout.logCard.right - S(16);
    layout.logText.bottom = layout.logCard.bottom - S(12);
    layout.lineHeight = S(18);

    layout.closeButton.right = width - layout.pad;
    layout.closeButton.left = layout.closeButton.right - S(116);
    layout.closeButton.bottom = height - S(18);
    layout.closeButton.top = layout.closeButton.bottom - S(38);

    layout.statusText.left = layout.pad;
    layout.statusText.top = layout.closeButton.top;
    layout.statusText.right = layout.closeButton.left - S(16);
    layout.statusText.bottom = layout.closeButton.bottom;

    return layout;
}

/* ------------------------------------------------------------------ */
/* Painting                                                            */
/* ------------------------------------------------------------------ */

void FillRectColor(HDC dc, const RECT& rect, COLORREF color)
{
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

void RoundRectColor(HDC dc, const RECT& rect, int radius, COLORREF fill, COLORREF border)
{
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, oldPen);
    SelectObject(dc, oldBrush);
    DeleteObject(pen);
    DeleteObject(brush);
}

void DrawTextIn(HDC dc, const RECT& rect, const wchar_t* text, HFONT font, COLORREF color,
                UINT format)
{
    HGDIOBJ oldFont = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    RECT target = rect;
    DrawTextW(dc, text, -1, &target, format);
    SelectObject(dc, oldFont);
}

bool Contains(const RECT& rect, int x, int y)
{
    return x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom;
}

void PaintCheckbox(HDC dc, const RECT& row, const wchar_t* label, bool checked, bool hover)
{
    const RECT box{row.left, row.top + S(4), row.left + S(18), row.top + S(22)};
    if (checked) {
        RoundRectColor(dc, box, S(4), hover ? kAccentHover : kAccent, kAccent);
        HPEN pen = CreatePen(PS_SOLID, S(2), RGB(255, 255, 255));
        HGDIOBJ oldPen = SelectObject(dc, pen);
        MoveToEx(dc, box.left + S(4), box.top + S(9), nullptr);
        LineTo(dc, box.left + S(7), box.top + S(13));
        LineTo(dc, box.left + S(14), box.top + S(5));
        SelectObject(dc, oldPen);
        DeleteObject(pen);
    } else {
        RoundRectColor(dc, box, S(4), kPanelOff, hover ? kBorderHover : kBorder);
    }
    RECT labelRect{box.right + S(10), row.top, row.right, row.bottom};
    DrawTextIn(dc, labelRect, label, g_fontBody, kText, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

void PaintButton(HDC dc, const RECT& rect, const wchar_t* label, int id, bool primary, bool enabled)
{
    const bool hover = enabled && g_hover == id;
    const bool pressed = enabled && g_pressed == id;
    COLORREF fill = kPanel;
    COLORREF border = kBorder;
    COLORREF text = kText;

    if (primary) {
        fill = pressed ? kAccentPress : (hover ? kAccentHover : kAccent);
        border = fill;
        text = RGB(255, 255, 255);
    } else if (hover) {
        fill = kPanelHover;
        border = kBorderHover;
    }
    if (!enabled) {
        fill = kPanelOff;
        border = kBorder;
        text = kTextOff;
    }

    const int offset = pressed ? S(1) : 0;
    RECT box = rect;
    OffsetRect(&box, 0, offset);
    RoundRectColor(dc, box, S(10), fill, border);
    DrawTextIn(dc, box, label, g_fontButton, text, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

void PaintWindow(HWND window, HDC target)
{
    RECT client{};
    GetClientRect(window, &client);
    const Layout layout = ComputeLayout(client);

    HDC buffer = CreateCompatibleDC(target);
    HBITMAP bitmap = CreateCompatibleBitmap(target, client.right, client.bottom);
    HGDIOBJ oldBitmap = SelectObject(buffer, bitmap);

    FillRectColor(buffer, client, kBg);

    /* Header */
    RECT titleRect{S(layout.pad), S(18), client.right - S(190), S(52)};
    DrawTextIn(buffer, titleRect, HWID_PRODUCT_NAME_WIDE, g_fontTitle, kText,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    const std::wstring subtitle =
        L"Setup  " HWID_VERSION_WIDE L"   -   GUI, CLI and driver image";
    RECT subtitleRect{S(layout.pad), S(54), client.right - S(40), S(76)};
    DrawTextIn(buffer, subtitleRect, subtitle.c_str(), g_fontSmall, kTextDim,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    RECT badge{client.right - S(160), S(28), client.right - S(layout.pad), S(52)};
    RoundRectColor(buffer, badge, S(8), kPanel, kBorder);
    DrawTextIn(buffer, badge, g_installed ? L"INSTALLED" : L"NOT INSTALLED", g_fontSmall,
               g_installed ? kOk : kTextOff, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    /* Install card */
    RoundRectColor(buffer, layout.card, S(12), kPanel, kBorder);

    RECT caption{layout.card.left + S(18), layout.card.top + S(14), layout.card.right - S(18),
                 layout.card.top + S(36)};
    DrawTextIn(buffer, caption, L"Install location", g_fontSmall, kTextDim,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    const std::wstring directory = DefaultInstallDir();
    RECT pathRect{layout.card.left + S(18), layout.card.top + S(36), layout.card.right - S(18),
                  layout.card.top + S(62)};
    DrawTextIn(buffer, pathRect, directory.c_str(), g_fontBody, kText,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_PATH_ELLIPSIS);

    PaintCheckbox(buffer, layout.shortcutRow, L"Desktop shortcut", g_shortcutWanted,
                  g_hover == kIdShortcut);
    PaintCheckbox(buffer, layout.driverRow, L"Install driver image (storhlp.sys)", g_driverWanted,
                  g_hover == kIdDriver);

    PaintButton(buffer, layout.installButton, g_installed ? L"Repair install" : L"Install", kIdInstall,
                true, !g_busy);
    PaintButton(buffer, layout.uninstallButton, L"Uninstall", kIdUninstall, false,
                !g_busy && g_installed);

    /* Log card */
    RoundRectColor(buffer, layout.logCard, S(12), kPanelOff, kBorder);
    RECT logTitle{layout.logCard.left + S(16), layout.logCard.top + S(10),
                  layout.logCard.right - S(16), layout.logCard.top + S(32)};
    DrawTextIn(buffer, logTitle, L"Activity", g_fontSmall, kTextDim,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    std::vector<LogEntry> snapshot;
    if (g_logLockReady) {
        EnterCriticalSection(&g_logLock);
    }
    snapshot = g_log;
    if (g_logLockReady) {
        LeaveCriticalSection(&g_logLock);
    }

    const int available = layout.logText.bottom - layout.logText.top;
    const size_t visible =
        available > 0 ? static_cast<size_t>(available / layout.lineHeight) : 0;
    const size_t first = snapshot.size() > visible ? snapshot.size() - visible : 0;
    int y = layout.logText.top;
    for (size_t index = first; index < snapshot.size(); index++) {
        if (y + layout.lineHeight > layout.logText.bottom) {
            break;
        }
        RECT line{layout.logText.left, y, layout.logText.right, y + layout.lineHeight};
        DrawTextIn(buffer, line, snapshot[index].text.c_str(), g_fontMono, snapshot[index].color,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        y += layout.lineHeight;
    }

    DrawTextIn(buffer, layout.statusText, g_statusText.c_str(), g_fontSmall, g_statusColor,
               DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    PaintButton(buffer, layout.closeButton, g_busy ? L"Working" : L"Close", kIdClose, false,
                !g_busy);

    BitBlt(target, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);

    SelectObject(buffer, oldBitmap);
    DeleteObject(bitmap);
    DeleteDC(buffer);
}

void SetStatus(const std::wstring& text, COLORREF color)
{
    g_statusText = text;
    g_statusColor = color;
    if (g_window != nullptr) {
        InvalidateRect(g_window, nullptr, FALSE);
    }
}

/* ------------------------------------------------------------------ */
/* Job control                                                         */
/* ------------------------------------------------------------------ */

void JobFinished(bool ok, std::wstring* message)
{
    std::wstring text = message != nullptr ? *message : std::wstring();
    delete message;

    g_busy = false;
    if (ok) {
        g_installed = g_jobKind == 1;
        if (g_jobKind == 1 && !g_jobNote.empty()) {
            SetStatus(g_jobNote, kWarn);
        } else {
            SetStatus(g_jobKind == 1 ? L"Done. The app is in the Start Menu."
                                     : L"Removed. The machine is back to its own identity.",
                      kOk);
        }
    } else {
        SetStatus(text.empty() ? L"Failed - see the activity log." : text, kErr);
    }
    if (g_worker.joinable()) {
        g_worker.join();
    }
    InvalidateRect(g_window, nullptr, TRUE);
}

void StartJob(bool install)
{
    if (g_busy) {
        return;
    }
    g_busy = true;
    g_jobKind = install ? 1 : 2;
    g_jobNote.clear();
    g_hover = 0;
    g_pressed = 0;
    SetStatus(install ? L"Installing..." : L"Uninstalling...", kTextDim);
    InvalidateRect(g_window, nullptr, TRUE);

    if (g_worker.joinable()) {
        g_worker.join();
    }

    const std::wstring directory = DefaultInstallDir();
    const bool desktopShortcut = g_shortcutWanted;
    const bool driverImage = g_driverWanted;

    g_worker = std::thread([install, directory, desktopShortcut, driverImage]() {
        std::wstring error;
        bool ok = false;
        if (install) {
            ok = Install(directory, desktopShortcut, driverImage, error);
        } else {
            ok = Uninstall(directory, error);
        }
        PostMessageW(g_window, kMsgJobDone, ok ? 1 : 0,
                     reinterpret_cast<LPARAM>(new std::wstring(error)));
    });
}

/* ------------------------------------------------------------------ */
/* Window procedure                                                    */
/* ------------------------------------------------------------------ */

void OnMouseMove(HWND window, int x, int y)
{
    RECT client{};
    GetClientRect(window, &client);
    const Layout layout = ComputeLayout(client);

    int hover = 0;
    if (Contains(layout.installButton, x, y) && !g_busy) {
        hover = kIdInstall;
    } else if (Contains(layout.uninstallButton, x, y) && !g_busy && g_installed) {
        hover = kIdUninstall;
    } else if (Contains(layout.closeButton, x, y) && !g_busy) {
        hover = kIdClose;
    } else if (Contains(layout.shortcutRow, x, y)) {
        hover = kIdShortcut;
    } else if (Contains(layout.driverRow, x, y)) {
        hover = kIdDriver;
    }

    if (hover != g_hover) {
        g_hover = hover;
        InvalidateRect(window, nullptr, FALSE);

        TRACKMOUSEEVENT track{};
        track.cbSize = sizeof(track);
        track.dwFlags = TME_LEAVE;
        track.hwndTrack = window;
        TrackMouseEvent(&track);
    }
}

void OnClick(HWND window, int x, int y)
{
    RECT client{};
    GetClientRect(window, &client);
    const Layout layout = ComputeLayout(client);

    if (Contains(layout.installButton, x, y) && !g_busy) {
        StartJob(true);
        return;
    }
    if (Contains(layout.uninstallButton, x, y) && !g_busy && g_installed) {
        StartJob(false);
        return;
    }
    if (Contains(layout.closeButton, x, y) && !g_busy) {
        DestroyWindow(window);
        return;
    }
    if (Contains(layout.shortcutRow, x, y)) {
        g_shortcutWanted = !g_shortcutWanted;
        InvalidateRect(window, nullptr, FALSE);
        return;
    }
    if (Contains(layout.driverRow, x, y)) {
        g_driverWanted = !g_driverWanted;
        InvalidateRect(window, nullptr, FALSE);
    }
}

LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_CREATE: {
        g_window = window;
        const BOOL dark = TRUE;
        DwmSetWindowAttribute(window, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
        const COLORREF caption = kBg;
        DwmSetWindowAttribute(window, 35 /* DWMWA_CAPTION_COLOR */, &caption, sizeof(caption));
        const COLORREF border = kBorder;
        DwmSetWindowAttribute(window, 34 /* DWMWA_BORDER_COLOR */, &border, sizeof(border));
        if (g_autoStart == 1 || g_autoStart == 2) {
            PostMessageW(window, kMsgAutoStart, static_cast<WPARAM>(g_autoStart), 0);
        }
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        PaintWindow(window, dc);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_MOUSEMOVE:
        OnMouseMove(window, GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
        return 0;
    case WM_MOUSELEAVE:
        if (g_hover != 0) {
            g_hover = 0;
            InvalidateRect(window, nullptr, FALSE);
        }
        return 0;
    case WM_LBUTTONDOWN: {
        const int x = GET_X_LPARAM(lparam);
        const int y = GET_Y_LPARAM(lparam);
        RECT client{};
        GetClientRect(window, &client);
        const Layout layout = ComputeLayout(client);
        g_pressed = 0;
        if (Contains(layout.installButton, x, y)) {
            g_pressed = kIdInstall;
        } else if (Contains(layout.uninstallButton, x, y)) {
            g_pressed = kIdUninstall;
        } else if (Contains(layout.closeButton, x, y)) {
            g_pressed = kIdClose;
        }
        if (g_pressed != 0) {
            SetCapture(window);
            InvalidateRect(window, nullptr, FALSE);
        }
        return 0;
    }
    case WM_LBUTTONUP: {
        const int x = GET_X_LPARAM(lparam);
        const int y = GET_Y_LPARAM(lparam);
        if (GetCapture() == window) {
            ReleaseCapture();
        }
        const int pressed = g_pressed;
        g_pressed = 0;
        if (pressed != 0) {
            RECT client{};
            GetClientRect(window, &client);
            const Layout layout = ComputeLayout(client);
            RECT box{};
            if (pressed == kIdInstall) {
                box = layout.installButton;
            } else if (pressed == kIdUninstall) {
                box = layout.uninstallButton;
            } else {
                box = layout.closeButton;
            }
            if (Contains(box, x, y)) {
                OnClick(window, x, y);
            }
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }
        OnClick(window, x, y);
        return 0;
    }
    case WM_SETCURSOR: {
        if (LOWORD(lparam) == HTCLIENT && g_hover != 0 && g_hover != kIdShortcut &&
            g_hover != kIdDriver) {
            SetCursor(LoadCursorW(nullptr, IDC_HAND));
            return TRUE;
        }
        break;
    }
    case WM_KEYDOWN:
        if (wparam == VK_ESCAPE && !g_busy) {
            DestroyWindow(window);
            return 0;
        }
        break;
    case kMsgRepaint:
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    case kMsgJobDone:
        JobFinished(wparam != 0, reinterpret_cast<std::wstring*>(lparam));
        return 0;
    case kMsgAutoStart:
        g_autoStart = 0;
        StartJob(wparam == 1);
        return 0;
    case WM_CLOSE:
        if (g_busy) {
            return 0;
        }
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        if (g_worker.joinable()) {
            g_worker.join();
        }
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

/* ------------------------------------------------------------------ */
/* Entry                                                               */
/* ------------------------------------------------------------------ */

void PrintUsage()
{
    const std::wstring text =
        L"HWID Spoofer setup " HWID_VERSION_WIDE L"\n"
        L"\n"
        L"  hwidspoof-setup.exe                 open the installer\n"
        L"  hwidspoof-setup.exe /install        install, then keep the window open\n"
        L"  hwidspoof-setup.exe /uninstall      remove the installation\n"
        L"  hwidspoof-setup.exe /quiet          no window (use with /install or /uninstall)\n"
        L"  hwidspoof-setup.exe /dir=<path>     install somewhere other than Program Files\n"
        L"  hwidspoof-setup.exe /nodriver       leave storhlp.sys out of the install\n"
        L"  hwidspoof-setup.exe /nodesktop      skip the desktop shortcut\n";
    if (g_silent) {
        for (const std::wstring& line : SplitLines(text)) {
            LogLine(line, kText);
        }
        return;
    }
    MessageBoxW(nullptr, text.c_str(), L"HWID Spoofer Setup", MB_OK | MB_ICONINFORMATION);
}

bool RunHeadless(bool install, const std::wstring& directory)
{
    std::wstring error;
    bool ok = false;
    if (install) {
        ok = Install(directory, g_shortcutWanted, g_driverWanted, error);
    } else {
        ok = Uninstall(directory, error);
    }
    if (!ok) {
        LogError(error);
    }
    return ok;
}

/* The UI thread keeps an apartment for the shell helpers the window calls.
   Shortcut creation does not rely on it: CreateShortcut opens its own, because
   Install runs on the worker thread and apartments do not cross threads. */
struct ComScope {
    ComScope()
        : result(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE))
    {
    }
    ~ComScope()
    {
        if (SUCCEEDED(result)) {
            CoUninitialize();
        }
    }
    ComScope(const ComScope&) = delete;
    ComScope& operator=(const ComScope&) = delete;

    HRESULT result;
};

} // namespace

int wWinMain(HINSTANCE instance, HINSTANCE previous, wchar_t* commandLine, int showCommand)
{
    (void)previous;
    (void)commandLine;

    g_instance = instance;
    const ComScope com;
    (void)com;

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    bool uninstallMode = false;
    bool installRequested = false;
    bool quiet = false;
    bool help = false;
    /* Helper-process mode for CreateShortcutInChild: one clean apartment, one
       link, then out. Never reaches the window or the registry. */
    bool linkChild = false;
    std::wstring childLink;
    std::wstring childTarget;
    std::wstring childArguments;
    std::wstring childWorkDir;
    std::wstring childDescription;
    for (int index = 1; argv != nullptr && index < argc; index++) {
        const std::wstring arg = argv[index];
        if (_wcsicmp(arg.c_str(), L"/quiet") == 0 || _wcsicmp(arg.c_str(), L"/silent") == 0 ||
            _wcsicmp(arg.c_str(), L"/s") == 0 || _wcsicmp(arg.c_str(), L"-quiet") == 0) {
            quiet = true;
        } else if (_wcsicmp(arg.c_str(), L"/uninstall") == 0 ||
                   _wcsicmp(arg.c_str(), L"-uninstall") == 0) {
            uninstallMode = true;
        } else if (_wcsicmp(arg.c_str(), L"/install") == 0) {
            uninstallMode = false;
            installRequested = true;
        } else if (_wcsicmp(arg.c_str(), L"/nodriver") == 0) {
            g_driverWanted = false;
        } else if (_wcsicmp(arg.c_str(), L"/nodesktop") == 0) {
            g_shortcutWanted = false;
        } else if (_wcsicmp(arg.c_str(), L"/?") == 0 || _wcsicmp(arg.c_str(), L"/help") == 0 ||
                   _wcsicmp(arg.c_str(), L"-h") == 0) {
            help = true;
        } else if (arg.size() > 8 && _wcsnicmp(arg.c_str(), L"/mklink=", 8) == 0) {
            linkChild = true;
            childLink = arg.substr(8);
        } else if (arg.size() > 8 && _wcsnicmp(arg.c_str(), L"/target=", 8) == 0) {
            childTarget = arg.substr(8);
        } else if (arg.size() > 9 && _wcsnicmp(arg.c_str(), L"/workdir=", 9) == 0) {
            childWorkDir = arg.substr(9);
        } else if (arg.size() > 6 && _wcsnicmp(arg.c_str(), L"/desc=", 6) == 0) {
            childDescription = arg.substr(6);
        } else if (arg.size() > 6 && _wcsnicmp(arg.c_str(), L"/args=", 6) == 0) {
            childArguments = arg.substr(6);
        } else if (arg.size() > 5 && _wcsnicmp(arg.c_str(), L"/dir=", 5) == 0) {
            g_dirOverride = arg.substr(5);
            while (!g_dirOverride.empty() && (g_dirOverride.back() == L'\\' ||
                                              g_dirOverride.back() == L'"')) {
                g_dirOverride.pop_back();
            }
        } else if (arg.size() > 10 && _wcsnicmp(arg.c_str(), L"/tempcopy=", 10) == 0) {
            /* Set by the in-directory launcher after it renamed itself into
               %TEMP%, so the cleanup step knows which image to schedule. */
            g_tempSelf = arg.substr(10);
        }
    }
    if (argv != nullptr) {
        LocalFree(argv);
    }

    if (linkChild) {
        const HRESULT hr = CreateShortcutDirect(childLink, childTarget, childArguments, childWorkDir,
                                                childDescription);
        return SUCCEEDED(hr) ? 0 : 1;
    }

    InitializeCriticalSection(&g_logLock);
    g_logLockReady = true;

    HDC screen = GetDC(nullptr);
    g_dpi = screen != nullptr ? GetDeviceCaps(screen, LOGPIXELSX) : 96;
    if (screen != nullptr) {
        ReleaseDC(nullptr, screen);
    }
    if (g_dpi <= 0) {
        g_dpi = 96;
    }

    std::wstring existing;
    g_installed = InstalledDir(existing);

    if (help) {
        PrintUsage();
        return 0;
    }

    /* Uninstall runs from the copy inside the install directory, and Windows
       will not delete a running image. Rename it into %TEMP% first: a rename is
       permitted while the image runs, so the install directory is left with no
       locked file and can be removed completely — even with this process still
       waiting on the child. */
    if (uninstallMode) {
        const std::wstring self = SelfPath();
        std::wstring installed;
        if (InstalledDir(installed) && IsInside(self, installed)) {
            wchar_t tempPath[MAX_PATH]{};
            const DWORD length = GetTempPathW(MAX_PATH, tempPath);
            if (length > 0) {
                const std::wstring target =
                    Join(tempPath, L"hwidspoof-uninstall-" +
                                       std::to_wstring(GetCurrentProcessId()) + L".exe");
                const bool moved = MoveFileExW(self.c_str(), target.c_str(),
                                               MOVEFILE_REPLACE_EXISTING) != FALSE;
                if (moved || CopyFileW(self.c_str(), target.c_str(), FALSE)) {
                    std::wstring command = L"\"" + target + L"\" /uninstall /tempcopy=\"" + target + L"\"";
                    if (quiet) {
                        command += L" /quiet";
                    }
                    STARTUPINFOW startup{};
                    startup.cb = sizeof(startup);
                    PROCESS_INFORMATION process{};
                    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
                    mutableCommand.push_back(L'\0');
                    if (CreateProcessW(target.c_str(), mutableCommand.data(), nullptr, nullptr,
                                       FALSE, 0, nullptr, nullptr, &startup, &process)) {
                        CloseHandle(process.hThread);
                        if (quiet) {
                            /* A scripted uninstall wants the real exit code,
                               not "started". Safe to wait now: this image no
                               longer sits inside the directory being removed. */
                            WaitForSingleObject(process.hProcess, INFINITE);
                            DWORD code = 1;
                            GetExitCodeProcess(process.hProcess, &code);
                            CloseHandle(process.hProcess);
                            return static_cast<int>(code);
                        }
                        CloseHandle(process.hProcess);
                        return 0;
                    }
                }
            }
        }
    }

    if (quiet) {
        g_silent = true;
        g_silentLog = SilentLogPath();
        AttachConsole(ATTACH_PARENT_PROCESS);
        SetConsoleOutputCP(CP_UTF8);
        /* A GUI-subsystem image has no stdout until one is attached or
           inherited; without this, /quiet from a script prints nothing. */
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        if (out == nullptr || out == INVALID_HANDLE_VALUE) {
            HANDLE console =
                CreateFileW(L"CONOUT$", GENERIC_WRITE | GENERIC_READ,
                            FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (console != INVALID_HANDLE_VALUE) {
                SetStdHandle(STD_OUTPUT_HANDLE, console);
            }
        }
        const std::wstring directory = DefaultInstallDir();
        LogStep(std::wstring(HWID_PRODUCT_NAME_WIDE) + L" " + HWID_VERSION_WIDE);
        LogLine(L"  log: " + g_silentLog, kTextDim);
        const bool ok = RunHeadless(!uninstallMode, directory);
        if (ok) {
            LogOk(L"Success");
        }
        return ok ? 0 : 1;
    }

    /* Interactive shell. A bare double-click opens the window idle; the
       Add/Remove Programs uninstall string starts the job by itself. */
    g_autoStart = uninstallMode ? 2 : (installRequested ? 1 : 0);
    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = WindowProc;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    windowClass.hIconSm = windowClass.hIcon;
    windowClass.hbrBackground = nullptr;
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass)) {
        return 1;
    }

    RECT frame{0, 0, S(660), S(540)};
    AdjustWindowRectEx(&frame, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE, 0);
    const int width = frame.right - frame.left;
    const int height = frame.bottom - frame.top;

    HWND window = CreateWindowExW(0, kWindowClass, L"HWID Spoofer Setup",
                                  WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                                  CW_USEDEFAULT, CW_USEDEFAULT, width, height, nullptr, nullptr,
                                  instance, nullptr);
    if (window == nullptr) {
        return 1;
    }

    g_fontTitle = CreateFontW(-S(27), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    g_fontBody = CreateFontW(-S(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    g_fontSmall = CreateFontW(-S(13), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    g_fontButton = CreateFontW(-S(15), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                               OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               VARIABLE_PITCH | FF_SWISS, L"Segoe UI");
    g_fontMono = CreateFontW(-S(13), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");

    SetStatus(g_installed ? L"An installation is present. Repair or remove it."
                          : L"Ready. Nothing is applied until you run the app.",
              kTextDim);

    ShowWindow(window, showCommand == SW_SHOWMAXIMIZED ? SW_SHOWMAXIMIZED : SW_SHOW);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    if (g_worker.joinable()) {
        g_worker.join();
    }

    DeleteObject(g_fontTitle);
    DeleteObject(g_fontBody);
    DeleteObject(g_fontSmall);
    DeleteObject(g_fontButton);
    DeleteObject(g_fontMono);
    DeleteCriticalSection(&g_logLock);
    g_logLockReady = false;
    return 0;
}
