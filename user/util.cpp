#include "util.h"

#include <bcrypt.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <atomic>
#include <fstream>
#include <mutex>
#include <sstream>
#include <vector>

namespace util {
namespace {

std::mutex g_logMutex;
std::ofstream g_logFile;
bool g_verbose = false;
LogSink g_sink;
std::atomic<bool> g_reveal{false};

const wchar_t* LevelPrefix(Level level)
{
    switch (level) {
    case Level::Step:
        return L"[*]";
    case Level::Ok:
        return L"[+]";
    case Level::Warn:
        return L"[!]";
    case Level::Error:
        return L"[-]";
    case Level::Info:
        return L"   ";
    }
    return L"   ";
}

std::wstring Timestamp()
{
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t buffer[16]{};
    swprintf_s(buffer, L"%02u:%02u:%02u", now.wHour, now.wMinute, now.wSecond);
    return buffer;
}

void WriteLogLine(const std::wstring& text)
{
    if (!g_logFile.is_open()) {
        return;
    }
    const std::string utf8 = ToUtf8(text);
    g_logFile.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
    g_logFile.put('\n');
    g_logFile.flush();
}

} // namespace

void SetVerbose(bool enabled)
{
    g_verbose = enabled;
}

bool Verbose()
{
    return g_verbose;
}

void SetLogFile(const std::wstring& path)
{
    std::lock_guard<std::mutex> guard(g_logMutex);
    g_logFile.close();
    g_logFile.open(path, std::ios::out | std::ios::app | std::ios::binary);
}

void SetLogSink(LogSink sink)
{
    std::lock_guard<std::mutex> guard(g_logMutex);
    g_sink = std::move(sink);
}

void Log(Level level, const std::wstring& message)
{
    std::lock_guard<std::mutex> guard(g_logMutex);
    const std::wstring line = Timestamp() + L" " + LevelPrefix(level) + L" " + message;
    if (g_sink) {
        /* GUI owns the sink; it must not block the worker for long. */
        g_sink(line);
    } else {
        std::wprintf(L"%ls\n", line.c_str());
    }
    WriteLogLine(line);
}

void Logf(Level level, const wchar_t* format, ...)
{
    wchar_t buffer[2048]{};
    va_list args;
    va_start(args, format);
    _vsnwprintf_s(buffer, _countof(buffer), _TRUNCATE, format, args);
    va_end(args);
    Log(level, buffer);
}

std::wstring ExePath()
{
    std::vector<wchar_t> buffer(MAX_PATH);
    for (;;) {
        const DWORD copied = GetModuleFileNameW(nullptr, buffer.data(),
                                               static_cast<DWORD>(buffer.size()));
        if (copied == 0) {
            return L"";
        }
        if (copied < buffer.size() - 1) {
            return std::wstring(buffer.data(), copied);
        }
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) {
            break;
        }
    }
    return L"";
}

std::wstring ExeDirectory()
{
    const std::wstring path = ExePath();
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L".";
    }
    return path.substr(0, slash);
}

std::wstring JoinPath(const std::wstring& directory, const std::wstring& name)
{
    if (directory.empty()) {
        return name;
    }
    wchar_t last = directory.back();
    if (last == L'\\' || last == L'/') {
        return directory + name;
    }
    return directory + L"\\" + name;
}

bool FileExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::string ToUtf8(const std::wstring& text)
{
    if (text.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0, nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), needed, nullptr, nullptr);
    return result;
}

std::wstring ToWide(const std::string& text)
{
    if (text.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, text.data(),
                                           static_cast<int>(text.size()),
                                           nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), needed);
    return result;
}

std::string ToLowerAscii(std::string text)
{
    for (char& ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

std::string TrimAscii(std::string text)
{
    const auto whitespace = [](unsigned char ch) {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };
    size_t begin = 0;
    while (begin < text.size() && whitespace(static_cast<unsigned char>(text[begin]))) {
        begin++;
    }
    size_t end = text.size();
    while (end > begin && whitespace(static_cast<unsigned char>(text[end - 1]))) {
        end--;
    }
    return text.substr(begin, end - begin);
}

bool SameId(const std::wstring& left, const std::wstring& right)
{
    const auto normalize = [](const std::wstring& text) {
        std::wstring result;
        result.reserve(text.size());
        for (wchar_t ch : text) {
            /* Windows writes GUIDs with braces in some keys and without in
               others; the identifier is the bytes, not the decoration. */
            if (ch == L'{' || ch == L'}' || ch == L' ' || ch == L'\t') {
                continue;
            }
            if (ch == L'_') {
                ch = L'-';
            } else if (ch >= L'A' && ch <= L'Z') {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
            result.push_back(ch);
        }
        return result;
    };
    return normalize(left) == normalize(right);
}

void SetReveal(bool enabled)
{
    g_reveal.store(enabled, std::memory_order_relaxed);
}

bool Reveal()
{
    return g_reveal.load(std::memory_order_relaxed);
}

std::wstring RealTag()
{
    return Reveal() ? std::wstring(L"[real]") : std::wstring(L"[real, masked]");
}

std::wstring Redact(const std::wstring& value)
{
    if (Reveal()) {
        return value.empty() ? std::wstring(L"<none>") : value;
    }

    std::wstring masked = value;
    bool hasContent = false;
    for (wchar_t& ch : masked) {
        const bool alphanumeric =
            (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'z') ||
            (ch >= L'A' && ch <= L'Z') || ch > 0x7F;
        if (alphanumeric) {
            ch = L'*';
            hasContent = true;
        }
    }
    return hasContent ? masked : std::wstring(L"<none>");
}

std::wstring RedactHex32(uint32_t value)
{
    wchar_t text[16]{};
    swprintf_s(text, L"%08lX", value);
    return Redact(text);
}

std::wstring FormatWin32Error(DWORD error)
{    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::wstring message;
    if (length != 0 && buffer != nullptr) {
        message.assign(buffer, length);
        LocalFree(buffer);
        while (!message.empty() &&
               (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
            message.pop_back();
        }
    }

    wchar_t code[32]{};
    swprintf_s(code, _countof(code), L"0x%08X", error);
    if (message.empty()) {
        return code;
    }
    return message + L" (" + code + L")";
}

bool IsElevated()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const bool elevated =
        GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE &&
        elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

int RelaunchElevated(const std::wstring& arguments)
{
    const std::wstring exe = ExePath();
    if (exe.empty()) {
        return -1;
    }

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    info.lpFile = exe.c_str();
    info.lpParameters = arguments.empty() ? nullptr : arguments.c_str();
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info)) {
        Logf(Level::Error, L"Elevation failed: %ls", FormatWin32Error(GetLastError()).c_str());
        return -1;
    }
    if (info.hProcess == nullptr) {
        return -1;
    }

    WaitForSingleObject(info.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(info.hProcess, &exitCode);
    CloseHandle(info.hProcess);
    return static_cast<int>(exitCode);
}

bool RelaunchElevatedDetached(const std::wstring& arguments)
{
    const std::wstring exe = ExePath();
    if (exe.empty()) {
        return false;
    }

    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_FLAG_NO_UI;
    info.lpVerb = L"runas";
    info.lpFile = exe.c_str();
    info.lpParameters = arguments.empty() ? nullptr : arguments.c_str();
    info.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&info)) {
        Logf(Level::Error, L"Elevation failed: %ls", FormatWin32Error(GetLastError()).c_str());
        return false;
    }
    return true;
}

bool EnablePrivilege(const wchar_t* name)
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    SetLastError(ERROR_SUCCESS);
    const BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges),
                                                 nullptr, nullptr);
    const DWORD error = GetLastError();
    CloseHandle(token);
    return adjusted != FALSE && error == ERROR_SUCCESS;
}

bool RebootNow(std::wstring& error)
{
    error.clear();
    if (!EnablePrivilege(SE_SHUTDOWN_NAME)) {
        error = L"Cannot enable SE_SHUTDOWN_NAME: " + FormatWin32Error(GetLastError());
        return false;
    }

    /*
     * Five seconds of grace so the MessageBox is off the screen and any log
     * flush lands before the machine goes down. Forced close because a stray
     * game process must not hold the reboot hostage.
     */
    if (!InitiateSystemShutdownExW(nullptr, const_cast<wchar_t*>(L"Applying the spoofed identity"),
                                   5, TRUE, TRUE,
                                   SHTDN_REASON_MAJOR_SOFTWARE | SHTDN_REASON_MINOR_RECONFIG |
                                       SHTDN_REASON_FLAG_PLANNED)) {
        error = L"Reboot request failed: " + FormatWin32Error(GetLastError());
        return false;
    }
    return true;
}

bool SecureBootEnabled()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0,
                      KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LONG result =
        RegQueryValueExW(key, L"UEFISecureBootEnabled", nullptr, &type,
                         reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);
    return result == ERROR_SUCCESS && type == REG_DWORD && value != 0;
}

bool TestSigningEnabled()
{
    /*
     * Boot configuration cannot be read back through bcdedit without a
     * process launch, and a stale BCD read is worse than the live answer.
     * SystemCodeIntegrityInformation reports the running policy directly.
     */
    using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return false;
    }
    const auto query = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    if (query == nullptr) {
        return false;
    }

    struct IntegrityInformation {
        ULONG length;
        ULONG options;
    };
    constexpr ULONG kSystemCodeIntegrityInformation = 103;
    constexpr ULONG kOptionTestSign = 0x00000002;

    IntegrityInformation info{sizeof(info), 0};
    const LONG status = query(kSystemCodeIntegrityInformation, &info, sizeof(info), nullptr);
    return status >= 0 && (info.options & kOptionTestSign) != 0;
}

bool MemoryIntegrityEnabled()
{
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                      L"HypervisorEnforcedCodeIntegrity",
                      0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
        return false;
    }

    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;
    const LONG result = RegQueryValueExW(key, L"Enabled", nullptr, &type,
                                         reinterpret_cast<LPBYTE>(&value), &size);
    RegCloseKey(key);
    return result == ERROR_SUCCESS && type == REG_DWORD && value != 0;
}

namespace {

std::wstring CertificateSubject(PCCERT_CONTEXT certificate)
{
    if (certificate == nullptr) {
        return {};
    }
    const DWORD length = CertNameToStrW(X509_ASN_ENCODING, &certificate->pCertInfo->Subject,
                                        CERT_X500_NAME_STR, nullptr, 0);
    if (length <= 1) {
        return {};
    }
    std::wstring text(length, L'\0');
    const DWORD written = CertNameToStrW(X509_ASN_ENCODING, &certificate->pCertInfo->Subject,
                                         CERT_X500_NAME_STR, text.data(), length);
    if (written <= 1) {
        return {};
    }
    text.resize(static_cast<size_t>(written) - 1);
    return text;
}

bool LooksLikeMicrosoftRoot(const std::wstring& authority)
{
    if (authority.empty()) {
        return false;
    }
    std::wstring lower = authority;
    CharLowerBuffW(lower.data(), static_cast<DWORD>(lower.size()));
    return lower.find(L"microsoft root certificate authority") != std::wstring::npos;
}

/*
 * CERT_FIND_SUBJECT_CERT answers CRYPT_E_NOT_FOUND on embedded PE signatures
 * even when the store holds the signer, so the match is done by hand:
 * serial number plus issuer, which is the pair CMSG_SIGNER_INFO identifies.
 */
PCCERT_CONTEXT FindSignerCertificate(HCERTSTORE store, const CMSG_SIGNER_INFO* signer)
{
    PCCERT_CONTEXT walk = nullptr;
    while ((walk = CertEnumCertificatesInStore(store, walk)) != nullptr) {
        const CERT_INFO* info = walk->pCertInfo;
        const bool sameSerial =
            info->SerialNumber.cbData == signer->SerialNumber.cbData &&
            memcmp(info->SerialNumber.pbData, signer->SerialNumber.pbData,
                   signer->SerialNumber.cbData) == 0;
        if (sameSerial &&
            CertCompareCertificateName(X509_ASN_ENCODING,
                                       const_cast<PCERT_NAME_BLOB>(&info->Issuer),
                                       const_cast<PCERT_NAME_BLOB>(&signer->Issuer))) {
            /* Enumeration frees the previous entry, so hand back a duplicate. */
            PCCERT_CONTEXT match = CertDuplicateCertificateContext(walk);
            (VOID)CertEnumCertificatesInStore(store, walk);
            return match;
        }
    }
    return nullptr;
}

} // namespace

DriverSignature InspectSignature(const std::wstring& path)
{
    DriverSignature signature;
    if (path.empty() || !FileExists(path)) {
        return signature;
    }

    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG verdict = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    (VOID)WinVerifyTrust(nullptr, &action, &data);
    if (verdict != ERROR_SUCCESS) {
        return signature;
    }
    signature.valid = true;

    HCERTSTORE store = nullptr;
    HCRYPTMSG message = nullptr;
    DWORD encoding = 0;
    DWORD content = 0;
    DWORD format = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format,
                          &store, &message, nullptr)) {
        return signature;
    }

    DWORD size = 0;
    if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &size) && size > 0) {
        std::vector<uint8_t> buffer(size);
        if (CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, buffer.data(), &size)) {
            auto* signer = reinterpret_cast<CMSG_SIGNER_INFO*>(buffer.data());
            PCCERT_CONTEXT leaf = FindSignerCertificate(store, signer);
            if (leaf != nullptr) {
                signature.subject = CertificateSubject(leaf);

                /*
                 * The subject alone can say "Microsoft" on a cert the machine
                 * minted itself. The root of the validated chain is the part
                 * firmware will accept, so that is what decides.
                 */
                CERT_CHAIN_PARA parameters{};
                parameters.cbSize = sizeof(parameters);
                PCCERT_CHAIN_CONTEXT chain = nullptr;
                if (CertGetCertificateChain(nullptr, leaf, nullptr, nullptr, &parameters,
                                            CERT_CHAIN_CACHE_END_CERT, nullptr, &chain)) {
                    if (chain->cChain > 0) {
                        const CERT_SIMPLE_CHAIN* simple = chain->rgpChain[0];
                        if (simple->cElement > 0) {
                            const PCCERT_CONTEXT root =
                                simple->rgpElement[simple->cElement - 1]->pCertContext;
                            signature.authority = CertificateSubject(root);
                            signature.microsoft = LooksLikeMicrosoftRoot(signature.authority);
                        }
                    }
                    CertFreeCertificateChain(chain);
                }
                CertFreeCertificateContext(leaf);
            }
        }
    }

    if (message != nullptr) {
        CryptMsgClose(message);
    }
    if (store != nullptr) {
        CertCloseStore(store, 0);
    }
    return signature;
}

uint64_t RandomU64()
{
    uint64_t value = 0;
    const NTSTATUS status = BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&value),
                                            sizeof(value), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        LARGE_INTEGER counter{};
        QueryPerformanceCounter(&counter);
        value = static_cast<uint64_t>(counter.QuadPart) ^
                (static_cast<uint64_t>(GetTickCount64()) << 17) ^
                reinterpret_cast<uintptr_t>(&value);
    }
    return value;
}

std::string HexEncode(const std::vector<uint8_t>& bytes)
{
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0F]);
    }
    return result;
}

std::vector<uint8_t> HexDecode(const std::string& hex)
{
    const auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }
        return -1;
    };

    if ((hex.size() % 2) != 0) {
        return {};
    }
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t index = 0; index < hex.size(); index += 2) {
        const int high = nibble(hex[index]);
        const int low = nibble(hex[index + 1]);
        if (high < 0 || low < 0) {
            return {};
        }
        result.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return result;
}

bool WriteAllBytes(const std::wstring& path, const std::vector<uint8_t>& bytes)
{
    std::ofstream file(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    if (!bytes.empty()) {
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    return file.good();
}

bool ReadAllBytes(const std::wstring& path, std::vector<uint8_t>& bytes)
{
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0) {
        return false;
    }
    file.seekg(0, std::ios::beg);
    bytes.assign(static_cast<size_t>(size), 0);
    if (size != 0) {
        file.read(reinterpret_cast<char*>(bytes.data()), size);
    }
    return file.good();
}

std::vector<uint8_t> ProtectForUser(const std::vector<uint8_t>& plain)
{
    if (plain.empty() || plain.size() > MAXDWORD) {
        return {};
    }
    DATA_BLOB input{static_cast<DWORD>(plain.size()), const_cast<BYTE*>(plain.data())};
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"hwidspoof identity snapshot", nullptr, nullptr, nullptr, 0,
                          &output)) {
        return {};
    }
    std::vector<uint8_t> blob(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return blob;
}

bool UnprotectForUser(const std::vector<uint8_t>& blob, std::vector<uint8_t>& plain)
{
    plain.clear();
    if (blob.empty() || blob.size() > MAXDWORD) {
        return false;
    }
    DATA_BLOB input{static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data())};
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
        return false;
    }
    plain.assign(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return true;
}

UniqueHandle::~UniqueHandle()
{
    reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.handle_)
{
    other.handle_ = nullptr;
}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept
{
    if (this != &other) {
        reset(other.handle_);
        other.handle_ = nullptr;
    }
    return *this;
}

HANDLE* UniqueHandle::put()
{
    reset();
    return &handle_;
}

void UniqueHandle::reset(HANDLE handle)
{
    if (valid()) {
        CloseHandle(handle_);
    }
    handle_ = handle;
}

UniqueKey::~UniqueKey()
{
    reset();
}

UniqueKey::UniqueKey(UniqueKey&& other) noexcept : key_(other.key_)
{
    other.key_ = nullptr;
}

UniqueKey& UniqueKey::operator=(UniqueKey&& other) noexcept
{
    if (this != &other) {
        reset(other.key_);
        other.key_ = nullptr;
    }
    return *this;
}

HKEY* UniqueKey::put()
{
    reset();
    return &key_;
}

void UniqueKey::reset(HKEY key)
{
    if (key_ != nullptr) {
        RegCloseKey(key_);
    }
    key_ = key;
}

std::wstring QuoteArg(const std::wstring& arg)
{
    if (arg.empty()) {
        return L"\"\"";
    }
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return arg;
    }

    std::wstring result;
    result.push_back(L'"');
    size_t backslashes = 0;
    for (wchar_t ch : arg) {
        if (ch == L'\\') {
            backslashes++;
            continue;
        }
        if (ch == L'"') {
            result.append(backslashes + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(ch);
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'"');
    return result;
}

} // namespace util
