#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace util {

enum class Level {
    Step,
    Ok,
    Warn,
    Error,
    Info
};

using LogSink = std::function<void(const std::wstring& line)>;

void SetVerbose(bool enabled);
bool Verbose();

void SetLogFile(const std::wstring& path);
/* Routes log lines somewhere other than stdout. Empty sink restores stdout. */
void SetLogSink(LogSink sink);
void Log(Level level, const std::wstring& message);
void Logf(Level level, const wchar_t* format, ...);

std::wstring ExePath();
std::wstring ExeDirectory();
std::wstring JoinPath(const std::wstring& directory, const std::wstring& name);
bool FileExists(const std::wstring& path);

std::string ToUtf8(const std::wstring& text);
std::wstring ToWide(const std::string& text);
std::string ToLowerAscii(std::string text);
std::string TrimAscii(std::string text);
std::wstring FormatWin32Error(DWORD error);

/* Case-insensitive compare for identifiers; '-' and '_' are the same. */
bool SameId(const std::wstring& left, const std::wstring& right);

/*
 * Display masking for live hardware values. Every surface this tool reports
 * may still be the machine's real identity (driver not loaded, reboot
 * pending, value lives in firmware we cannot reach). Keeping separators and
 * length lets the reader see the shape; every alphanumeric character becomes
 * '*' so nothing identifying survives a shared log.
 */
std::wstring Redact(const std::wstring& value);
std::wstring RedactHex32(uint32_t value);

/*
 * Reveal switch for the masking rule above. Off by default, and the only way
 * it turns on is an explicit ask: --reveal on the CLI, the "reveal real
 * values" tick in the GUI. While it is on, Redact() returns the value
 * unchanged, so the log holds clear text — the caller is responsible for
 * saying so when it prints.
 */
void SetReveal(bool enabled);
bool Reveal();

/*
 * Wording for a line that carries a live value: "real, masked" when the value
 * is stars, "real" when reveal printed it. A fixed label would either lie about
 * clear text or lie about the masking, and the log is the thing people paste.
 */
std::wstring RealTag();

bool IsElevated();
/* Blocks until the elevated copy exits and returns its code, or -1. */
int RelaunchElevated(const std::wstring& arguments);
/* Fire and forget: the GUI must not linger as a ghost parent for a whole session. */
bool RelaunchElevatedDetached(const std::wstring& arguments);
bool EnablePrivilege(const wchar_t* name);
/*
 * Firmware state. Secure Boot enforces the Microsoft signature policy at
 * boot: a locally signed image is refused and bcdedit will not turn test
 * signing on. This tool never changes that policy.
 */
bool SecureBootEnabled();
bool TestSigningEnabled();
bool MemoryIntegrityEnabled();

struct DriverSignature {
    bool valid = false;          // chain verifies against the local trust store
    bool microsoft = false;      // chain terminates in a Microsoft root
    std::wstring subject;        // signing certificate, one line
    std::wstring authority;      // chain root, one line
};

/*
 * Verifies the Authenticode signature on a PE without network access and
 * reports who signed it. A test-signed image returns valid=true with a
 * non-Microsoft authority: it loads only while test signing is enabled.
 */
DriverSignature InspectSignature(const std::wstring& path);
/*
 * Reboots after a short delay. Used to land registry/hostname/volume changes
 * that only settle on boot. Requires elevation; caller confirms first.
 */
bool RebootNow(std::wstring& error);

uint64_t RandomU64();
std::string HexEncode(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> HexDecode(const std::string& hex);

bool WriteAllBytes(const std::wstring& path, const std::vector<uint8_t>& bytes);
bool ReadAllBytes(const std::wstring& path, std::vector<uint8_t>& bytes);

/*
 * DPAPI for the current user. Snapshots that hold the machine's true
 * identifiers are sealed at rest so a copied folder does not hand them over;
 * another account cannot unseal them.
 */
std::vector<uint8_t> ProtectForUser(const std::vector<uint8_t>& plain);
bool UnprotectForUser(const std::vector<uint8_t>& blob, std::vector<uint8_t>& plain);

class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(HANDLE handle) : handle_(handle) {}
    ~UniqueHandle();

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    HANDLE get() const { return handle_; }
    HANDLE* put();
    bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }
    void reset(HANDLE handle = nullptr);

private:
    HANDLE handle_ = nullptr;
};

class UniqueKey {
public:
    UniqueKey() = default;
    explicit UniqueKey(HKEY key) : key_(key) {}
    ~UniqueKey();

    UniqueKey(const UniqueKey&) = delete;
    UniqueKey& operator=(const UniqueKey&) = delete;

    UniqueKey(UniqueKey&& other) noexcept;
    UniqueKey& operator=(UniqueKey&& other) noexcept;

    HKEY get() const { return key_; }
    HKEY* put();
    bool valid() const { return key_ != nullptr; }
    void reset(HKEY key = nullptr);

private:
    HKEY key_ = nullptr;
};

std::wstring QuoteArg(const std::wstring& arg);

} // namespace util
