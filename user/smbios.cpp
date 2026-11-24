#include "smbios.h"

#include "registry.h"
#include "util.h"

#include <cstring>

namespace smbios {
namespace {

constexpr wchar_t kDataKey[] = L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data";
constexpr wchar_t kValueName[] = L"SMBiosData";
constexpr wchar_t kTaskName[] = L"HWID Spoofer Reapply";

/*
 * The originals hold the machine's true firmware strings. They are sealed with
 * DPAPI for the current user, same rule as the registry backup: another
 * account cannot read them.
 */
constexpr char kMagic[8] = {'H', 'W', 'S', 'M', 'B', 'I', 'O', '1'};
constexpr uint32_t kFormat = 1;
constexpr uint32_t kOwned = 1u << 0;

constexpr size_t kMaxStructures = 512;
constexpr size_t kMaxStrings = 256;
constexpr size_t kMaxStringLength = 1024;
constexpr size_t kStartWindow = 256;

struct Structure {
    uint8_t type = 0;
    std::vector<uint8_t> formatted;
    std::vector<std::string> strings;
};

struct Table {
    std::vector<uint8_t> prefix; // header bytes mssmbios puts before the table
    std::vector<Structure> structures;
    std::vector<uint8_t> suffix; // bytes after the terminating type 127
};

/*
 * Locate the first plausible SMBIOS structure. mssmbios sometimes stores the
 * table behind an 8-byte header; that header looks like a type-0 structure
 * with an impossible length, so four chained structures with terminated
 * string sets is what tells the two apart.
 */
size_t FindStart(const std::vector<uint8_t>& data)
{
    if (data.size() < 8) {
        return data.size();
    }
    const size_t limit = data.size() < kStartWindow ? data.size() : kStartWindow;
    for (size_t offset = 0; offset + 4 <= limit; offset++) {
        if (data[offset] != 0) {
            continue;
        }
        if (data[offset + 1] < 0x12 || data[offset + 1] > 0x40) {
            continue;
        }
        size_t cursor = offset;
        bool valid = true;
        for (int step = 0; step < 4; step++) {
            if (cursor + 4 > data.size()) {
                valid = false;
                break;
            }
            const size_t length = data[cursor + 1];
            if (length < 4 || cursor + length > data.size()) {
                valid = false;
                break;
            }
            size_t next = cursor + length;
            while (next + 1 < data.size() && !(data[next] == 0 && data[next + 1] == 0)) {
                next++;
            }
            if (next + 1 >= data.size()) {
                valid = false;
                break;
            }
            cursor = next + 2;
        }
        if (valid) {
            return offset;
        }
    }
    return data.size();
}

bool AllZero(const std::vector<uint8_t>& data, size_t begin)
{
    for (size_t index = begin; index < data.size(); index++) {
        if (data[index] != 0) {
            return false;
        }
    }
    return true;
}

/*
 * Splits the raw value into structures. Every consumer reads the table by
 * walking it, so parsing it is also the check that a rewrite is safe: a table
 * that does not parse is refused, never patched blind.
 */
bool ParseTable(const std::vector<uint8_t>& data, size_t start, Table& table,
                std::wstring& error)
{
    table.prefix.assign(data.data(), data.data() + start);
    size_t cursor = start;

    while (cursor < data.size()) {
        if (AllZero(data, cursor)) {
            table.suffix.assign(data.data() + cursor, data.data() + data.size());
            break;
        }
        if (table.structures.size() >= kMaxStructures) {
            error = L"SMBIOS table has more than 512 structures";
            return false;
        }
        if (cursor + 4 > data.size()) {
            error = L"SMBIOS table ends mid-structure";
            return false;
        }

        const uint8_t type = data[cursor];
        const size_t formattedLength = data[cursor + 1];
        if (formattedLength < 4 || cursor + formattedLength > data.size()) {
            error = L"SMBIOS structure length is out of range";
            return false;
        }

        Structure structure;
        structure.type = type;
        structure.formatted.assign(data.data() + cursor, data.data() + cursor + formattedLength);

        const size_t stringsBegin = cursor + formattedLength;
        size_t scan = stringsBegin;
        while (scan + 1 < data.size() && !(data[scan] == 0 && data[scan + 1] == 0)) {
            scan++;
        }
        if (scan + 1 >= data.size()) {
            error = L"SMBIOS string set is unterminated";
            return false;
        }

        size_t position = stringsBegin;
        while (position < scan) {
            size_t end = position;
            while (end < scan && data[end] != 0) {
                end++;
            }
            if (structure.strings.size() >= kMaxStrings || end - position > kMaxStringLength) {
                error = L"SMBIOS string set is oversized";
                return false;
            }
            structure.strings.emplace_back(
                reinterpret_cast<const char*>(data.data()) + position, end - position);
            position = end + 1;
        }

        table.structures.push_back(std::move(structure));
        cursor = scan + 2;

        if (type == 127) {
            table.suffix.assign(data.data() + cursor, data.data() + data.size());
            break;
        }
    }

    if (table.structures.empty()) {
        error = L"SMBIOS table has no structures";
        return false;
    }
    return true;
}

/*
 * Rebuilds the value from the parsed table. Strings take their replacement
 * length: SMBIOS is self-describing, structure offsets are not stored, so a
 * longer vendor string is legal and does not shift anything a consumer can
 * observe. Padding to the original length would truncate "Micro-Star
 * International Co., Ltd." into "ASRock"'s six bytes, which reads as damage.
 */
std::vector<uint8_t> Serialize(const Table& table, size_t& terminator)
{
    std::vector<uint8_t> image = table.prefix;
    terminator = 0;

    for (const Structure& structure : table.structures) {
        const size_t offset = image.size();
        image.insert(image.end(), structure.formatted.begin(), structure.formatted.end());
        for (const std::string& text : structure.strings) {
            image.insert(image.end(), text.begin(), text.end());
            image.push_back(0);
        }
        image.push_back(0);
        if (structure.strings.empty()) {
            /* No strings: the set is still terminated by two NUL bytes. */
            image.push_back(0);
        }
        /*
         * Type 127 carries the structure-table checksum at offset 0x04, but a
         * short type-127 (length 4) has no room for it and the next byte is
         * the string-set terminator. Only reseal when the byte exists.
         */
        if (structure.type == 127 && structure.formatted.size() >= 5) {
            terminator = offset;
        }
    }

    image.insert(image.end(), table.suffix.begin(), table.suffix.end());
    return image;
}

/* Type 127 carries the structure-table checksum; reseal it after a rewrite. */
void ResealChecksum(std::vector<uint8_t>& image, const Table& table, size_t terminator)
{
    if (terminator == 0 || terminator + 5 > image.size()) {
        return;
    }
    uint8_t sum = 0;
    for (size_t index = table.prefix.size(); index <= terminator + 4; index++) {
        if (index == terminator + 4) {
            continue;
        }
        sum = static_cast<uint8_t>(sum + image[index]);
    }
    image[terminator + 4] = static_cast<uint8_t>((0x100u - sum) & 0xFFu);
}

bool IsPrintableAscii(const std::string& text)
{
    for (char ch : text) {
        const unsigned char value = static_cast<unsigned char>(ch);
        if (value < 0x20 || value > 0x7E) {
            return false;
        }
    }
    return !text.empty();
}

int HexNibble(char ch)
{
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
}

/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -> 16 bytes in SMBIOS byte order. */
bool ParseUuid(const std::string& text, uint8_t* uuid)
{
    size_t out = 0;
    for (size_t index = 0; index < text.size();) {
        if (text[index] == '-') {
            index++;
            continue;
        }
        if (index + 1 >= text.size() || out >= 16) {
            return false;
        }
        const int high = HexNibble(text[index]);
        const int low = HexNibble(text[index + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        uuid[out++] = static_cast<uint8_t>((high << 4) | low);
        index += 2;
    }
    if (out != 16) {
        return false;
    }
    /* First three groups are big-endian on the wire, little-endian in memory. */
    uint8_t temporary = uuid[0];
uuid[0] = uuid[3];
uuid[3] = temporary;
    temporary = uuid[1];
uuid[1] = uuid[2];
uuid[2] = temporary;
    temporary = uuid[4];
uuid[4] = uuid[5];
uuid[5] = temporary;
    temporary = uuid[6];
uuid[6] = uuid[7];
uuid[7] = temporary;
    return true;
}

void SetString(Structure& structure, size_t offset, const std::string& text, size_t& changed,
               size_t& matched)
{
    if (text.empty() || offset >= structure.formatted.size()) {
        return;
    }
    const uint8_t index = structure.formatted[offset];
    if (index == 0 || index > structure.strings.size()) {
        return;
    }
    std::string& slot = structure.strings[index - 1];
    if (slot == text) {
        matched++;
        return;
    }
    if (!IsPrintableAscii(text)) {
        return;
    }
    slot = text;
    changed++;
}

void SetUuid(Structure& structure, const std::string& text, size_t& changed, size_t& matched)
{
    if (text.empty() || structure.formatted.size() < 0x18) {
        return;
    }
    uint8_t uuid[16]{};
    if (!ParseUuid(text, uuid)) {
        return;
    }
    uint8_t* target = structure.formatted.data() + 0x08;
    if (memcmp(target, uuid, sizeof(uuid)) == 0) {
        matched++;
        return;
    }
    memcpy(target, uuid, sizeof(uuid));
    changed++;
}

/* Applies the identity in place and counts what moved and what already matched. */
void ApplyIdentity(Table& table, const Identity& identity, size_t& changed, size_t& matched)
{
    size_t memoryIndex = 0;

    for (Structure& structure : table.structures) {
        const size_t length = structure.formatted.size();
        switch (structure.type) {
        case 0:
            if (length > 0x08) {
                SetString(structure, 0x04, identity.biosVendor, changed, matched);
                SetString(structure, 0x05, identity.biosVersion, changed, matched);
                SetString(structure, 0x08, identity.biosReleaseDate, changed, matched);
            }
            break;
        case 1:
            if (length > 0x08) {
                SetString(structure, 0x04, identity.systemManufacturer, changed, matched);
                SetString(structure, 0x05, identity.systemProductName, changed, matched);
                SetString(structure, 0x06, identity.systemVersion, changed, matched);
                SetString(structure, 0x07, identity.systemSerial, changed, matched);
            }
            SetUuid(structure, identity.systemUuid, changed, matched);
            if (length > 0x19) {
                SetString(structure, 0x19, identity.systemSku, changed, matched);
            }
            if (length > 0x1A) {
                SetString(structure, 0x1A, identity.systemFamily, changed, matched);
            }
            break;
        case 2:
            if (length > 0x08) {
                SetString(structure, 0x04, identity.baseboardManufacturer, changed, matched);
                SetString(structure, 0x05, identity.baseboardProduct, changed, matched);
                SetString(structure, 0x06, identity.baseboardVersion, changed, matched);
                SetString(structure, 0x07, identity.baseboardSerial, changed, matched);
            }
            break;
        case 3:
            if (length > 0x08) {
                SetString(structure, 0x04, identity.chassisManufacturer, changed, matched);
                SetString(structure, 0x06, identity.chassisVersion, changed, matched);
                SetString(structure, 0x07, identity.chassisSerial, changed, matched);
            }
            break;
        case 17:
            if (length > 0x18 && memoryIndex < identity.memorySerials.size()) {
                SetString(structure, 0x18, identity.memorySerials[memoryIndex], changed, matched);
                memoryIndex++;
            }
            break;
        default:
            break;
        }
    }
}

struct Originals {
    bool owned = false;
    std::vector<uint8_t> bytes;
};

/* true when the file was there and usable; present is false when absent. */
bool LoadOriginals(Originals& originals, bool& present, std::wstring& error)
{
    present = false;
    std::vector<uint8_t> file;
    if (!util::FileExists(OriginalsPath())) {
        return true;
    }
    present = true;

    if (!util::ReadAllBytes(OriginalsPath(), file)) {
        error = L"Cannot read " + OriginalsPath();
        return false;
    }
    if (file.size() < sizeof(kMagic) + 12 || memcmp(file.data(), kMagic, sizeof(kMagic)) != 0) {
        error = L"SMBIOS originals file is not in a recognised format";
        return false;
    }

    uint32_t format = 0;
    uint32_t flags = 0;
    uint32_t length = 0;
    memcpy(&format, file.data() + sizeof(kMagic), sizeof(format));
    memcpy(&flags, file.data() + sizeof(kMagic) + 4, sizeof(flags));
    memcpy(&length, file.data() + sizeof(kMagic) + 8, sizeof(length));
    if (format != kFormat) {
        error = L"SMBIOS originals file has an unknown version";
        return false;
    }
    const size_t blobOffset = sizeof(kMagic) + 12;
    if (blobOffset + length > file.size()) {
        error = L"SMBIOS originals file is truncated";
        return false;
    }

    const std::vector<uint8_t> blob(file.data() + blobOffset, file.data() + blobOffset + length);
    if (!util::UnprotectForUser(blob, originals.bytes) || originals.bytes.empty()) {
        error = L"SMBIOS originals cannot be decrypted by this account";
        return false;
    }
    originals.owned = (flags & kOwned) != 0;
    return true;
}

bool SaveOriginals(const Originals& originals, std::wstring& error)
{
    const std::vector<uint8_t> blob = util::ProtectForUser(originals.bytes);
    if (blob.empty()) {
        error = L"CryptProtectData failed for the SMBIOS originals";
        return false;
    }

    std::vector<uint8_t> file;
    file.insert(file.end(), kMagic, kMagic + sizeof(kMagic));
    const uint32_t format = kFormat;
    const uint32_t flags = originals.owned ? kOwned : 0;
    const uint32_t length = static_cast<uint32_t>(blob.size());
    const uint8_t* parts[3] = {reinterpret_cast<const uint8_t*>(&format),
                               reinterpret_cast<const uint8_t*>(&flags),
                               reinterpret_cast<const uint8_t*>(&length)};
    for (const uint8_t* part : parts) {
        file.insert(file.end(), part, part + 4);
    }
    file.insert(file.end(), blob.begin(), blob.end());

    if (!util::WriteAllBytes(OriginalsPath(), file)) {
        error = L"Cannot write " + OriginalsPath();
        return false;
    }
    return true;
}

bool RunTool(const std::wstring& commandLine, DWORD& exitCode, std::wstring& error)
{
    std::vector<wchar_t> buffer(commandLine.begin(), commandLine.end());
    buffer.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) {
        error = L"Cannot run schtasks: " + util::FormatWin32Error(GetLastError());
        return false;
    }
    WaitForSingleObject(process.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    exitCode = code;
    return true;
}

} // namespace

std::wstring OriginalsPath()
{
    return util::JoinPath(util::ExeDirectory(), L"smbios_orig.bin");
}

bool Apply(const Identity& identity, bool dryRun, Result& result, std::wstring& error)
{
    result = Result{};

    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    if (!ReadRawValue(kDataKey, kValueName, type, data, present, error)) {
        return false;
    }
    if (!present) {
        error = L"mssmbios has not published a SMBiosData value";
        return false;
    }
    if (type != REG_BINARY || data.size() < 16) {
        error = L"SMBiosData is not a usable binary table";
        return false;
    }

    const size_t start = FindStart(data);
    if (start >= data.size()) {
        error = L"SMBiosData does not begin with a SMBIOS structure table";
        return false;
    }

    Table table;
    if (!ParseTable(data, start, table, error)) {
        return false;
    }

    size_t changed = 0;
    size_t matched = 0;
    {
        Table probe = table;
        ApplyIdentity(probe, identity, changed, matched);
    }
    result.fields = changed + matched;
    result.alreadyProfile = result.fields > 0 && changed == 0;

    Originals originals;
    bool haveOriginals = false;
    if (!LoadOriginals(originals, haveOriginals, error)) {
        return false;
    }
    if (!haveOriginals) {
        if (result.alreadyProfile) {
            /*
             * Nothing here is the machine's own table: something already
             * spoofed it. Capturing those bytes as "originals" would write a
             * spoof back on restore, so no snapshot is taken.
             */
            util::Log(util::Level::Info,
                      L"  table already reads as the profile; originals stay with whatever "
                      L"applied it first");
        } else {
            originals.owned = true;
            originals.bytes = data;
            if (dryRun) {
                util::Logf(util::Level::Info,
                           L"  dry-run: would capture %zu bytes of firmware table",
                           data.size());
            } else if (!SaveOriginals(originals, error)) {
                return false;
            } else {
                util::Logf(util::Level::Ok, L"  originals captured: %zu bytes, DPAPI-sealed",
                           data.size());
            }
        }
    }

    Table patched = table;
    size_t patchedChanged = 0;
    size_t patchedMatched = 0;
    ApplyIdentity(patched, identity, patchedChanged, patchedMatched);

    size_t terminator = 0;
    std::vector<uint8_t> image = Serialize(patched, terminator);
    ResealChecksum(image, table, terminator);

    result.changed = patchedChanged;
    result.fields = patchedChanged + patchedMatched;
    result.bytes = image.size();

    if (image == data) {
        util::Logf(util::Level::Ok, L"  table already serves the profile (%zu bytes, %zu fields)",
                   image.size(), result.fields);
        return true;
    }
    if (dryRun) {
        util::Logf(util::Level::Info, L"  dry-run: would rewrite %zu field(s), %zu -> %zu bytes",
                   patchedChanged, data.size(), image.size());
        return true;
    }
    if (!WriteRawValue(kDataKey, kValueName, REG_BINARY, image, error)) {
        return false;
    }
    util::Logf(util::Level::Ok, L"  table rewritten: %zu field(s), %zu -> %zu bytes",
               patchedChanged, data.size(), image.size());
    return true;
}

bool Restore(bool dryRun, size_t& bytes, std::wstring& error)
{
    bytes = 0;

    Originals originals;
    bool present = false;
    if (!LoadOriginals(originals, present, error)) {
        return false;
    }
    if (!present) {
        util::Log(util::Level::Info,
                  L"  no captured SMBIOS originals; the machine's firmware table is untouched");
        return true;
    }
    if (!originals.owned) {
        util::Log(util::Level::Warn,
                  L"  originals were never captured: the table was already spoofed on the "
                  L"first run, so there is no real copy here to put back");
        return true;
    }

    bytes = originals.bytes.size();
    if (dryRun) {
        util::Logf(util::Level::Info, L"  dry-run: would write the %zu-byte firmware table back",
                   bytes);
        return true;
    }
    if (!WriteRawValue(kDataKey, kValueName, REG_BINARY, originals.bytes, error)) {
        return false;
    }
    DeleteFileW(OriginalsPath().c_str());
    util::Logf(util::Level::Ok, L"  SMBiosData -> firmware table (%zu bytes, bytes not printed)",
               bytes);
    return true;
}

State Inspect(const Identity* identity)
{
    State state;

    DWORD type = 0;
    std::vector<uint8_t> data;
    bool present = false;
    std::wstring error;
    if (!ReadRawValue(kDataKey, kValueName, type, data, present, error) || !present) {
        return state;
    }
    state.readable = true;
    state.bytes = data.size();

    Originals originals;
    bool haveOriginals = false;
    if (LoadOriginals(originals, haveOriginals, error) && haveOriginals) {
        state.originals = true;
        state.spoofed = originals.bytes != data;
    }

    if (identity != nullptr) {
        const size_t start = FindStart(data);
        Table table;
        if (start < data.size() && ParseTable(data, start, table, error)) {
            size_t changed = 0;
            size_t matched = 0;
            ApplyIdentity(table, *identity, changed, matched);
            state.matchedFields = matched;
            state.profileFields = changed + matched;
            state.servesProfile = state.profileFields > 0 && changed == 0;
        }
    }
    return state;
}

bool InstallBootTask(const std::wstring& executable, std::wstring& error)
{
    if (!util::FileExists(executable)) {
        error = L"Boot task target is missing: " + executable;
        return false;
    }
    const std::wstring action = L"\"" + executable +
                                L"\" --reapply --no-driver --no-network --no-task";
    const std::wstring command = L"schtasks.exe /Create /F /TN \"" + std::wstring(kTaskName) +
                                 L"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR \"" + action + L"\"";
    DWORD code = 0;
    if (!RunTool(command, code, error)) {
        return false;
    }
    if (code != 0) {
        error = L"schtasks /Create failed with exit code " + std::to_wstring(code);
        return false;
    }
    return true;
}

bool RemoveBootTask(std::wstring& error)
{
    if (!BootTaskInstalled()) {
        /* Nothing registered: already in the wanted state, not a failure. */
        return true;
    }
    const std::wstring command = L"schtasks.exe /Delete /F /TN \"" + std::wstring(kTaskName) + L"\"";
    DWORD code = 0;
    if (!RunTool(command, code, error)) {
        return false;
    }
    if (code != 0 || BootTaskInstalled()) {
        error = L"schtasks /Delete failed with exit code " + std::to_wstring(code);
        return false;
    }
    return true;
}

bool BootTaskInstalled()
{
    const std::wstring command =
        L"schtasks.exe /Query /TN \"" + std::wstring(kTaskName) + L"\"";
    DWORD code = 0;
    std::wstring error;
    if (!RunTool(command, code, error)) {
        return false;
    }
    return code == 0;
}

} // namespace smbios
