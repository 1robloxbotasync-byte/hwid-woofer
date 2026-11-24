#include "identity.h"

#include "util.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <sstream>

namespace {

class Rng {
public:
    explicit Rng(uint64_t seed) : state_(seed != 0 ? seed : 0x9E3779B97F4A7C15ull) {}

    uint64_t Next()
    {
        uint64_t value = (state_ += 0x9E3779B97F4A7C15ull);
        value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
        value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
        return value ^ (value >> 31);
    }

    uint32_t Below(uint32_t bound)
    {
        return bound == 0 ? 0 : static_cast<uint32_t>(Next() % bound);
    }

    std::string Pick(std::initializer_list<const char*> values)
    {
        auto it = values.begin();
        std::advance(it, Below(static_cast<uint32_t>(values.size())));
        return *it;
    }

    std::string Chars(size_t count, const char* alphabet)
    {
        const size_t alphabetSize = std::char_traits<char>::length(alphabet);
        std::string result;
        result.reserve(count);
        for (size_t index = 0; index < count; index++) {
            result.push_back(alphabet[Below(static_cast<uint32_t>(alphabetSize))]);
        }
        return result;
    }

    std::string Digits(size_t count)
    {
        return Chars(count, "0123456789");
    }

    std::string HexDigits(size_t count)
    {
        return Chars(count, "0123456789ABCDEF");
    }

    std::string Uuid()
    {
        uint8_t bytes[16]{};
        for (size_t index = 0; index < sizeof(bytes); index++) {
            bytes[index] = static_cast<uint8_t>(Next() & 0xFF);
        }
        bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0F) | 0x40);
        bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3F) | 0x80);

        char text[40]{};
        std::snprintf(text, sizeof(text),
                      "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                      bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                      bytes[12], bytes[13], bytes[14], bytes[15]);
        return text;
    }

private:
    uint64_t state_;
};

struct PlatformTemplate {
    const char* systemManufacturer;
    const char* systemProduct;
    const char* systemFamily;
    const char* baseboardManufacturer;
    const char* baseboardProduct;
    const char* chassisManufacturer;
    const char* biosVendor;
};

const PlatformTemplate kPlatforms[] = {
    {"ASUSTeK COMPUTER INC.", "ROG STRIX X670E-A GAMING WIFI", "ROG", "ASUSTeK COMPUTER INC.",
     "ROG STRIX X670E-A GAMING WIFI", "ASUSTeK COMPUTER INC.", "American Megatrends Inc."},
    {"Micro-Star International Co., Ltd.", "MS-7D75", "MSI", "Micro-Star International Co., Ltd.",
     "MPG B650 CARBON WIFI (MS-7D75)", "Micro-Star International Co., Ltd.", "American Megatrends International, LLC."},
    {"Gigabyte Technology Co., Ltd.", "X670 AORUS ELITE AX", "AORUS", "Gigabyte Technology Co., Ltd.",
     "X670 AORUS ELITE AX", "Gigabyte Technology Co., Ltd.", "American Megatrends International, LLC."},
    {"ASRock", "B650 Steel Legend WiFi", "Steel Legend", "ASRock", "B650 Steel Legend WiFi",
     "ASRock", "American Megatrends International, LLC."},
    {"Dell Inc.", "XPS 8960", "XPS", "Dell Inc.", "0K240Y", "Dell Inc.", "Dell Inc."},
    {"HP", "OMEN 30L Desktop GT13-1xxx", "OMEN", "HP", "886B", "HP", "AMI"},
    {"LENOVO", "Legion T7 34IRZ8", "Legion", "LENOVO", "1046", "LENOVO", "LENOVO"},
    {"System manufacturer", "System Product Name", "System Family", "ASUSTeK COMPUTER INC.",
     "PRIME B650-PLUS", "Default string", "American Megatrends Inc."},
};

constexpr char kSerialAlphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
constexpr char kMacAlphabet[] = "0123456789ABCDEF";
const char* kMacOuis[] = {
    "001B21", // Intel
    "00E04C", // Realtek
    "001018", // Broadcom
    "04D4C4", // ASUSTek
    "50C7BF", // TP-Link
    "B0A460", // Dell
};

bool ParseU64(const std::string& text, int base, uint64_t& value)
{
    if (text.empty()) {
        return false;
    }
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto result = std::from_chars(begin, end, value, base);
    return result.ec == std::errc() && result.ptr == end;
}

bool ParseU32(const std::string& text, uint32_t& value)
{
    uint64_t parsed = 0;
    if (!ParseU64(text, 10, parsed) || parsed > 0xFFFFFFFFull) {
        return false;
    }
    value = static_cast<uint32_t>(parsed);
    return true;
}

std::string FormatHex64(uint64_t value)
{
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(value));
    return buffer;
}

uint64_t HashGuid(const std::wstring& guid)
{
    uint64_t hash = 1469598103934665603ull;
    for (wchar_t ch : guid) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= 1099511628211ull;
    }
    return hash;
}

std::string GenerateMac(uint64_t seed, const std::wstring& guid)
{
    Rng rng(seed ^ HashGuid(guid));
    const std::string oui = kMacOuis[rng.Below(static_cast<uint32_t>(std::size(kMacOuis)))];
    return oui + rng.HexDigits(6);
}

std::string MakeBiosDate(Rng& rng)
{
    const uint32_t year = 2019 + rng.Below(7);
    const uint32_t month = 1 + rng.Below(12);
    const uint32_t day = 1 + rng.Below(28);
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "%02u/%02u/%04u", month, day, year);
    return buffer;
}

Identity GenerateWithRng(uint64_t seed)
{
    Identity identity;
    identity.seed = seed != 0 ? seed : util::RandomU64();
    identity.created = static_cast<uint64_t>(std::time(nullptr));
    Rng rng(identity.seed);

    const PlatformTemplate& platform = kPlatforms[rng.Below(std::size(kPlatforms))];

    identity.machineGuid = rng.Uuid();
    identity.productId = "00330-" + rng.Digits(5) + "-" + rng.Digits(5) + "-" +
                         rng.Digits(5) + "-" + rng.Digits(5);
    identity.installDate = 1609459200u + rng.Below(4u * 365u * 24u * 60u * 60u);
    identity.hwProfileGuid = "{" + rng.Uuid() + "}";
    identity.sqmMachineId = "{" + rng.Uuid() + "}";
    identity.computerName = "DESKTOP-" + rng.Chars(7, "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789");
    identity.susClientId = rng.Uuid();
    identity.computerHardwareId = "{" + rng.Uuid() + "}";

    identity.systemUuid = rng.Uuid();
    identity.systemSerial = rng.Chars(10, kSerialAlphabet);
    identity.baseboardSerial = rng.Chars(12, kSerialAlphabet);
    identity.chassisSerial = rng.Chars(12, kSerialAlphabet);

    identity.biosVendor = platform.biosVendor;
    identity.biosVersion = rng.Pick({"F4", "F5", "F7a", "1.14", "2.12.0", "1.28", "7C56v1A"});
    identity.biosReleaseDate = MakeBiosDate(rng);

    identity.systemManufacturer = platform.systemManufacturer;
    identity.systemProductName = platform.systemProduct;
    identity.systemVersion = rng.Pick({"1.0", "1.1", "2.0", ""});
    identity.systemFamily = platform.systemFamily;
    identity.systemSku = "SKU" + rng.Digits(5);

    identity.baseboardManufacturer = platform.baseboardManufacturer;
    identity.baseboardProduct = platform.baseboardProduct;
    identity.baseboardVersion = rng.Pick({"Rev 1.0", "Rev 1.1", "1.0", "2.0"});

    identity.chassisManufacturer = platform.chassisManufacturer;
    identity.chassisVersion = rng.Pick({"Rev 1.0", "1.0", "2.0"});

    identity.processorSerial = rng.Chars(16, kSerialAlphabet);

    for (std::string& serial : identity.diskSerials) {
        serial = rng.Chars(20, kSerialAlphabet);
    }
    for (std::string& serial : identity.volumeSerials) {
        serial = rng.HexDigits(8);
    }
    for (std::string& serial : identity.memorySerials) {
        serial = rng.Chars(12, kSerialAlphabet);
    }

    return identity;
}

std::string EscapeField(const std::string& text)
{
    std::string result = text;
    for (char& ch : result) {
        if (ch == '\t' || ch == '\r' || ch == '\n') {
            ch = ' ';
        }
    }
    return result;
}

std::array<std::string, 3> SplitAdapterLine(const std::string& value)
{
    std::array<std::string, 3> parts{};
    const size_t first = value.find('\t');
    if (first == std::string::npos) {
        parts[0] = util::TrimAscii(value);
        return parts;
    }
    const size_t second = value.find('\t', first + 1);
    parts[0] = util::TrimAscii(value.substr(0, first));
    if (second == std::string::npos) {
        parts[1] = util::TrimAscii(value.substr(first + 1));
        return parts;
    }
    parts[1] = util::TrimAscii(value.substr(first + 1, second - first - 1));
    parts[2] = value.substr(second + 1);
    return parts;
}

} // namespace

const MacAssignment* Identity::FindAdapter(const std::wstring& guid) const
{
    for (const MacAssignment& assignment : adapters) {
        if (_wcsicmp(assignment.adapterGuid.c_str(), guid.c_str()) == 0) {
            return &assignment;
        }
    }
    return nullptr;
}

Identity GenerateIdentity(uint64_t seed)
{
    return GenerateWithRng(seed);
}

MacAssignment& EnsureAdapterMac(Identity& identity, const std::wstring& guid,
                                const std::wstring& description)
{
    for (MacAssignment& assignment : identity.adapters) {
        if (_wcsicmp(assignment.adapterGuid.c_str(), guid.c_str()) == 0) {
            if (!description.empty()) {
                assignment.description = description;
            }
            return assignment;
        }
    }

    MacAssignment assignment;
    assignment.adapterGuid = guid;
    assignment.description = description;
    assignment.mac = GenerateMac(identity.seed, guid);
    identity.adapters.push_back(assignment);
    return identity.adapters.back();
}

std::string MacWithSeparators(const std::string& mac)
{
    if (mac.size() != 12) {
        return mac;
    }
    std::string result;
    result.reserve(17);
    for (size_t index = 0; index < mac.size(); index += 2) {
        if (index != 0) {
            result.push_back(':');
        }
        result.push_back(mac[index]);
        result.push_back(mac[index + 1]);
    }
    return result;
}

bool SaveIdentity(const std::wstring& path, const Identity& identity, std::wstring& error)
{
    std::error_code fsError;
    const std::filesystem::path file(path);
    if (file.has_parent_path()) {
        std::filesystem::create_directories(file.parent_path(), fsError);
    }

    std::ofstream out(file, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        error = L"Cannot write profile: " + path;
        return false;
    }

    out << "[profile]\n";
    out << "format=1\n";
    out << "seed=" << FormatHex64(identity.seed) << "\n";
    out << "created=" << identity.created << "\n\n";

    out << "[identity]\n";
    out << "machine_guid=" << EscapeField(identity.machineGuid) << "\n";
    out << "product_id=" << EscapeField(identity.productId) << "\n";
    out << "install_date=" << identity.installDate << "\n";
    out << "hw_profile_guid=" << EscapeField(identity.hwProfileGuid) << "\n";
    out << "sqm_machine_id=" << EscapeField(identity.sqmMachineId) << "\n";
    out << "computer_name=" << EscapeField(identity.computerName) << "\n";
    out << "sus_client_id=" << EscapeField(identity.susClientId) << "\n";
    out << "computer_hardware_id=" << EscapeField(identity.computerHardwareId) << "\n";
    out << "system_uuid=" << EscapeField(identity.systemUuid) << "\n";
    out << "system_serial=" << EscapeField(identity.systemSerial) << "\n";
    out << "baseboard_serial=" << EscapeField(identity.baseboardSerial) << "\n";
    out << "chassis_serial=" << EscapeField(identity.chassisSerial) << "\n";
    out << "bios_vendor=" << EscapeField(identity.biosVendor) << "\n";
    out << "bios_version=" << EscapeField(identity.biosVersion) << "\n";
    out << "bios_date=" << EscapeField(identity.biosReleaseDate) << "\n";
    out << "system_manufacturer=" << EscapeField(identity.systemManufacturer) << "\n";
    out << "system_product=" << EscapeField(identity.systemProductName) << "\n";
    out << "system_version=" << EscapeField(identity.systemVersion) << "\n";
    out << "system_family=" << EscapeField(identity.systemFamily) << "\n";
    out << "system_sku=" << EscapeField(identity.systemSku) << "\n";
    out << "baseboard_manufacturer=" << EscapeField(identity.baseboardManufacturer) << "\n";
    out << "baseboard_product=" << EscapeField(identity.baseboardProduct) << "\n";
    out << "baseboard_version=" << EscapeField(identity.baseboardVersion) << "\n";
    out << "chassis_manufacturer=" << EscapeField(identity.chassisManufacturer) << "\n";
    out << "chassis_version=" << EscapeField(identity.chassisVersion) << "\n";
    out << "processor_serial=" << EscapeField(identity.processorSerial) << "\n\n";

    out << "[driver]\n";
    for (size_t index = 0; index < identity.diskSerials.size(); index++) {
        out << "disk_" << index << "=" << EscapeField(identity.diskSerials[index]) << "\n";
    }
    for (size_t index = 0; index < identity.volumeSerials.size(); index++) {
        out << "volume_" << index << "=" << EscapeField(identity.volumeSerials[index]) << "\n";
    }
    for (size_t index = 0; index < identity.memorySerials.size(); index++) {
        out << "memory_" << index << "=" << EscapeField(identity.memorySerials[index]) << "\n";
    }
    out << "\n[network]\n";
    for (const MacAssignment& assignment : identity.adapters) {
        out << "adapter=" << util::ToUtf8(assignment.adapterGuid) << "\t"
            << EscapeField(assignment.mac) << "\t"
            << util::ToUtf8(assignment.description) << "\n";
    }

    if (!out.good()) {
        error = L"Profile write failed: " + path;
        return false;
    }
    error.clear();
    return true;
}

bool LoadIdentity(const std::wstring& path, Identity& identity, std::wstring& error)
{
    std::ifstream in(std::filesystem::path(path), std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        error = L"Profile not found: " + path;
        return false;
    }

    Identity loaded;
    std::string section;
    std::string line;
    bool sawFormat = false;
    bool sawSeed = false;

    while (std::getline(in, line)) {
        line = util::TrimAscii(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            section = util::ToLowerAscii(line.substr(1, line.size() - 2));
            continue;
        }

        const size_t equals = line.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        const std::string key = util::ToLowerAscii(util::TrimAscii(line.substr(0, equals)));
        const std::string value = util::TrimAscii(line.substr(equals + 1));

        auto setText = [&value](std::string& target) { target = value; };

        if (section == "profile") {
            if (key == "format") {
                uint32_t format = 0;
                if (!ParseU32(value, format) || format != 1) {
                    error = L"Unsupported profile format";
                    return false;
                }
                sawFormat = true;
            } else if (key == "seed") {
                if (!ParseU64(value, 16, loaded.seed)) {
                    error = L"Invalid seed in profile";
                    return false;
                }
                sawSeed = true;
            } else if (key == "created") {
                (void)ParseU64(value, 10, loaded.created);
            }
        } else if (section == "identity") {
            if (key == "machine_guid") setText(loaded.machineGuid);
            else if (key == "product_id") setText(loaded.productId);
            else if (key == "install_date") (void)ParseU32(value, loaded.installDate);
            else if (key == "hw_profile_guid") setText(loaded.hwProfileGuid);
            else if (key == "sqm_machine_id") setText(loaded.sqmMachineId);
            else if (key == "computer_name") setText(loaded.computerName);
            else if (key == "sus_client_id") setText(loaded.susClientId);
            else if (key == "computer_hardware_id") setText(loaded.computerHardwareId);
            else if (key == "system_uuid") setText(loaded.systemUuid);
            else if (key == "system_serial") setText(loaded.systemSerial);
            else if (key == "baseboard_serial") setText(loaded.baseboardSerial);
            else if (key == "chassis_serial") setText(loaded.chassisSerial);
            else if (key == "bios_vendor") setText(loaded.biosVendor);
            else if (key == "bios_version") setText(loaded.biosVersion);
            else if (key == "bios_date") setText(loaded.biosReleaseDate);
            else if (key == "system_manufacturer") setText(loaded.systemManufacturer);
            else if (key == "system_product") setText(loaded.systemProductName);
            else if (key == "system_version") setText(loaded.systemVersion);
            else if (key == "system_family") setText(loaded.systemFamily);
            else if (key == "system_sku") setText(loaded.systemSku);
            else if (key == "baseboard_manufacturer") setText(loaded.baseboardManufacturer);
            else if (key == "baseboard_product") setText(loaded.baseboardProduct);
            else if (key == "baseboard_version") setText(loaded.baseboardVersion);
            else if (key == "chassis_manufacturer") setText(loaded.chassisManufacturer);
            else if (key == "chassis_version") setText(loaded.chassisVersion);
            else if (key == "processor_serial") setText(loaded.processorSerial);
        } else if (section == "driver") {
            auto setIndexed = [&key, &value](const char* prefix, auto& array) {
                const std::string prefixText(prefix);
                if (key.rfind(prefixText, 0) != 0) {
                    return;
                }
                uint32_t index = 0;
                if (!ParseU32(key.substr(prefixText.size()), index) || index >= array.size()) {
                    return;
                }
                array[index] = value;
            };
            setIndexed("disk_", loaded.diskSerials);
            setIndexed("volume_", loaded.volumeSerials);
            setIndexed("memory_", loaded.memorySerials);
        } else if (section == "network" && key == "adapter") {
            const auto parts = SplitAdapterLine(value);
            if (!parts[0].empty() && parts[1].size() == 12) {
                MacAssignment assignment;
                assignment.adapterGuid = util::ToWide(parts[0]);
                assignment.mac = parts[1];
                assignment.description = util::ToWide(parts[2]);
                loaded.adapters.push_back(std::move(assignment));
            }
        }
    }

    if (!sawFormat || !sawSeed || loaded.seed == 0 || loaded.machineGuid.empty()) {
        error = L"Profile is incomplete: " + path;
        return false;
    }

    /*
     * Profiles written before these two surfaces existed have no value for
     * them. Derive from the seed so --reapply fills them in without touching
     * the rest of the identity (separate stream, same seed).
     */
    {
        Rng extra(loaded.seed ^ 0xD1B54A32D192ED03ull);
        if (loaded.susClientId.empty()) {
            loaded.susClientId = extra.Uuid();
        }
        if (loaded.computerHardwareId.empty()) {
            loaded.computerHardwareId = "{" + extra.Uuid() + "}";
        }
        /* These keys carry braces in a stock install; keep the shape. */
        const auto brace = [](std::string& value) {
            if (!value.empty() && value.front() != '{') {
                value = "{" + value + "}";
            }
        };
        brace(loaded.hwProfileGuid);
        brace(loaded.sqmMachineId);
        brace(loaded.computerHardwareId);
    }

    identity = std::move(loaded);
    error.clear();
    return true;
}
