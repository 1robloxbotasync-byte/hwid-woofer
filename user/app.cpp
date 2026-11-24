#include "driver_client.h"
#include "identity.h"
#include "network.h"
#include "registry.h"
#include "smbios.h"
#include "util.h"
#include "verify.h"

#include "../shared/hwid_ioctl.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "app.h"

namespace app {

namespace {

std::vector<std::wstring> g_lastIssues;

std::wstring OnOff(bool value)
{
    return value ? L"on" : L"off";
}

} // namespace

void PrintUsage()
{
    util::Log(util::Level::Info, L"hwidspoof " + std::wstring(kVersion));
    util::Log(util::Level::Info, L"");
    util::Log(util::Level::Info, L"  hwidspoof --spoof [--seed <hex>] [flags]");
    util::Log(util::Level::Info, L"      Generate a new identity, load the driver, apply it.");
    util::Log(util::Level::Info, L"  hwidspoof --reapply");
    util::Log(util::Level::Info, L"      Re-apply the stored profile (after reboot / driver reload).");
    util::Log(util::Level::Info, L"  hwidspoof --verify");
    util::Log(util::Level::Info, L"      Compare live values against the stored profile.");
    util::Log(util::Level::Info, L"  hwidspoof --restore");
    util::Log(util::Level::Info, L"      Clear driver config, restore registry and MACs.");
    util::Log(util::Level::Info, L"  hwidspoof --status");
    util::Log(util::Level::Info, L"      Platform, SMBIOS table, boot task and driver state.");
    util::Log(util::Level::Info, L"  hwidspoof --unload");
    util::Log(util::Level::Info, L"      Stop and delete the kernel service.");
    util::Log(util::Level::Info, L"  hwidspoof --install [--seed <hex>]");
    util::Log(util::Level::Info, L"      Perma mode: new identity, driver as AUTO_START when the");
    util::Log(util::Level::Info, L"      boot policy allows it, plus a SYSTEM boot task, so the");
    util::Log(util::Level::Info, L"      identity is reapplied at every boot either way.");
    util::Log(util::Level::Info, L"  hwidspoof --uninstall");
    util::Log(util::Level::Info, L"      Restore everything, delete the stored config, remove the service.");
    util::Log(util::Level::Info, L"");
    util::Log(util::Level::Info, L"  --perma          same as --install but against an existing profile");
    util::Log(util::Level::Info, L"  --dry-run        print the plan, change nothing");
    util::Log(util::Level::Info, L"  --no-driver      skip driver install and disk/volume patches");
    util::Log(util::Level::Info, L"  --no-registry    skip registry and SMBIOS table writes");
    util::Log(util::Level::Info, L"  --no-network     skip MAC overrides");
    util::Log(util::Level::Info, L"  --no-task        do not register the boot reapply task");
    util::Log(util::Level::Info, L"  --no-restart     do not cycle adapters after MAC change");
    util::Log(util::Level::Info, L"  --keep-profile   reuse the existing profile instead of regenerating");
    util::Log(util::Level::Info, L"  --reveal         print real values in clear instead of masking them");
    util::Log(util::Level::Info, L"                   (the log then holds this machine's true identifiers)");
    util::Log(util::Level::Info, L"  --profile <path> profile path (default: profile.ini next to the exe)");
    util::Log(util::Level::Info, L"  --driver <path>  driver path (default: storhlp.sys next to the exe)");
    util::Log(util::Level::Info, L"  -v, --verbose    log every step");
}

bool NeedsElevation(const Options& options)
{
    if (options.dryRun) {
        return false;
    }
    switch (options.mode) {
    case Mode::Spoof:
    case Mode::Reapply:
    case Mode::Install:
        return true;
    case Mode::Restore:
    case Mode::Unload:
    case Mode::Uninstall:
        return !options.dryRun;
    default:
        return false;
    }
}

bool ParseSeed(const std::wstring& text, uint64_t& seed)
{
    const std::string narrow = util::ToUtf8(text);
    int base = 10;
    size_t offset = 0;
    if (narrow.size() > 2 && narrow[0] == '0' && (narrow[1] == 'x' || narrow[1] == 'X')) {
        base = 16;
        offset = 2;
    }
    if (narrow.size() <= offset) {
        return false;
    }
    try {
        size_t consumed = 0;
        const unsigned long long value =
            std::stoull(narrow.substr(offset), &consumed, base);
        if (consumed != narrow.size() - offset) {
            return false;
        }
        seed = static_cast<uint64_t>(value);
        return seed != 0;
    } catch (...) {
        return false;
    }
}

bool ParseArgs(int argc, wchar_t** argv, Options& options, std::wstring& error)
{
    int modeCount = 0;
    const auto setMode = [&](Mode mode) {
        options.mode = mode;
        modeCount++;
    };

    for (int index = 1; index < argc; index++) {
        const std::wstring arg = argv[index];
        const auto next = [&](const wchar_t* what) -> const wchar_t* {
            if (index + 1 >= argc) {
                error = std::wstring(L"Missing value for ") + what;
                return nullptr;
            }
            return argv[++index];
        };

        if (arg == L"--spoof") {
            setMode(Mode::Spoof);
        } else if (arg == L"--reapply") {
            setMode(Mode::Reapply);
        } else if (arg == L"--restore") {
            setMode(Mode::Restore);
        } else if (arg == L"--verify") {
            setMode(Mode::Verify);
        } else if (arg == L"--status") {
            setMode(Mode::Status);
        } else if (arg == L"--unload") {
            setMode(Mode::Unload);
        } else if (arg == L"--install") {
            setMode(Mode::Install);
        } else if (arg == L"--uninstall") {
            setMode(Mode::Uninstall);
        } else if (arg == L"--perma") {
            options.perma = true;
        } else if (arg == L"--dry-run") {
            options.dryRun = true;
        } else if (arg == L"--no-driver") {
            options.noDriver = true;
        } else if (arg == L"--no-registry") {
            options.noRegistry = true;
        } else if (arg == L"--no-network") {
            options.noNetwork = true;
        } else if (arg == L"--no-task") {
            options.noTask = true;
        } else if (arg == L"--no-restart") {
            options.noRestart = true;
        } else if (arg == L"--keep-profile") {
            options.keepProfile = true;
        } else if (arg == L"--reveal") {
            options.reveal = true;
        } else if (arg == L"-v" || arg == L"--verbose") {
            options.verbose = true;
        } else if (arg == L"--seed") {
            const wchar_t* value = next(L"--seed");
            if (value == nullptr) {
                return false;
            }
            if (!ParseSeed(value, options.seed)) {
                error = L"--seed must be a non-zero decimal or 0x-prefixed hex value";
                return false;
            }
        } else if (arg == L"--profile") {
            const wchar_t* value = next(L"--profile");
            if (value == nullptr) {
                return false;
            }
            options.profilePath = value;
        } else if (arg == L"--driver") {
            const wchar_t* value = next(L"--driver");
            if (value == nullptr) {
                return false;
            }
            options.driverPath = value;
        } else if (arg == L"-h" || arg == L"--help" || arg == L"/?") {
            options.mode = Mode::None;
            error.clear();
            return true;
        } else {
            error = L"Unknown argument: " + arg;
            return false;
        }
    }

    if (modeCount > 1) {
        error = L"Pick one mode";
        return false;
    }
    if (options.mode == Mode::Install) {
        options.perma = true;
    }
    ApplyDefaults(options);
    return true;
}

void ApplyDefaults(Options& options)
{
    if (options.profilePath.empty()) {
        options.profilePath = util::JoinPath(util::ExeDirectory(), L"profile.ini");
    }
    if (options.driverPath.empty()) {
        options.driverPath = util::JoinPath(util::ExeDirectory(), L"storhlp.sys");
    }
}

bool ProfileExists(const Options& options)
{
    return util::FileExists(options.profilePath);
}

void CopyText(char* destination, size_t capacity, const std::string& source)
{
    if (capacity == 0) {
        return;
    }
    const size_t length = source.size() < capacity - 1 ? source.size() : capacity - 1;
    memcpy(destination, source.data(), length);
    destination[length] = '\0';
}

HWID_CONFIG BuildConfig(const Identity& identity, const Options& options)
{
    HWID_CONFIG config{};
    config.Size = sizeof(config);
    config.Version = HWID_CONFIG_VERSION;
    config.Generation = 1;

    if (!options.noDriver) {
        config.Flags |= HWID_CFG_DISK_SERIAL | HWID_CFG_VOLUME_SERIAL | HWID_CFG_SMBIOS;
    }
    if (options.noRegistry) {
        config.Flags &= ~HWID_CFG_SMBIOS;
    }
    if (options.perma && !options.noDriver) {
        config.Flags |= HWID_CFG_PERSIST;
    }

    for (size_t index = 0; index < identity.diskSerials.size() && index < HWID_MAX_DISKS;
         index++) {
        CopyText(config.DiskSerial[index], sizeof(config.DiskSerial[index]),
                 identity.diskSerials[index]);
    }
    for (size_t index = 0; index < identity.volumeSerials.size() && index < HWID_MAX_VOLUMES;
         index++) {
        CopyText(config.VolumeSerial[index], sizeof(config.VolumeSerial[index]),
                 identity.volumeSerials[index]);
    }
    for (size_t index = 0; index < identity.memorySerials.size() && index < HWID_MAX_MEMORY;
         index++) {
        CopyText(config.MemorySerial[index], sizeof(config.MemorySerial[index]),
                 identity.memorySerials[index]);
    }

    CopyText(config.SystemUuid, sizeof(config.SystemUuid), identity.systemUuid);
    CopyText(config.SystemSerial, sizeof(config.SystemSerial), identity.systemSerial);
    CopyText(config.BaseboardSerial, sizeof(config.BaseboardSerial), identity.baseboardSerial);
    CopyText(config.ChassisSerial, sizeof(config.ChassisSerial), identity.chassisSerial);

    CopyText(config.BiosVendor, sizeof(config.BiosVendor), identity.biosVendor);
    CopyText(config.BiosVersion, sizeof(config.BiosVersion), identity.biosVersion);
    CopyText(config.BiosReleaseDate, sizeof(config.BiosReleaseDate), identity.biosReleaseDate);

    CopyText(config.SystemManufacturer, sizeof(config.SystemManufacturer),
             identity.systemManufacturer);
    CopyText(config.SystemProductName, sizeof(config.SystemProductName),
             identity.systemProductName);
    CopyText(config.SystemVersion, sizeof(config.SystemVersion), identity.systemVersion);
    CopyText(config.SystemFamily, sizeof(config.SystemFamily), identity.systemFamily);
    CopyText(config.SystemSku, sizeof(config.SystemSku), identity.systemSku);

    CopyText(config.BaseboardManufacturer, sizeof(config.BaseboardManufacturer),
             identity.baseboardManufacturer);
    CopyText(config.BaseboardProduct, sizeof(config.BaseboardProduct),
             identity.baseboardProduct);
    CopyText(config.BaseboardVersion, sizeof(config.BaseboardVersion),
             identity.baseboardVersion);

    CopyText(config.ChassisManufacturer, sizeof(config.ChassisManufacturer),
             identity.chassisManufacturer);
    CopyText(config.ChassisVersion, sizeof(config.ChassisVersion), identity.chassisVersion);

    return config;
}

/*
 * A profile carries an identity, not a machine. When one arrives from another
 * PC it brings none of its history: no originals snapshot (that is DPAPI-sealed
 * per user per machine) and the served table is still the firmware one. The
 * tool would apply someone else's serials and report success, so say it plainly
 * before any surface is touched. Detection only — the operator decides.
 */
void WarnIfProfileIsForeign(const Options& options, const Identity& identity)
{
    if (!util::FileExists(options.profilePath)) {
        return;
    }
    const smbios::State table = smbios::Inspect(&identity);
    if (!table.readable || table.servesProfile || table.originals) {
        return;
    }
    util::Log(util::Level::Warn,
              L"This profile has no history on this machine: no captured originals, firmware "
              L"table intact.");
    util::Log(util::Level::Warn,
              L"  if it came from another PC, this run writes that machine's identity here.");
    util::Log(util::Level::Info,
              L"  delete profile.ini to generate a local identity, or keep it deliberately.");
}

bool LoadOrCreateProfile(const Options& options, bool regenerate, Identity& identity,
                         std::wstring& error)
{
    if (!regenerate && util::FileExists(options.profilePath)) {
        if (LoadIdentity(options.profilePath, identity, error)) {
            util::Logf(util::Level::Ok, L"Profile loaded: %ls", options.profilePath.c_str());
            WarnIfProfileIsForeign(options, identity);
            return true;
        }
        util::Logf(util::Level::Warn, L"%ls", error.c_str());
        util::Log(util::Level::Info, L"Falling back to a freshly generated identity.");
    }

    identity = GenerateIdentity(options.seed);
    util::Logf(util::Level::Ok, L"New identity seed %016llx",
               static_cast<unsigned long long>(identity.seed));
    return true;
}

int DoUnload(const Options& options)
{
    util::Log(util::Level::Step, L"Stopping driver service");
    std::wstring error;
    if (!DriverClient::StopAndDelete(error)) {
        util::Logf(util::Level::Error, L"%ls", error.c_str());
        return 1;
    }
    util::Log(util::Level::Ok, L"Driver service removed");
    UNREFERENCED_PARAMETER(options);
    return 0;
}

int DoStatus(const Options& options)
{
    const KernelGate gate = InspectKernel(options.driverPath);

    util::Log(util::Level::Info, L"  -- platform --");
    util::Logf(util::Level::Info, L"  secure boot        %ls", OnOff(gate.secureBoot).c_str());
    util::Logf(util::Level::Info, L"  test signing       %ls", OnOff(gate.testSigning).c_str());
    util::Logf(util::Level::Info, L"  memory integrity   %ls", OnOff(gate.hvci).c_str());
    if (gate.signer.empty()) {
        util::Log(util::Level::Info, L"  driver signature   none");
    } else {
        util::Logf(util::Level::Info, L"  driver signature   %ls", gate.signer.c_str());
        if (!gate.authority.empty()) {
            util::Logf(util::Level::Info, L"  signed through     %ls", gate.authority.c_str());
        }
    }
    if (gate.canStart) {
        util::Log(util::Level::Info, L"  kernel surfaces    available");
    } else {
        util::Logf(util::Level::Warn, L"  kernel surfaces    blocked - %ls", gate.blocker.c_str());
    }

    /*
     * The firmware table is read and written from ring 3, so it is reported
     * here whether or not the driver is loaded. It is the one kernel-class
     * surface that works under Secure Boot with only a local signature.
     */
    Identity identity;
    std::wstring tableError;
    const bool haveProfile = util::FileExists(options.profilePath) &&
                             LoadIdentity(options.profilePath, identity, tableError);
    const smbios::State table = smbios::Inspect(haveProfile ? &identity : nullptr);
    util::Log(util::Level::Info, L"  -- smbios (user mode) --");
    if (!table.readable) {
        util::Log(util::Level::Warn, L"  table              not readable on this account");
    } else {
        util::Logf(util::Level::Info, L"  table              %zu bytes", table.bytes);
        util::Logf(util::Level::Info, L"  originals          %ls",
                   table.originals ? L"captured" : L"none");
        util::Logf(util::Level::Info, L"  served             %ls",
                   table.spoofed ? L"rewritten table" : L"firmware table");
        if (table.profileFields > 0) {
            util::Logf(util::Level::Info, L"  profile fields     %zu of %zu",
                       table.matchedFields, table.profileFields);
        }
    }
    util::Logf(util::Level::Info, L"  boot task          %ls",
               smbios::BootTaskInstalled() ? L"installed (SYSTEM, ONSTART)" : L"absent");

    DriverClient client;
    std::wstring error;
    if (!client.Open(error)) {
        util::Logf(util::Level::Warn, L"%ls", error.c_str());
        util::Log(util::Level::Info,
                  L"Driver not loaded. Registry, hostname and network surfaces are unaffected.");
        return 0;
    }

    HWID_STATUS status{};
    if (!client.GetStatus(status, error)) {
        util::Logf(util::Level::Error, L"%ls", error.c_str());
        return 1;
    }

    util::Log(util::Level::Info, L"  -- driver --");
    util::Logf(util::Level::Info, L"  version            %lu.%lu", status.DriverVersion >> 16,
               status.DriverVersion & 0xFFFF);
    util::Logf(util::Level::Info, L"  config generation  %lu", status.ConfigGeneration);
    util::Logf(util::Level::Info, L"  flags              0x%08lX", status.Flags);
    util::Logf(util::Level::Info, L"  disk filters       %lu", status.DiskFilters);
    util::Logf(util::Level::Info, L"  partition filters  %lu", status.PartitionFilters);
    util::Logf(util::Level::Info, L"  volume filters     %lu", status.VolumeFilters);
    util::Logf(util::Level::Info, L"  smbios active      %lu", status.SmbiosActive);
    util::Logf(util::Level::Info, L"  smbios bytes       %lu", status.SmbiosBytes);
    util::Logf(util::Level::Info, L"  smbios fields      %lu", status.SmbiosFieldsPatched);
    util::Logf(util::Level::Info, L"  persisted config   %lu", status.Persisted);
    return 0;
}

int DoRestore(const Options& options)
{
    std::vector<std::wstring> failures;

    util::Log(util::Level::Step, L"Clearing driver configuration");
    DriverClient client;
    std::wstring error;
    if (client.Open(error)) {
        if (options.dryRun) {
            util::Log(util::Level::Info, L"  dry-run: would clear driver config");
        } else if (!client.Clear(error)) {
            util::Logf(util::Level::Warn, L"%ls", error.c_str());
            failures.push_back(L"driver clear");
        } else {
            util::Log(util::Level::Ok, L"  driver config cleared");
        }
        client.Close();
    } else {
        util::Logf(util::Level::Info, L"  driver not open, nothing to clear (%ls)",
                   error.c_str());
    }

    if (!options.noRegistry) {
        util::Log(util::Level::Step, L"Restoring the SMBIOS table");
        size_t tableBytes = 0;
        if (!smbios::Restore(options.dryRun, tableBytes, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"smbios restore");
        }
    }

    if (!options.noRegistry) {
        util::Log(util::Level::Step, L"Restoring registry values");
        RegistrySpoofer spoofer;
        if (!spoofer.Restore(options.dryRun, error)) {
            util::Logf(util::Level::Error, L"%ls", error.c_str());
            failures.push_back(L"registry restore");
        }
    }

    if (!options.noNetwork) {
        util::Log(util::Level::Step, L"Clearing MAC overrides");
        Identity identity;
        std::vector<std::wstring> guids;
        for (const NetAdapter& adapter : NetworkSpoofer::Enumerate()) {
            guids.push_back(adapter.guid);
        }
        if (!NetworkSpoofer::Restore(identity, options.dryRun, error)) {
            util::Logf(util::Level::Warn, L"%ls", error.c_str());
            failures.push_back(L"network restore");
        }
        if (!options.noRestart && !options.dryRun && !guids.empty()) {
            (void)NetworkSpoofer::RestartAdapters(guids, error);
        }
    }

    util::Log(util::Level::Info, L"Reboot to fully retire hostname and volume changes.");
    g_lastIssues = failures;
    return failures.empty() ? 0 : 1;
}

/*
 * Perma teardown. The driver holds the stored config and the rewritten
 * firmware table, so it is cleared first, then the service is removed,
 * then the registry and NIC values go back. Doing it in the other order
 * would let a still-running driver re-apply the identity on the way out.
 */
int DoUninstall(const Options& options)
{
    util::Log(util::Level::Step, L"Restoring machine identity");
    const int restoreCode = DoRestore(options);
    if (restoreCode != 0) {
        return restoreCode;
    }
    if (options.dryRun) {
        util::Log(util::Level::Info, L"  dry-run: would delete the driver service");
        return 0;
    }

    util::Log(util::Level::Step, L"Removing driver service");
    std::wstring error;
    if (!DriverClient::StopAndDelete(error)) {
        util::Logf(util::Level::Error, L"  %ls", error.c_str());
        g_lastIssues.push_back(L"driver service");
        return 1;
    }
    util::Log(util::Level::Ok, L"  service deleted");

    if (!options.noTask) {
        util::Log(util::Level::Step, L"Removing the boot task");
        if (!smbios::RemoveBootTask(error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            g_lastIssues.push_back(L"boot task");
            return 1;
        }
        util::Log(util::Level::Ok, L"  boot task removed");
    }

    util::Log(util::Level::Ok, L"Uninstalled. Reboot to retire the remaining cached values.");
    return 0;
}

int DoVerify(const Options& options)
{
    Identity identity;
    std::wstring error;
    if (!LoadIdentity(options.profilePath, identity, error)) {
        util::Logf(util::Level::Error, L"%ls", error.c_str());
        util::Log(util::Level::Info, L"Nothing to verify. Run --spoof first.");
        g_lastIssues.push_back(L"no profile to verify");
        return 1;
    }

    Verifier::PrintIdentity(identity);
    WarnIfProfileIsForeign(options, identity);
    if (util::Reveal()) {
        util::Log(util::Level::Warn,
                  L"  reveal is on: real values print in clear, this log holds them");
    } else {
        util::Log(util::Level::Info,
                  L"  real values are masked below; only profile values print in clear");
    }

    /*
     * Name the kernel state up front. Otherwise every firmware surface shows
     * up as a mismatch with no visible reason, which reads like a bug.
     */
    const KernelGate gate = InspectKernel(options.driverPath);
    if (!gate.serviceRunning) {
        util::Logf(util::Level::Info, L"  kernel surfaces: %ls",
                   gate.canStart ? L"driver not loaded in this boot" : gate.blocker.c_str());
    }

    std::wstring smbiosDetail;
    if (Verifier::SmbiosServed(smbiosDetail)) {
        util::Logf(util::Level::Info, L"  %ls", smbiosDetail.c_str());
    } else {
        util::Logf(util::Level::Warn, L"  smbios: %ls", smbiosDetail.c_str());
    }

    util::Log(util::Level::Step, L"Comparing live values");
    std::vector<std::wstring> problems;
    size_t masked = 0;
    const bool match = Verifier::Compare(identity, problems, &masked);
    for (const std::wstring& problem : problems) {
        util::Logf(util::Level::Error, L"  %ls", problem.c_str());
    }
    if (match) {
        util::Log(util::Level::Ok, L"Every readable surface reads back as the profile.");
        return 0;
    }
    if (masked > 0) {
        if (util::Reveal()) {
            util::Logf(util::Level::Warn,
                       L"%zu real value(s) above are printed in clear because reveal is on.",
                       masked);
        } else {
            util::Logf(util::Level::Warn,
                       L"%zu real value(s) were masked above; this log holds no clear text.",
                       masked);
        }
        std::wstring detail =
            std::to_wstring(masked) + L" surface(s) still read real (masked";
        if (!gate.serviceRunning && !gate.tag.empty()) {
            detail += L", " + gate.tag;
        }
        detail += L")";
        g_lastIssues.push_back(detail);
    } else {
        g_lastIssues.push_back(L"verify found mismatches");
    }
    util::Logf(util::Level::Warn, L"%zu mismatches. Re-run --reapply (and reboot if needed).",
               problems.size());
    return 1;
}

int DoSpoof(const Options& options)
{
    const bool regenerate =
        (options.mode == Mode::Spoof || options.mode == Mode::Install) && !options.keepProfile;

    Identity identity;
    std::wstring error;
    if (!LoadOrCreateProfile(options, regenerate, identity, error)) {
        return 1;
    }

    if (options.dryRun) {
        util::Log(util::Level::Step, L"Dry run: no changes will be written");
    }

    /* Named failures, not just a count: "1 problem" is useless without it. */
    std::vector<std::wstring> failures;
    DriverClient client;
    bool driverReady = false;
    bool taskArmed = false;

    if (!options.noDriver) {
        const KernelGate gate = InspectKernel(options.driverPath);
        const DWORD startType = options.perma ? SERVICE_AUTO_START : SERVICE_DEMAND_START;
        util::Log(util::Level::Step,
                  options.perma ? L"Driver (AUTO_START, perma)" : L"Driver (demand start)");
        util::Logf(util::Level::Info, L"  platform: Secure Boot %ls, test signing %ls, image %ls",
                   OnOff(gate.secureBoot).c_str(), OnOff(gate.testSigning).c_str(),
                   gate.signer.empty() ? L"unsigned" : gate.signer.c_str());
        if (!gate.canStart) {
            util::Logf(util::Level::Warn, L"  expected: %ls", gate.blocker.c_str());
            util::Log(util::Level::Info,
                      L"  boot configuration is left alone; a refused load is rolled back");
        }

        if (options.dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would install %ls and attach filters",
                       options.driverPath.c_str());
            driverReady = true;
        } else if (!DriverClient::InstallAndStart(options.driverPath, startType, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            util::Log(util::Level::Warn, L"  Continuing with registry and network only.");
            failures.push_back(gate.tag.empty() ? std::wstring(L"kernel surfaces")
                                                : L"kernel surfaces (" + gate.tag + L")");
        } else {
            util::Log(util::Level::Ok, L"  service running");
            driverReady = client.Open(error);
            if (!driverReady) {
                util::Logf(util::Level::Error, L"  %ls", error.c_str());
                failures.push_back(L"kernel device");
            }
        }
    } else {
        util::Log(util::Level::Info, L"Driver disabled by --no-driver");
    }

    if (!options.noNetwork) {
        util::Log(util::Level::Step, L"Network adapters");
        size_t written = 0;
        if (!NetworkSpoofer::Apply(identity, options.dryRun, written, error)) {
            util::Logf(util::Level::Warn, L"  %ls", error.c_str());
        }

        if (!options.noRestart && !options.dryRun && written > 0) {
            std::vector<std::wstring> guids;
            for (const MacAssignment& adapter : identity.adapters) {
                guids.push_back(adapter.adapterGuid);
            }
            if (!NetworkSpoofer::RestartAdapters(guids, error)) {
                util::Logf(util::Level::Warn, L"  %ls", error.c_str());
            }
        }
    }

    if (!options.noRegistry) {
        util::Log(util::Level::Step, L"Registry identity");
        RegistrySpoofer spoofer;
        if (!spoofer.Apply(identity, options.dryRun, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"registry");
        }
    }

    /*
     * The firmware table is a registry value, so this half of the SMBIOS
     * surface lands without the driver. WMI and GetSystemFirmwareTable('RSMB')
     * both read what is written here.
     */
    if (!options.noRegistry) {
        util::Log(util::Level::Step, L"SMBIOS table (user mode)");
        smbios::Result table;
        if (!smbios::Apply(identity, options.dryRun, table, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"smbios table");
        }
    }

    if (driverReady) {
        util::Log(util::Level::Step, L"Driver configuration");
        const HWID_CONFIG config = BuildConfig(identity, options);
        if (options.dryRun) {
            util::Logf(util::Level::Info, L"  dry-run: would send %zu bytes, flags 0x%08lX",
                       sizeof(config), config.Flags);
        } else if (!client.SetConfig(config, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"driver config");
        } else {
            util::Log(util::Level::Ok, L"  configuration applied");
        }
        client.Close();
    }

    /*
     * Perma without a driver. mssmbios republishes the firmware table at every
     * boot, so the rewrite has to happen again after it does; a SYSTEM ONSTART
     * task is what makes the identity survive a reboot on a machine whose boot
     * policy refuses a locally signed kernel image.
     */
    if (options.perma && !options.noTask) {
        util::Log(util::Level::Step, L"Boot task (perma reapply)");
        if (options.dryRun) {
            util::Log(util::Level::Info,
                      L"  dry-run: would register a SYSTEM ONSTART task for --reapply");
        } else if (!smbios::InstallBootTask(util::ExePath(), error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"boot task");
        } else {
            taskArmed = true;
            util::Log(util::Level::Ok,
                      L"  \"HWID Spoofer Reapply\" runs as SYSTEM at every start");
        }
    }

    if (!options.dryRun) {
        util::Log(util::Level::Step, L"Saving profile");
        if (!SaveIdentity(options.profilePath, identity, error)) {
            util::Logf(util::Level::Error, L"  %ls", error.c_str());
            failures.push_back(L"profile save");
        } else {
            util::Logf(util::Level::Ok, L"  %ls", options.profilePath.c_str());
        }
    }

    if (!options.dryRun) {
        util::Log(util::Level::Step, L"Verification");
        std::vector<std::wstring> problems;
        size_t masked = 0;
        if (Verifier::Compare(identity, problems, &masked)) {
            util::Log(util::Level::Ok, L"  every live surface reads back as the profile");
            util::Log(util::Level::Info,
                      L"  no real identifier is exposed: all values above are the spoof");
        } else {
            for (const std::wstring& problem : problems) {
                util::Logf(util::Level::Warn, L"  %ls", problem.c_str());
            }
            util::Log(util::Level::Info, L"  Mismatches usually need a reboot / driver reload.");
            if (masked > 0) {
                if (util::Reveal()) {
                    util::Logf(util::Level::Warn,
                               L"  %zu real value(s) printed in clear; reveal is on.", masked);
                } else {
                    util::Logf(util::Level::Info,
                               L"  %zu real value(s) masked; this log holds no clear text.",
                               masked);
                }
            }
            if (util::Reveal()) {
                util::Log(util::Level::Info,
                          L"  (profile) lines are the spoof; [real] lines are this machine's id.");
            } else {
                util::Log(util::Level::Info,
                          L"  (profile) lines are the spoof; [real, masked] lines are what still");
                util::Log(util::Level::Info, L"  reads the machine's true id, shape only.");
            }
        }
    }

    if (failures.empty()) {
        if (options.perma && driverReady) {
            util::Log(util::Level::Ok,
                      L"Perma armed. The driver starts with Windows and reloads this identity.");
            util::Log(util::Level::Info,
                      L"Reboot once, then --status should show persisted=1 with no user action.");
        } else if (options.perma && taskArmed) {
            util::Log(util::Level::Ok,
                      L"Perma armed without the driver: the boot task reapplies this identity.");
            util::Log(util::Level::Info,
                      L"Reboot once, then --status should show the table rewritten, no user action.");
        } else {
            util::Log(util::Level::Ok,
                      L"Done. Reboot once so every consumer sees the new identity.");
        }
    } else {
        std::wstring names;
        for (const std::wstring& name : failures) {
            if (!names.empty()) {
                names += L", ";
            }
            names += name;
        }
        util::Logf(util::Level::Warn, L"Finished with %zu problem(s): %ls", failures.size(),
                   names.c_str());
        if (util::SecureBootEnabled()) {
            util::Log(util::Level::Info,
                      L"Secure Boot is untouched. Disk and volume serials need a Microsoft-signed "
                      L"image; registry, hostname, network and the SMBIOS table are applied and "
                      L"survive reboot.");
        }
    }
    g_lastIssues = failures;
    return failures.empty() ? 0 : 1;
}

const std::vector<std::wstring>& LastIssues()
{
    return g_lastIssues;
}

KernelGate InspectKernel(const std::wstring& driverPath)
{
    KernelGate gate;
    gate.secureBoot = util::SecureBootEnabled();
    gate.testSigning = util::TestSigningEnabled();
    gate.hvci = util::MemoryIntegrityEnabled();
    gate.serviceRunning = DriverClient::IsRunning();

    if (gate.serviceRunning) {
        gate.canStart = true;
        gate.summary = L"KERNEL: ACTIVE";
        return gate;
    }

    if (!util::FileExists(driverPath)) {
        gate.summary = L"KERNEL: NO DRIVER";
        gate.blocker = L"no driver image next to the executable";
        gate.tag = L"no driver";
        return gate;
    }

    const util::DriverSignature signature = util::InspectSignature(driverPath);
    gate.signerValid = signature.valid;
    gate.signerMicrosoft = signature.microsoft;
    gate.signer = signature.subject;
    gate.authority = signature.authority;

    /*
     * This is a prediction for the status badge and the plan. The kernel's
     * own answer at StartService time wins; this only avoids surprising the
     * reader with a refusal it could have named in advance.
     */
    if (!signature.valid) {
        gate.summary = L"KERNEL: UNSIGNED";
        gate.blocker = L"the driver image carries no valid signature";
        gate.tag = L"unsigned driver";
    } else if (signature.microsoft) {
        gate.canStart = true;
        gate.summary = L"KERNEL: MICROSOFT SIGNED";
    } else if (gate.secureBoot) {
        gate.summary = L"KERNEL: SECURE BOOT";
        gate.blocker = L"Secure Boot is on and this image carries a local signature";
        gate.tag = L"secure boot";
    } else if (!gate.testSigning) {
        gate.summary = L"KERNEL: TEST MODE OFF";
        gate.blocker = L"test signing is off, so Windows refuses the local signature";
        gate.tag = L"test signing off";
    } else {
        gate.canStart = true;
        gate.summary = L"KERNEL: TEST MODE";
    }
    return gate;
}

int Run(const Options& options)
{
    g_lastIssues.clear();
    util::SetReveal(options.reveal);
    if (options.reveal) {
        util::Log(util::Level::Warn,
                  L"Reveal is on: real values print in clear. Do not share this log.");
    }
    switch (options.mode) {
    case Mode::Spoof:
    case Mode::Reapply:
    case Mode::Install:
        return DoSpoof(options);
    case Mode::Restore:
        return DoRestore(options);
    case Mode::Uninstall:
        return DoUninstall(options);
    case Mode::Verify:
        return DoVerify(options);
    case Mode::Status:
        return DoStatus(options);
    case Mode::Unload:
        return DoUnload(options);
    case Mode::None:
        break;
    }
    PrintUsage();
    return 0;
}

} // namespace app

