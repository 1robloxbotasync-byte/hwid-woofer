#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "../shared/version.h"

namespace app {

/* Same string the resource scripts stamp into every image. */
inline constexpr wchar_t kVersion[] = HWID_VERSION_WIDE;

enum class Mode {
    None,
    Spoof,
    Reapply,
    Restore,
    Verify,
    Status,
    Unload,
    Install,
    Uninstall
};

struct Options {
    Mode mode = Mode::None;
    bool dryRun = false;
    bool noDriver = false;
    bool noRegistry = false;
    bool noNetwork = false;
    bool noTask = false;
    bool noRestart = false;
    bool keepProfile = false;
    bool perma = false;
    bool verbose = false;
    /* Explicit ask before real values are printed in clear. */
    bool reveal = false;
    uint64_t seed = 0;
    std::wstring profilePath;
    std::wstring driverPath;
};

// Fills the paths that depend on where the exe lives. Safe to call twice.
void ApplyDefaults(Options& options);

bool ParseArgs(int argc, wchar_t** argv, Options& options, std::wstring& error);
/* Decimal or 0x-prefixed hex; rejects zero and trailing garbage. */
bool ParseSeed(const std::wstring& text, uint64_t& seed);
void PrintUsage();

// Modes that must run elevated: driver, registry, network.
bool NeedsElevation(const Options& options);

// One mode per call, same behaviour as the CLI. Returns 0 on success.
int Run(const Options& options);

// True when a profile exists next to the exe.
bool ProfileExists(const Options& options);

/*
 * Named failures from the last Run(): "driver install", "registry", and so
 * on. The GUI shows these instead of a generic "see the log". Empty means
 * the last run had nothing to report.
 */
const std::vector<std::wstring>& LastIssues();

/*
 * What this machine will accept right now. Kernel surfaces need an image the
 * boot policy trusts; under Secure Boot that means a Microsoft signature and
 * nothing else. The tool reports this and adjusts its plan - it never edits
 * boot configuration to force a load.
 */
struct KernelGate {
    bool secureBoot = false;
    bool testSigning = false;
    bool hvci = false;
    bool signerValid = false;
    bool signerMicrosoft = false;
    bool serviceRunning = false;
    bool canStart = false;
    std::wstring signer;    // signing certificate, one line
    std::wstring authority; // chain root, one line
    std::wstring summary;   // short badge text: "KERNEL: ..."
    std::wstring blocker;   // why canStart is false, empty otherwise
    std::wstring tag;       // two or three words for status strips
};

KernelGate InspectKernel(const std::wstring& driverPath);

} // namespace app
