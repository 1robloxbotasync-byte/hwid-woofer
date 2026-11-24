# HWID Spoofer (perma build)

Kernel-assisted hardware identity replacement for Windows 11 x64.

| Piece | What it does |
|---|---|
| `exe/storhlp.sys` | WDM filter driver: disk serials, volume serials, SMART/ATA identify, SMBIOS table, `HARDWARE\DESCRIPTION\System\BIOS` |
| `exe/hwidspoof.exe` | GUI: buttons for spoof, perma install, reapply, verify, status, restore, uninstall |
| `exe/hwidspoof-cli.exe` | same engine, scriptable: identity generation, perma install, registry + SMBIOS + MAC + EDID writes, verification |

The SMBIOS table has two paths: the driver rewrites it from ring 0, and the
same rewrite runs in user mode on `mssmbios\Data\SMBiosData`. The user-mode
path needs no kernel image, so WMI and `Win32_BIOS` / `Win32_BaseBoard` /
`Win32_PhysicalMemory` read the new identity even on a machine whose boot
policy refuses the driver.

Everything lives in `exe/` — that is the folder you copy to another machine.
The driver is copied into `System32\drivers\` on install so perma mode loads
before anyone logs in.

Nothing is written to firmware. Every change is either in memory (disk/volume
path) or in a value that is snapshotted first and restored on `--uninstall`.

---

## Coverage

| Surface | Where it is intercepted | Read by |
|---|---|---|
| Physical disk serial | `IOCTL_STORAGE_QUERY_PROPERTY` → `SerialNumberOffset` | `Win32_DiskDrive`, most ACs |
| Disk serial (SMART) | `IOCTL_SMART_RCV_DRIVE_DATA` + IDENTIFY words 10–19 | SMART tooling, some ACs |
| Disk serial (ATA) | `IOCTL_ATA_PASS_THROUGH` + IDENTIFY at `DataBufferOffset + 20` | low-level scanners |
| Volume serial | `IRP_MJ_QUERY_VOLUME_INFORMATION` / `FileFsVolumeInformation` | `GetVolumeInformation`, any serial hash |
| SMBIOS UUID + board/chassis/memory serials + BIOS strings | `mssmbios\Data\SMBiosData` rewritten in place by the driver, or from user mode when the driver cannot load; original restored on clear/unload/`--restore` | `Win32_BaseBoard`, `Win32_BIOS`, `Win32_PhysicalMemory`, `MSSmBios` |
| `HARDWARE\DESCRIPTION\System\BIOS` | driver rewrites it on every apply and again at boot | registry readers |
| Monitor EDID serial | bytes 0x0C–0x0F of every cached EDID blob, checksums resealed | display hashes |
| MachineGuid, ProductId, InstallDate, HwProfileGuid, SQMClient MachineId | registry | Windows / AC fingerprints |
| Windows Update `SusClientId` | registry | update-client correlation, some ACs |
| `ComputerHardwareId` + `SystemInformation` mirror | registry | WMI / hardware fingerprint hashes |
| Computer name, both live and pending keys | registry + `SetComputerNameExW` | telemetry, server-side correlation |
| NIC MAC | `NetworkAddress` on the adapter driver key + miniport restart | `Win32_NetworkAdapter`, ARP-side checks |

### SMBIOS from user mode

`mssmbios` publishes the raw firmware table as
`HKLM\SYSTEM\CurrentControlSet\Services\mssmbios\Data\SMBiosData`, and every
WMI SMBIOS class reads that value. The rewrite therefore does not need ring 0:

- the table is parsed into structures (types 0, 1, 2, 3, 17, 127), bounds
  checked, and refused if it does not walk cleanly — a table that fails the walk
  is never patched;
- BIOS vendor/version/date, system manufacturer/product/version/serial/SKU/
  family, the system UUID, board manufacturer/product/version/serial, chassis
  manufacturer/version/serial and every DIMM serial are replaced;
- strings are re-emitted at their new length instead of padded to the old one.
  SMBIOS is self-describing, so nothing observable shifts, and padding would
  truncate a long vendor string into a short board's slot;
- the type-127 structure-table checksum is resealed when that structure carries
  the checksum byte;
- the original bytes are captured before the first rewrite, DPAPI-sealed in
  `smbios_orig.bin`, and written back by `--restore`. A table that is already
  spoofed when the tool first runs is **not** captured, so a restore can never
  write a spoof back and call it firmware.

### Redaction

Live values are read back through the same APIs an anti-cheat uses, and any
value that does not match the stored profile is the machine's real one. Those
values never leave the process in clear text:

- `--verify`, the GUI log and `hwidspoof.log` print the shape (`****-****-…`),
  never the bytes. Only values equal to the spoofed profile print in full.
- Reverse spoof (`--restore`) writes the originals back and logs them the same
  way: `restored MachineGuid -> ****…  [real, masked]`.
- `--reveal` on the CLI, or the `reveal reals` tick in the GUI, prints those
  values in clear instead of masking them. It is off on every start, it only
  affects the lines printed after it is enabled, and the log says so when it is
  on: `[real]` instead of `[real, masked]`. Use it to read this machine's own
  identifiers; do not share that log.
- The registry backup (`backup.ini`) holds the originals, so it is encrypted
  with DPAPI (`CryptProtectData`) for the current user. `--restore` decrypts
  it; another account cannot read it. Old plain-text backups still restore.
- The profile (`profile.ini`) contains the generated identity only.
- A profile that arrives from another machine is named in the log: no captured
  originals and an intact firmware table mean it has no history here, so the
  run says it would write someone else's identity before it does.

### Not covered

- `GetSystemFirmwareTable('RSMB')` reads the kernel's own cached table, not the
  registry value. A checker that uses it directly still sees real firmware.
- TPM endorsement key, EFI variables, GPU board serial / NVML UUID, router MAC.
  Each needs its own hook; none of them are in this build.
- Anything that hashes the CPUID leaf or the SMBIOS *in kernel mode* directly.

---

## Secure Boot

Secure Boot is firmware policy: it loads only images chained to a Microsoft
root. This tool reads that state and never changes it. No boot setting is
written by the GUI or the CLI: no `bcdedit`, no `testsigning`, no root-store
writes at apply time.

Two tiers, decided at runtime:

| Tier | Needs | Surfaces |
|---|---|---|
| User-mode | nothing | MachineGuid, ProductId, InstallDate, HwProfileGuid, SQMClient, SusClientId, ComputerHardwareId, SystemInformation, ComputerName, MACs, SMBIOS table |
| Kernel | a Microsoft-signed `storhlp.sys` | disk and volume serials, SMART/ATA identify, `HARDWARE\DESCRIPTION\System\BIOS` |

On a Secure Boot machine the header shows the state as a badge: `KERNEL:
SECURE BOOT`, `KERNEL: TEST MODE`, `KERNEL: MICROSOFT SIGNED` or `KERNEL:
ACTIVE`. The engine:

1. reads Secure Boot, test signing, HVCI and the image's signing chain;
2. still attempts the load — the kernel's answer is authoritative;
3. on refusal touches no boot configuration, deletes the service and the
   copied image, and continues with the user-mode surfaces;
4. names the result in the status strip: `kernel surfaces (secure boot)`.

Safety properties worth knowing:

- The service is created `DEMAND_START` and switched to `AUTO_START` only
  after the kernel accepts the image. A refused driver can never sit in the
  boot path.
- A failed load rolls back: service object and `System32\drivers\storhlp.sys`
  are removed, so the next boot is exactly the boot before.
- User-mode surfaces are ordinary registry and NIC values; they persist across
  a reboot without a driver and without touching firmware.

Kernel surfaces on a Secure Boot machine require an attestation- or
WHQL-signed image from Microsoft. That is the only route; a locally signed
driver does not load while Secure Boot is enforcing.

---

## Build

- Visual Studio 2022, **Desktop development with C++**
- **Windows Driver Kit** for the `.sys` (VS installer → Individual components)
- Windows SDK 10.0.26100+
- Admin rights for install, signing and any apply

```powershell
.\build.ps1              # GUI + CLI + driver + setup (driver skipped when no WDK)
.\build.ps1 -UserOnly    # GUI + CLI + setup, no driver
.\build.ps1 -NoSetup     # skip the installer
.\build.ps1 -Sign        # build + sign with a generated test certificate
.\build.ps1 -Install     # sign, and trust/test-sign only when Secure Boot is off

# release signing: payloads first, then the setup that embeds them
.\build.ps1 -Certificate .\codesign.pfx -CertificatePassword '...'
$env:HWID_SIGN_CERT = '.\codesign.pfx'; $env:HWID_SIGN_PASSWORD = '...'; .\build.ps1
```

Output: `exe\hwidspoof.exe` (GUI), `exe\hwidspoof-cli.exe` (console),
`exe\storhlp.sys`, `exe\hwidspoof-setup.exe`, and a versioned copy at
`dist\HWID-Spoofer-Setup-<version>.exe`.

Signing happens in dependency order: each payload is signed as it is built, and
the installer is signed last, so the copies inside the setup image are already
signed when they land on disk. A release certificate also gets an RFC 3161
timestamp (`-TimestampUrl`, default DigiCert) so the signature outlives the
certificate. The self-signed test certificate skips the timestamp — no public
chain, nothing to countersign.

The WDK bundle does not always register its Visual Studio toolset for Build
Tools. When `WindowsKernelModeDriver10.0` is missing the script falls back to
`cl /kernel` + `link /DRIVER` with the WDK `km` headers and import libs, which
is the same toolchain MSBuild would invoke.

Both exes are `/std:c++20 /W4 /permissive-` and statically linked (`/MT`).

### Signing

Windows will not load an unsigned kernel driver.

1. **Test signing** — `.\build.ps1 -Install`, reboot. Creates a self-signed
   cert, signs, trusts it in `LocalMachine\Root`, runs
   `bcdedit /set testsigning on`. This only works with Secure Boot off, and the
   script checks: when Secure Boot is on it signs the driver and stops there,
   because `testsigning` cannot be enabled under firmware policy and forcing
   boot settings is not something this tool does.
2. **Real certificate** — sign `exe/storhlp.sys` with an EV/attestation
   certificate and submit through the Hardware Dev Center. This is the only
   build that loads with Secure Boot on.

If Memory Integrity (HVCI) is on, the driver must be properly signed and
HVCI-compatible before it loads.

---

## Installer

`dist\HWID-Spoofer-Setup-<version>.exe` is a self-contained native installer.
The GUI, CLI, README and driver are RCDATA resources inside the image; there is
no second file to keep track of and no bundled third-party installer stub.

Double-click, confirm UAC (`requireAdministrator` is in its manifest), and it
installs to `%ProgramFiles%\HWID Spoofer`:

| Step | Result |
|---|---|
| Extract | `hwidspoof.exe`, `hwidspoof-cli.exe`, `README.md`, `storhlp.sys` (when built) into the install directory |
| Uninstall entry | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\HWIDSpoofer` with size, version, publisher, install date |
| Start Menu | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\HWID Spoofer.lnk` |
| Desktop | `%PUBLIC%\Desktop\HWID Spoofer.lnk` |
| Copy of setup | `<install dir>\setup.exe`, which is what Add/Remove Programs runs |

Installing never applies an identity. It puts the tool on the machine; the
spoof is still a separate click or a separate `--install`.

Shortcuts go through `IShellLink`. The install job runs on a worker thread, so
`CreateShortcut` opens its own COM apartment instead of borrowing the window's —
apartments do not cross threads, and the previous build failed every shortcut
with `CO_E_NOTINITIALIZED` while reporting a successful install. If OLE refuses
in-process anyway, the same binary re-runs itself with `/mklink=` and retries in
a clean process; if both attempts fail the log says so and the status line stops
claiming a Start Menu entry exists.

### Switches

```powershell
.\HWID-Spoofer-Setup-2.4.1.exe                        # interactive window
.\HWID-Spoofer-Setup-2.4.1.exe /quiet                 # no window, exit code only
.\HWID-Spoofer-Setup-2.4.1.exe /quiet /dir=D:\apps\hwid
.\HWID-Spoofer-Setup-2.4.1.exe /uninstall              # uninstall window
.\HWID-Spoofer-Setup-2.4.1.exe /uninstall /quiet       # scripted removal
.\HWID-Spoofer-Setup-2.4.1.exe /quiet /nodriver        # skip storhlp.sys
.\HWID-Spoofer-Setup-2.4.1.exe /quiet /nodesktop       # no desktop shortcut
.\HWID-Spoofer-Setup-2.4.1.exe /install /quiet         # start the job without a click
```

`/quiet` is the only headless mode. `/uninstall` alone still shows the window
so a user gets the confirmation and the log. Exit code is 0 on success, 1 on
failure, and in `/quiet /uninstall` the launcher waits for the temp copy and
returns its real code.

`/mklink=<path> /target=<exe>` is the shortcut helper the installer spawns for
itself when `IShellLink` fails in-process. It writes one link and exits; it never
touches the registry or the install directory.

An upgrade reads `InstallLocation` back out of the uninstall key, so running a
newer setup over an existing one lands in the same directory and refreshes the
uninstall entry rather than leaving two.

`/quiet` writes a transcript to `%TEMP%\hwidspoof-setup.log`. An elevated child
does not inherit a script's redirected stdout, so the file is the record that
survives; the console gets the same lines when one is attached.

### Uninstall

Add/Remove Programs runs `<install dir>\setup.exe /uninstall`. Windows will not
delete a running image, so when setup starts from inside the install directory
it renames itself to `%TEMP%\hwidspoof-uninstall-<pid>.exe` and relaunches
there. A rename is allowed while the image runs, and it leaves the install
directory with nothing locked — the directory is removed completely, not
deferred to the next reboot. The temp copy then:

1. runs `hwidspoof-cli.exe --restore --no-driver --no-network` — puts every
   backed-up value back and deletes `smbios_orig.bin`;
2. runs `hwidspoof-cli.exe --uninstall --no-driver --no-network` — removes the
   service key, the boot task, the stored driver config and the copied image;
3. deletes the shortcuts, the uninstall entry, and the install directory.

Step 1 and 2 both run before any file is removed; a machine whose driver never
loaded still gets its registry, hostname, MAC and SMBIOS table restored. The
temp copy schedules itself with `MOVEFILE_DELAY_UNTIL_REBOOT` and drops a
`RunOnce` cleanup, so `%TEMP%` is clear after the next boot. If a scanner is
holding a file open, the directory removal falls back to the same RunOnce path
and the log says so.

---

## Perma mode

```powershell
.\exe\hwidspoof.exe --install            # new identity, armed for every boot
.\exe\hwidspoof.exe --install --seed 0x8f3ac21d55be0197
.\exe\hwidspoof.exe --perma              # arm the existing profile
```

What `--install` sets up:

1. The identity is generated and written to `profile.ini`.
2. `storhlp.sys` is copied to `System32\drivers\`.
3. The service is created `DEMAND_START` and started; only after the kernel
   accepts the image is it switched to `SERVICE_AUTO_START`. A refusal deletes
   both the service and the copied image.
4. The full `HWID_CONFIG` is stored as `HKLM\SYSTEM\CurrentControlSet\Services\StorHlp\Parameters\Config`.
5. Registry, hostname, MAC, EDID and the SMBIOS table are applied immediately.
6. A `HWID Spoofer Reapply` scheduled task is registered: SYSTEM, `ONSTART`,
   running `hwidspoof --reapply --no-driver --no-network --no-task`.

At every boot the driver loads before logon, reads the stored config, rebuilds
the SMBIOS image (mssmbios regenerates the registry value from firmware during
boot), rewrites `HARDWARE\DESCRIPTION\System\BIOS` and attaches the storage
filters. Disk, volume and SMBIOS reads are then spoofed from the first IOCTL —
no user action, no CLI run.

The scheduled task is the same idea one tier down. When the boot policy refuses
the kernel image, mssmbios still republishes the firmware table at every boot,
so the task rewrites it again from user mode after that happens; WMI keeps
reading the new identity across reboots without a driver. Both paths can be
armed at once: they write the same identity, so whichever runs last wins and
the result is identical.

A plain `--spoof` deletes the stored config, so the two modes never fight.

### Uninstall

```powershell
.\exe\hwidspoof.exe --uninstall     # restore, delete config, remove service + image
```

Order matters and the CLI enforces it: driver config and SMBIOS table first,
then the service, then the boot task, then registry/NIC/EDID from `backup.ini`.

---

## Usage

Double-click `hwidspoof.exe`. It asks for admin up front, then gives you:

| Button | Does |
|---|---|
| Spoof now | new identity, driver on demand, everything applied |
| Install perma | new identity, driver AUTO_START, config stored in the service key |
| Reapply | push the stored profile again |
| Verify | read every surface back and compare to the profile |
| Status | boot policy, SMBIOS table state, boot task, driver filters, persisted flag |
| Reverse spoof | put the real values back, log them masked, keep the service |
| Restart PC | reboot now; registry, hostname and volume changes settle on boot |
| Uninstall | restore, delete stored config, remove service + image |

The header carries the live kernel state as a badge — `KERNEL: ACTIVE`,
`KERNEL: SECURE BOOT`, `KERNEL: TEST MODE OFF`, `KERNEL: NO DRIVER` — so the
answer to "can this machine take kernel surfaces" is visible before any click.

Checkboxes: `skip driver`, `skip registry`, `skip network`, `dry run`. The seed
box is optional; empty means a fresh random seed. Every line the engine emits
lands in the log pane live, and in `hwidspoof.log`.

The window runs one job at a time; buttons disable until the worker finishes.
When a job ends with a failure the status strip names the component (`kernel
surfaces (secure boot)`, `registry restore`, `15 surface(s) still read real
(masked, secure boot)`) instead of pointing at the log.

### CLI

`hwidspoof.exe` also accepts the same arguments as `hwidspoof-cli.exe` and runs
headless when given any.

```powershell
.\exe\hwidspoof-cli.exe --spoof          # one-shot identity, demand-start driver
.\exe\hwidspoof-cli.exe --install        # perma: AUTO_START + stored config
.\exe\hwidspoof-cli.exe --reapply        # re-push the stored profile
.\exe\hwidspoof-cli.exe --verify         # compare live values to the profile
.\exe\hwidspoof-cli.exe --status         # filters, SMBIOS state, persisted flag
.\exe\hwidspoof-cli.exe --restore        # put everything back
.\exe\hwidspoof-cli.exe --unload         # stop and delete the service only
.\exe\hwidspoof-cli.exe --uninstall      # restore + remove service and image
```

Flags: `--dry-run`, `--no-driver`, `--no-registry`, `--no-network`,
`--no-task`, `--no-restart`, `--keep-profile`, `--profile <path>`, `--driver <path>`,
`--seed <hex>`, `-v`.

`--status` after a reboot should report `persisted config   1` and non-zero
filter counts with no CLI run since boot. That is the proof perma mode is live.
On a machine without the driver it should report the SMBIOS table rewritten
with `profile fields 21 of 21` and the boot task installed.

### Files

| File | Purpose |
|---|---|
| `profile.ini` | generated identity: seed, serials, UUIDs, MACs |
| `backup.ini` | originals, DPAPI-encrypted, written once, deleted by `--uninstall` |
| `smbios_orig.bin` | firmware SMBIOS table, DPAPI-encrypted, written once, deleted by `--restore` |
| `hwidspoof.log` | append-only run log, real values masked |

`backup.ini` is created on the first apply and never overwritten, so a second
spoof cannot destroy the true originals. It is encrypted for the current user:
`--restore` can read it, another account cannot.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | applied (or verified) |
| 1 | at least one component failed; the log names it |

The CLI self-elevates via `ShellExecuteEx(runas)` and returns the child code.
The GUI relaunches itself elevated at startup and exits the unelevated copy.

---

## Layout

```
shared/hwid_ioctl.h     driver <-> user ABI, names, IOCTLs
shared/version.h        version and publisher strings, single source
driver/hwid_drv.c       WDM driver, single translation unit
driver/hwid_drv.rc      driver VERSIONINFO (shows in file properties)
driver/hwid_drv.vcxproj MSBuild project (TargetName storhlp)
user/main.cpp           CLI entry: args, elevation, dispatch
user/gui.cpp            Win32 window, buttons, log pane, worker thread
user/app.rc / app.ico   Explorer icon + VERSIONINFO for the GUI build
user/cli.rc             VERSIONINFO for the CLI build
user/app.manifest       asInvoker, Win10/11 compat, system DPI, long paths
user/app.h / app.cpp    shared engine: options, modes, perma teardown
user/identity.*         seeded identity generation, INI profile I/O
user/registry.*         registry + BIOS key + EDID, byte-exact backup
user/smbios.*           SMBIOS table rewrite from user mode, boot task
user/network.*          adapter enumeration, NetworkAddress, miniport restart
user/verify.*           live read-back of every surface
user/driver_client.*    SCM install/start/stop, image copy, IOCTL client
user/util.*             logging, UTF-8, handles, elevation, RNG
packaging/setup.cpp     installer: payload extraction, shortcuts, uninstall
packaging/setup.rc      setup icon + VERSIONINFO
packaging/setup.manifest requireAdministrator
packaging/verify-build.ps1  hashes, signature state, Defender scan, submission
build.ps1               builds both halves, the setup, signing helpers
```

### Driver internals

- Device `\Device\StorHlp`, symlink `\DosDevices\StorHlp`, service `StorHlp`.
  Names are deliberately boring — they appear in the service list and in
  loaded-module enumeration.
- Filters attach to `\Device\HarddiskN\DR0`, `\Device\HarddiskN\Partition1..8`
  and `\??\X:` for every letter, and detach in `DriverUnload`.
- `IRP_MJ_DEVICE_CONTROL` is patched in the completion routine, after the lower
  stack filled the buffer.
- SMBIOS strings are rewritten in place, padded to their original length, so
  every structure offset stays valid and no string table is rebuilt.
- The table start is found by walking four structures and requiring each string
  set to terminate; the 8-byte `mssmbios` header cannot pass that check.
- Config sits behind a spinlock; the SMBIOS image behind an `ERESOURCE`
  because rebuilding touches paged pool and the registry.
- Clearing config or unloading writes the original firmware bytes back before
  the snapshot is freed.

---

## Notes on detection

- The driver is a non-Microsoft kernel module. That is the loudest remaining
  signal: enumeration of loaded drivers, `.sys` on disk, or a signature check
  will show it. Renaming things does not make it invisible.
- Some checks hash several sources and compare them. Keep the CLI order
  (network → registry/EDID → driver config) so nothing is stale.
- Reboot once after the first install. Host name, volume serial caches and
  every boot-time consumer only settle then.
- Re-spoofing without a reboot leaves stale caches in services that already
  read the old values.

---

## False positives

A tool that rewrites hardware identity and installs a kernel service is going
to be looked at closely by scanners. Some of those verdicts are earned by
behaviour; some are just name matching. Both are worth knowing about before
shipping a build to someone else.

### What the build already does

| Measure | Where | What it fixes |
|---|---|---|
| `VERSIONINFO` on every image, driver included | `shared/version.h` → each `.rc` | files with no company, no description and a generic name are a heuristic hit on their own |
| Embedded manifests | `user/app.manifest`, `packaging/setup.manifest` | a signed-looking setup with no `requestedExecutionLevel` looks like a packed dropper |
| `/guard:cf`, `/CETCOMPAT`, `/Brepro` | `build.ps1` | CFG + CET are what a modern MSVC build has; `-Brepro` stops the binary hash changing on every rebuild for identical source, which matters when you submit a file to a vendor and then rebuild |
| Authenticode with RFC 3161 timestamp | `build.ps1 -Certificate` | the only build-side change that actually moves a reputation verdict |
| `storhlp.sys` named and described as a storage filter | `driver/hwid_drv.rc` | the driver presents as what it is rather than as an unnamed module |

### What it does not do

- **No packing, no cryptor, no stub.** A crypter hides a payload from a static
  scan; it also gets flagged by every emulator in the first ten seconds, and the
  verdict is worse than the one it was hiding from. The setup carries its
  payloads as plain `RCDATA`, extractable with any resource tool.
- **No process hollowing, no injection, no persistence outside its own
  uninstall entry and boot task.**
- **No anti-analysis tricks.** Nothing checks for debuggers, VMs, sandbox
  usernames or scan tooling.

### What actually removes the detections

1. **Sign it with a real certificate and timestamp it.** An unsigned or
   self-signed binary that installs a `SYSTEM`-start service gets a generic
   `Trojan:Win32/Wacatac` or `HackTool` verdict from heuristics alone.
   `.\build.ps1 -Certificate codesign.pfx` is the whole change.
2. **Submit the exact build to Microsoft.** Hashes are per-file, so submit the
   files you are actually distributing, not a rebuild.
   `.\packaging\verify-build.ps1 -Submit` writes the SHA-256 table, opens the
   portal and puts the hashes on the clipboard:

   <https://www.microsoft.com/en-us/wdsi/filesubmission>

   File it as a false positive, name the file, and say what it is: a local
   hardware identity tool, user-owned values, no self-propagation, no remote
   target. Turnaround is usually a day or two, and the verdict applies to that
   hash — a rebuild needs a resubmission.
3. **Let SmartScreen reputation accumulate.** A new certificate has no
   reputation, so the first downloads warn regardless of the signature. That
   fades with download volume; there is no way to buy it.
4. **Do not rename the binaries between releases.** Reputation is per-file-path
   and per-hash. `hwidspoof.exe` staying `hwidspoof.exe` is worth more than a
   cleverer name.

For the driver specifically: a non-Microsoft kernel module on disk is visible
to any integrity check and no naming choice changes that. The only build that
loads clean under Secure Boot is an attestation-signed one from the Hardware Dev
Center.

### Checking a build before you hand it over

```powershell
.\build.ps1 -Certificate .\codesign.pfx -CertificatePassword '...'
.\packaging\verify-build.ps1
```

That prints a SHA-256 table, the Authenticode status and signer of every image,
scans the release folder with Defender, and writes `SHA256SUMS.txt` next to the
artifacts. `-Submit` adds the portal step.

If a third-party engine flags it and Microsoft does not, submit that hash to the
engine directly — every vendor has a false-positive form and they act on
specific hashes, not on arguments.

