<#
    build.ps1 - builds hwidspoof.exe, hwidspoof-cli.exe, hwidspoof-setup.exe
    (always) and storhlp.sys (when the WDK is present).

    Examples:
        .\build.ps1                          # everything the toolchain allows
        .\build.ps1 -UserOnly                # GUI + CLI + setup, no driver
        .\build.ps1 -NoSetup                 # skip the installer
        .\build.ps1 -Sign                    # local test cert, signs every image
        .\build.ps1 -Install                 # sign + enable test signing + reboot prompt

    Release signing (the only thing that actually moves a false-positive
    verdict on other people's machines):

        .\build.ps1 -Certificate .\codesign.pfx -CertificatePassword '...'
        # or set $env:HWID_SIGN_CERT / $env:HWID_SIGN_PASSWORD

    Every image is signed in dependency order: payloads first, then the setup
    that embeds them, so the copies inside the installer are the signed ones.
#>
[CmdletBinding()]
param(
    [switch]$UserOnly,
    [switch]$DriverOnly,
    [switch]$NoSetup,
    [switch]$Sign,
    [switch]$Install,
    [string]$Certificate,
    [string]$CertificatePassword,
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $root 'exe'
$objDir = Join-Path $root 'obj'
$distDir = Join-Path $root 'dist'

$versionMatch = Select-String -Path (Join-Path $root 'shared\version.h') `
    -Pattern '^#define HWID_VERSION_STRING "([^"]+)"'
if (-not $versionMatch) { throw 'shared\version.h is missing HWID_VERSION_STRING.' }
$version = $versionMatch.Matches[0].Groups[1].Value

function Find-VcVars {
    $candidates = @()
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $paths = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        foreach ($p in $paths) {
            $candidates += (Join-Path $p 'VC\Auxiliary\Build\vcvars64.bat')
        }
    }
    $candidates += (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat')
    $candidates += (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat')
    $candidates += (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat')
    $candidates += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat')

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }
    throw 'vcvars64.bat not found. Install Visual Studio 2022 (Desktop C++ workload).'
}

function Find-WdkInclude {
    # The WDK lands in the same kit root as the SDK, but the root can be
    # relocated. WDKContentRoot wins, then both Program Files roots.
    $kitRoots = @()
    if ($env:WDKContentRoot) { $kitRoots += $env:WDKContentRoot.TrimEnd('\') }
    foreach ($programFiles in @(${env:ProgramFiles}, ${env:ProgramFiles(x86)})) {
        if ($programFiles) { $kitRoots += (Join-Path $programFiles 'Windows Kits\10') }
    }
    $kitRoots = $kitRoots | Select-Object -Unique

    $probed = @()
    foreach ($kitRoot in $kitRoots) {
        $include = Join-Path $kitRoot 'Include'
        $probed += $include
        if (-not (Test-Path $include)) { continue }
        $versions = Get-ChildItem $include -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending
        foreach ($versionDir in $versions) {
            # Headers and import libs both have to be there; a half install
            # (headers only) cannot link and should not count.
            $kmInclude = Join-Path $versionDir.FullName 'km'
            $kmLib = Join-Path $kitRoot ('Lib\' + $versionDir.Name + '\km')
            if ((Test-Path $kmInclude) -and (Test-Path $kmLib)) {
                return [pscustomobject]@{
                    Version = $versionDir.Name
                    Root    = $kitRoot
                    Probed  = $probed
                }
            }
        }
    }

    return [pscustomobject]@{
        Version = $null
        Root    = $null
        Probed  = $probed
    }
}

function Invoke-Cmd {
    param([string]$Command, [string]$Label)
    Write-Host "  $Label" -ForegroundColor DarkGray
    # A temp script keeps quoting out of PowerShell's native argument layer.
    $script = Join-Path $env:TEMP ('hwid_build_' + [guid]::NewGuid().ToString('N') + '.cmd')
    Set-Content -Path $script -Value "@echo off`r`n$Command" -Encoding Default
    try {
        cmd.exe /c $script
        if ($LASTEXITCODE -ne 0) {
            throw "$Label failed with exit code $LASTEXITCODE"
        }
    } finally {
        Remove-Item $script -Force -ErrorAction SilentlyContinue
    }
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
New-Item -ItemType Directory -Force -Path $objDir | Out-Null

$vcvars = Find-VcVars
Write-Host "toolchain: $vcvars" -ForegroundColor DarkGray
Write-Host "version:   $version" -ForegroundColor DarkGray

# ---------------------------------------------------------------------
# Signing identity, resolved once and used after each artifact exists.
# ---------------------------------------------------------------------

$signPfx = ''
$signPassword = ''
$usingTestCert = $false
if ($Certificate) { $signPfx = $Certificate }
elseif ($env:HWID_SIGN_CERT) { $signPfx = $env:HWID_SIGN_CERT }
if ($CertificatePassword) { $signPassword = $CertificatePassword }
elseif ($env:HWID_SIGN_PASSWORD) { $signPassword = $env:HWID_SIGN_PASSWORD }

$signtool = $null
function Get-SignTool {
    if ($script:signtool) { return $script:signtool }
    $found = $null
    $kitsBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    if (Test-Path $kitsBin) {
        $found = Get-ChildItem $kitsBin -Recurse -Filter signtool.exe |
            Where-Object { $_.FullName -like '*x64*' } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($found) { $found = $found.FullName }
    }
    if (-not $found) { throw 'signtool.exe not found. Install the Windows SDK.' }
    $script:signtool = $found
    return $found
}

function Invoke-Sign {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    if (-not $signPfx) { return }

    $tool = Get-SignTool
    $arguments = @('sign', '/fd', 'sha256')
    # Timestamping is what keeps the signature valid past the certificate's
    # expiry. It also needs the certificate chain to be publicly trusted,
    # so it is skipped for the local test cert.
    if (-not $usingTestCert) {
        $arguments += @('/tr', $TimestampUrl, '/td', 'sha256')
    }
    $arguments += @('/f', $signPfx, '/p', $signPassword, '/d', 'HWID Spoofer', $Path)

    $quoted = $arguments | ForEach-Object {
        if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
    }
    Invoke-Cmd "`"$tool`" $($quoted -join ' ')" ("sign " + (Split-Path -Leaf $Path))
}

if ($Sign -and -not $signPfx) {
    $signPfx = Join-Path $root 'hwidtest.pfx'
    $signPassword = 'hwidtest'
    $usingTestCert = $true
    if (-not (Test-Path $signPfx)) {
        Write-Host 'creating self-signed test certificate' -ForegroundColor Cyan
        $cert = New-SelfSignedCertificate -Type CodeSigningCert `
            -Subject 'CN=HWID Spoofer Test' `
            -KeyUsage DigitalSignature `
            -KeyAlgorithm RSA -KeyLength 2048 `
            -CertStoreLocation 'Cert:\CurrentUser\My' `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.5.5.7.3.6')
        $secure = ConvertTo-SecureString -String $signPassword -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath $signPfx -Password $secure | Out-Null
        Export-Certificate -Cert $cert -FilePath (Join-Path $root 'hwidtest.cer') | Out-Null
    }
}

if ($signPfx) {
    if (-not (Test-Path $signPfx)) { throw "signing certificate not found: $signPfx" }
    Write-Host ("signing:   {0}{1}" -f $signPfx, $(if ($usingTestCert) { ' (local test cert)' } else { '' })) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------
# User-mode binaries
# ---------------------------------------------------------------------

$builtExes = @()
if (-not $DriverOnly) {
    $commonSources = @(
        'user\app.cpp',
        'user\util.cpp',
        'user\identity.cpp',
        'user\registry.cpp',
        'user\smbios.cpp',
        'user\network.cpp',
        'user\verify.cpp',
        'user\driver_client.cpp'
    ) | ForEach-Object { '"' + (Join-Path $root $_) + '"' }

    $obj = Join-Path $objDir 'user\'
    New-Item -ItemType Directory -Force -Path $obj | Out-Null
    $libs = 'advapi32.lib bcrypt.lib crypt32.lib wintrust.lib setupapi.lib shell32.lib user32.lib gdi32.lib ole32.lib comctl32.lib dwmapi.lib uxtheme.lib'

    function Build-Exe {
        param([string]$Name, [string]$Entry, [string]$Subsystem, [string]$EntryPoint,
              [string]$Resource, [string]$Manifest)

        Write-Host "building $Name" -ForegroundColor Cyan
        $sources = @(('"' + (Join-Path $root $Entry) + '"')) + $commonSources
        $target = Join-Path $outDir $Name
        $flags = @(
            '/nologo', '/std:c++20', '/W4', '/permissive-', '/EHsc', '/O2', '/MT',
            '/utf-8', '/DUNICODE', '/D_UNICODE', '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX',
            '/guard:cf',
            ('/Fe:"' + $target + '"')
        )
        $linkFlags = "/SUBSYSTEM:$Subsystem /MANIFEST:EMBED /guard:cf /CETCOMPAT /MANIFESTUAC:NO"
        if ($EntryPoint) { $linkFlags += " /ENTRY:$EntryPoint" }
        if ($Manifest) { $linkFlags += (' /MANIFESTINPUT:"' + (Join-Path $root $Manifest) + '"') }
        $resArg = ''
        if ($Resource) {
            $resFile = Join-Path $obj 'app.res'
            Invoke-Cmd "call `"$vcvars`" >nul && cd /d `"$obj`" && rc /nologo /fo `"$resFile`" `"$(Join-Path $root $Resource)`"" "resource $Name"
            $resArg = ' "' + $resFile + '"'
        }
        Invoke-Cmd "call `"$vcvars`" >nul && cd /d `"$obj`" && cl $($flags -join ' ') $($sources -join ' ')$resArg /link $linkFlags $libs" "compile $Name"

        $bytes = [System.IO.File]::ReadAllBytes($target)
        Write-Host ("  built {0} ({1:N0} bytes)" -f $target, $bytes.Length) -ForegroundColor Green
    }

    Build-Exe -Name 'hwidspoof.exe' -Entry 'user\gui.cpp' -Subsystem 'WINDOWS' `
        -EntryPoint 'wWinMainCRTStartup' -Resource 'user\app.rc' -Manifest 'user\app.manifest'
    Build-Exe -Name 'hwidspoof-cli.exe' -Entry 'user\main.cpp' -Subsystem 'CONSOLE' `
        -EntryPoint '' -Resource 'user\cli.rc' -Manifest 'user\app.manifest'

    $builtExes = @((Join-Path $outDir 'hwidspoof.exe'), (Join-Path $outDir 'hwidspoof-cli.exe'))
    if ($signPfx) {
        foreach ($exe in $builtExes) { Invoke-Sign -Path $exe }
    }
}

# ---------------------------------------------------------------------
# Kernel driver
# ---------------------------------------------------------------------

$driverPath = Join-Path $outDir 'storhlp.sys'
if (-not $UserOnly) {
    Write-Host 'building storhlp.sys' -ForegroundColor Cyan
    $wdk = Find-WdkInclude
    if (-not $wdk.Version) {
        Write-Host '  WDK not installed - skipping kernel driver.' -ForegroundColor Yellow
        foreach ($path in $wdk.Probed) {
            Write-Host ("  looked in {0}" -f $path) -ForegroundColor DarkGray
        }
        Write-Host '  A Windows SDK alone is not enough: the driver needs km headers, km libs' -ForegroundColor Yellow
        Write-Host '  and the WindowsKernelModeDriver10.0 toolset.' -ForegroundColor Yellow
        Write-Host '  winget install --id Microsoft.WindowsWDK.10.0.26100 -e' -ForegroundColor Cyan
        $driverPath = $null
    } else {
        Write-Host ("  WDK {0} ({1})" -f $wdk.Version, $wdk.Root) -ForegroundColor DarkGray

        $vsRoots = @()
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path $vswhere) {
            $vsRoots = @(& $vswhere -latest -products * -property installationPath)
        }

        # The kernel toolset is a separate VSIX that the WDK bundle only
        # registers when it finds a full Visual Studio instance. Build Tools
        # often misses it, so detect it and fall back to cl/link with the WDK
        # headers and import libs, which is all MSBuild would have invoked.
        $toolset = $vsRoots |
            ForEach-Object {
                Join-Path $_ 'MSBuild\Microsoft\VC\v170\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0'
            } |
            Where-Object { Test-Path $_ } |
            Select-Object -First 1

        if ($toolset) {
            $msbuild = $vsRoots |
                ForEach-Object { Join-Path $_ 'MSBuild\Current\Bin\MSBuild.exe' } |
                Where-Object { Test-Path $_ } |
                Select-Object -First 1
            if (-not $msbuild) { throw 'MSBuild.exe not found.' }

            $project = Join-Path $root 'driver\hwid_drv.vcxproj'
            Invoke-Cmd "`"$msbuild`" `"$project`" /nologo /m /p:Configuration=Release /p:Platform=x64" 'msbuild'

            $sys = Join-Path $outDir 'Release\storhlp.sys'
            if (-not (Test-Path $sys)) { throw "driver output missing: $sys" }
            $driverPath = $sys
        } else {
            Write-Host '  kernel VS toolset not registered - building with cl/link' -ForegroundColor DarkGray
            $kmInclude = Join-Path $wdk.Root ('Include\' + $wdk.Version + '\km')
            $kmLib = Join-Path $wdk.Root ('Lib\' + $wdk.Version + '\km\x64')
            $source = Join-Path $root 'driver\hwid_drv.c'
            $object = Join-Path $objDir 'hwid_drv.obj'
            $resources = Join-Path $objDir 'hwid_drv.res'
            $sys = Join-Path $outDir 'storhlp.sys'
            Invoke-Cmd "call `"$vcvars`" >nul && cd /d `"$objDir`" && rc /nologo /fo `"$resources`" `"$(Join-Path $root 'driver\hwid_drv.rc')`"" 'resource storhlp.sys'
            $compile = "call `"$vcvars`" >nul && cl /nologo /kernel /c /W4 /GS- /D_AMD64_ " +
                "/DWIN32_LEAN_AND_MEAN /Fo`"$object`" /I`"$kmInclude`" /I`"$kmInclude\crt`" `"$source`""
            Invoke-Cmd $compile 'wdk-cl'
            $link = "call `"$vcvars`" >nul && link /nologo /DRIVER /SUBSYSTEM:NATIVE " +
                "/ENTRY:DriverEntry /LIBPATH:`"$kmLib`" /OUT:`"$sys`" `"$object`" `"$resources`" " +
                'ntoskrnl.lib hal.lib wdm.lib BufferOverflowK.lib ntstrsafe.lib'
            Invoke-Cmd $link 'wdk-link'
            if (-not (Test-Path $sys)) { throw "driver output missing: $sys" }
            $driverPath = $sys
        }
        Write-Host "  built $driverPath" -ForegroundColor Green
        if ($signPfx) { Invoke-Sign -Path $driverPath }
    }
}

# ---------------------------------------------------------------------
# Installer - built last, so the payloads it embeds are already signed
# ---------------------------------------------------------------------

$setupPath = Join-Path $outDir 'hwidspoof-setup.exe'
if (-not $NoSetup -and -not $DriverOnly) {
    Write-Host 'building hwidspoof-setup.exe' -ForegroundColor Cyan
    $setupObj = Join-Path $objDir 'setup\'
    New-Item -ItemType Directory -Force -Path $setupObj | Out-Null

    # Absolute paths, generated: rc resolves file names against its own
    # directory, and the build output must not depend on where rc runs.
    $payload = New-Object System.Collections.Generic.List[string]
    $payload.Add('// generated by build.ps1 - do not edit')
    # RC applies C escapes inside quoted strings, so a literal path has to
    # double its backslashes or \t in C:\temp silently becomes a tab.
    function ConvertTo-RcPath {
        param([string]$Path)
        return ($Path -replace '\\', '\\')
    }
    $payload.Add(('PAYLOAD_APP    RCDATA "{0}"' -f (ConvertTo-RcPath (Join-Path $outDir 'hwidspoof.exe'))))
    $payload.Add(('PAYLOAD_CLI    RCDATA "{0}"' -f (ConvertTo-RcPath (Join-Path $outDir 'hwidspoof-cli.exe'))))
    $payload.Add(('PAYLOAD_README RCDATA "{0}"' -f (ConvertTo-RcPath (Join-Path $root 'README.md'))))
    if ($driverPath -and (Test-Path $driverPath)) {
        $payload.Add(('PAYLOAD_SYS    RCDATA "{0}"' -f (ConvertTo-RcPath $driverPath)))
    }
    $payloadFile = Join-Path $setupObj 'payload.rc'
    Set-Content -Path $payloadFile -Value ($payload -join "`r`n") -Encoding ASCII

    $setupRes = Join-Path $setupObj 'setup.res'
    $payloadRes = Join-Path $setupObj 'payload.res'
    Invoke-Cmd "call `"$vcvars`" >nul && cd /d `"$setupObj`" && rc /nologo /fo `"$setupRes`" `"$(Join-Path $root 'packaging\setup.rc')`"" 'resource hwidspoof-setup.exe'
    Invoke-Cmd "call `"$vcvars`" >nul && cd /d `"$setupObj`" && rc /nologo /fo `"$payloadRes`" `"$payloadFile`"" 'resource payload'

    $setupFlags = @(
        '/nologo', '/std:c++20', '/W4', '/permissive-', '/EHsc', '/O2', '/MT',
        '/utf-8', '/DUNICODE', '/D_UNICODE', '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX',
        '/guard:cf',
        ('/Fe:"' + $setupPath + '"')
    )
    $setupLink = "/SUBSYSTEM:WINDOWS /MANIFEST:EMBED /guard:cf /CETCOMPAT /MANIFESTUAC:NO" +
        " /MANIFESTINPUT:`"$(Join-Path $root 'packaging\setup.manifest')`""
    $setupLibs = 'advapi32.lib shell32.lib ole32.lib user32.lib gdi32.lib dwmapi.lib uuid.lib'
    Invoke-Cmd ("call `"$vcvars`" >nul && cd /d `"$setupObj`" && cl $($setupFlags -join ' ') " +
        "`"$(Join-Path $root 'packaging\setup.cpp')`" `"$setupRes`" `"$payloadRes`" " +
        "/link $setupLink $setupLibs") 'compile hwidspoof-setup.exe'

    $bytes = [System.IO.File]::ReadAllBytes($setupPath)
    Write-Host ("  built {0} ({1:N0} bytes)" -f $setupPath, $bytes.Length) -ForegroundColor Green

    if ($signPfx) { Invoke-Sign -Path $setupPath }

    New-Item -ItemType Directory -Force -Path $distDir | Out-Null
    $distPath = Join-Path $distDir ("HWID-Spoofer-Setup-{0}.exe" -f $version)
    Copy-Item -Path $setupPath -Destination $distPath -Force
    Write-Host ("  packaged {0}" -f $distPath) -ForegroundColor Green
}

# ---------------------------------------------------------------------
# Boot-policy install (unchanged behaviour, refusal is reported not forced)
# ---------------------------------------------------------------------

if ($Install) {
    if (-not $driverPath -or -not (Test-Path $driverPath)) {
        throw 'Driver signing requires the WDK build.'
    }
    if (-not $signPfx) {
        throw '-Install needs a signature on the driver. Add -Sign or -Certificate.'
    }

    # Firmware policy decides this, not the script. Turning test signing
    # on under Secure Boot cannot work, and editing boot settings to force
    # it is exactly the machine-harming move this tool refuses to make.
    $secureBoot = $false
    try {
        $state = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop
        $secureBoot = ($state.UEFISecureBootEnabled -eq 1)
    } catch {
        $secureBoot = $false
    }

    if ($secureBoot) {
        Write-Host 'Secure Boot is on - boot configuration is left alone.' -ForegroundColor Yellow
        Write-Host '  test signing is not enabled, the test cert is not added to the root store,' -ForegroundColor Yellow
        Write-Host '  and bcdedit is not touched. Windows will refuse this local signature at boot.' -ForegroundColor Yellow
        Write-Host '  Kernel surfaces need an attestation-signed image; registry, hostname,' -ForegroundColor Yellow
        Write-Host '  network and the SMBIOS table work without one.' -ForegroundColor Cyan
    } else {
        Write-Host 'installing test cert into LocalMachine\Root (needs admin)' -ForegroundColor Cyan
        Invoke-Cmd "certutil -addstore -f Root `"$(Join-Path $root 'hwidtest.cer')`"" 'certutil'
        Write-Host 'enabling test signing' -ForegroundColor Cyan
        Invoke-Cmd 'bcdedit /set testsigning on' 'bcdedit'
        Write-Host 'Reboot, then run: .\exe\hwidspoof.exe --spoof' -ForegroundColor Yellow
    }
}

Write-Host ''
Write-Host 'done.' -ForegroundColor Green
Write-Host '  exe\hwidspoof-setup.exe        run this on a machine to install'
Write-Host '  exe\hwidspoof.exe --spoof      apply a new identity'
Write-Host '  exe\hwidspoof.exe --verify     check live values'
Write-Host '  exe\hwidspoof.exe --restore    put the machine back'
if ($signPfx) {
    Write-Host ('  signed with {0}' -f $signPfx) -ForegroundColor DarkGray
} else {
    Write-Host '  unsigned build - see README "False positives" before shipping it' -ForegroundColor DarkGray
}
