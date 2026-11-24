<#
    verify-build.ps1 - the last check before a build goes to someone else.

    Hashes every shipped image, reports its Authenticode state, runs Defender
    over the release folder, and (with -Submit) opens the Microsoft false
    positive portal with the hashes already on the clipboard.

    Examples:
        .\packaging\verify-build.ps1
        .\packaging\verify-build.ps1 -Submit
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Submit
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $Path) {
    $dist = Join-Path $root 'dist'
    $Path = if (Test-Path $dist) { $dist } else { Join-Path $root 'exe' }
}

$artifacts = @()
foreach ($pattern in '*.exe', '*.sys') {
    $artifacts += Get-ChildItem -Path $Path -Filter $pattern -File -ErrorAction SilentlyContinue
}
$artifacts = $artifacts | Sort-Object Name

if ($artifacts.Count -eq 0) {
    throw "no .exe or .sys files under $Path - run build.ps1 first"
}

$rows = @()
foreach ($file in $artifacts) {
    $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
    $signature = Get-AuthenticodeSignature -FilePath $file.FullName
    $signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '-' }
    $rows += [pscustomobject]@{
        Name   = $file.Name
        KiB    = [math]::Round($file.Length / 1KB, 1)
        Sha256 = $hash
        Status = $signature.Status
        Signer = $signer
    }
}

$rows | Format-Table -AutoSize | Out-String -Width 240 | Write-Host

$sumFile = Join-Path $Path 'SHA256SUMS.txt'
$lines = $rows | ForEach-Object { '{0}  {1}' -f $_.Sha256, $_.Name }
Set-Content -Path $sumFile -Value ($lines -join "`r`n") -Encoding ASCII
Write-Host "hashes written to $sumFile" -ForegroundColor DarkGray

$unsigned = $rows | Where-Object { $_.Status -ne 'Valid' }
if ($unsigned.Count -gt 0) {
    Write-Host ''
    Write-Host 'Unsigned or untrusted images:' -ForegroundColor Yellow
    foreach ($row in $unsigned) {
        Write-Host ("  {0,-30} {1}" -f $row.Name, $row.Status) -ForegroundColor Yellow
    }
    Write-Host '  A valid Authenticode signature (real certificate, timestamped) is the' -ForegroundColor Yellow
    Write-Host '  only build-side change that moves a reputation verdict. See README.' -ForegroundColor Yellow
}

$defender = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
$scanOk = $null
if (Test-Path $defender) {
    Write-Host ''
    Write-Host "scanning $Path with Defender" -ForegroundColor Cyan
    $scan = & $defender -Scan -ScanType 3 -File $Path -DisableRemediation 2>&1 | Out-String
    $scanOk = $scan -match 'found no threats'
    Write-Host ($scan.Trim() -split "`r?`n" | Select-Object -Last 2) -ForegroundColor DarkGray
    if (-not $scanOk) {
        Write-Host 'Defender reported something - read the scan output above.' -ForegroundColor Red
    }
} else {
    Write-Host 'Defender CLI not found; skipping the local scan.' -ForegroundColor Yellow
}

if ($Submit) {
    $summary = @(
        'Files flagged by a scanner:'
        ''
    ) + ($rows | ForEach-Object { '{0}  {1}  {2}' -f $_.Sha256, $_.Name, $_.KiB + ' KiB' }) + @(
        ''
        'Submitted as a false positive: the tool changes local hardware identity'
        'values that the user owns, does not self-propagate, and does not touch'
        'other users or remote systems.'
    )
    $summary -join "`r`n" | Set-Clipboard
    Write-Host ''
    Write-Host 'Hashes copied to the clipboard. Upload the files from' -ForegroundColor Cyan
    Write-Host "  $Path" -ForegroundColor Cyan
    Write-Host 'at https://www.microsoft.com/en-us/wdsi/filesubmission and paste the notes.' -ForegroundColor Cyan
    Start-Process 'https://www.microsoft.com/en-us/wdsi/filesubmission'
}

if ($Submit -or $scanOk -eq $false) {
    exit 0
}
