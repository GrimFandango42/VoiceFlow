<#
.SYNOPSIS
    Compute the SHA256 hash of the VoiceFlow installer and update the winget manifest.

.DESCRIPTION
    Run this after building the installer with build_windows_installer.ps1.
    Outputs the hash and optionally writes it into the winget manifest.

.PARAMETER InstallerPath
    Path to the installer EXE. Defaults to dist\packages\VoiceFlow-*-Setup.exe

.PARAMETER UpdateManifest
    If set, writes the hash into packaging\windows\winget\GrimFandango42.VoiceFlow.yaml

.EXAMPLE
    .\scripts\setup\compute_installer_hash.ps1 -UpdateManifest
#>

param(
    [string]$InstallerPath = "",
    [switch]$UpdateManifest
)

$RepoRoot = Split-Path $PSScriptRoot -Parent | Split-Path -Parent

if (-not $InstallerPath) {
    $candidates = Get-ChildItem "$RepoRoot\dist\packages\VoiceFlow-*-Setup.exe" -ErrorAction SilentlyContinue
    if (-not $candidates) {
        Write-Error "No installer found in dist\packages\. Run build_windows_installer.ps1 first."
        exit 1
    }
    $InstallerPath = ($candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}

if (-not (Test-Path $InstallerPath)) {
    Write-Error "Installer not found: $InstallerPath"
    exit 1
}

$Hash = (Get-FileHash $InstallerPath -Algorithm SHA256).Hash
$Size = (Get-Item $InstallerPath).Length

Write-Host ""
Write-Host "Installer: $InstallerPath"
Write-Host "Size:      $([math]::Round($Size / 1MB, 1)) MB"
Write-Host "SHA256:    $Hash"
Write-Host ""

if ($UpdateManifest) {
    $ManifestPath = "$RepoRoot\packaging\windows\winget\GrimFandango42.VoiceFlow.yaml"
    if (-not (Test-Path $ManifestPath)) {
        Write-Error "Manifest not found: $ManifestPath"
        exit 1
    }
    $content = Get-Content $ManifestPath -Raw
    $content = $content -replace "REPLACE_WITH_SHA256_OF_INSTALLER", $Hash
    Set-Content $ManifestPath $content -NoNewline
    Write-Host "Updated manifest: $ManifestPath"
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "  1. Upload the installer to the GitHub release"
    Write-Host "  2. winget validate --manifest packaging\windows\winget\"
    Write-Host "  3. Submit PR to https://github.com/microsoft/winget-pkgs"
}
