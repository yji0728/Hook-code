<#
 Quick Build Script for Hook-code Project
 - Finds and loads Visual Studio build tools automatically (VsDevCmd/vcvars)
 - Falls back to scanning common install paths if vswhere is missing
#>

Write-Host "Hook-code Build Script" -ForegroundColor Cyan
Write-Host ("=" * 50) -ForegroundColor Cyan
Write-Host ""

function Import-EnvFromBatch {
    param(
        [Parameter(Mandatory=$true)][string]$BatchPath,
        [string]$Args = ""
    )
    if (-not (Test-Path $BatchPath)) { return $false }
    Write-Host "[*] Loading environment: $BatchPath $Args" -ForegroundColor Yellow
    $cmd = "`"$BatchPath`" $Args && set"
    cmd /c $cmd | ForEach-Object {
        if ($_ -match "^(.*?)=(.*)$") {
            Set-Item -Force -Path "ENV:\$($matches[1])" -Value $matches[2]
        }
    }
    return $true
}

# Try vswhere first
$vsWherePath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
$envLoaded = $false

if (Test-Path $vsWherePath) {
    Write-Host "[*] Finding Visual Studio installation..." -ForegroundColor Yellow
    $vsPath = & $vsWherePath -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vsPath) {
        # Fallback: any latest installation
        $vsPath = & $vsWherePath -latest -property installationPath 2>$null
    }
    if ($vsPath) {
        Write-Host "[+] Found Visual Studio at: $vsPath" -ForegroundColor Green
        $vsDevCmd = Join-Path $vsPath "Common7/Tools/VsDevCmd.bat"
        $vcvars64 = Join-Path $vsPath "VC/Auxiliary/Build/vcvars64.bat"
        if (-not $envLoaded -and (Test-Path $vsDevCmd)) {
            $envLoaded = Import-EnvFromBatch -BatchPath $vsDevCmd -Args "-arch=x64"
        }
        if (-not $envLoaded -and (Test-Path $vcvars64)) {
            $envLoaded = Import-EnvFromBatch -BatchPath $vcvars64
        }
    }
}

# If still not loaded, scan common install locations for VsDevCmd/vcvars
if (-not $envLoaded) {
    $searchRoots = @(
        "C:\\Program Files\\Microsoft Visual Studio",
        "C:\\Program Files (x86)\\Microsoft Visual Studio"
    )
    foreach ($root in $searchRoots) {
        if (-not (Test-Path $root)) { continue }
        try {
            $devCmds = Get-ChildItem -Path $root -Filter "VsDevCmd.bat" -Recurse -ErrorAction SilentlyContinue
            if ($devCmds -and $devCmds.Count -gt 0) {
                # Prefer the most recent by path (heuristic)
                $picked = $devCmds | Sort-Object FullName -Descending | Select-Object -First 1
                $envLoaded = Import-EnvFromBatch -BatchPath $picked.FullName -Args "-arch=x64"
            }
            if (-not $envLoaded) {
                $vcvars = Get-ChildItem -Path $root -Filter "vcvars64.bat" -Recurse -ErrorAction SilentlyContinue
                if ($vcvars -and $vcvars.Count -gt 0) {
                    $picked = $vcvars | Sort-Object FullName -Descending | Select-Object -First 1
                    $envLoaded = Import-EnvFromBatch -BatchPath $picked.FullName
                }
            }
            if ($envLoaded) { break }
        } catch {}
    }
}

# Check if cl.exe is available after environment load
$clExe = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $clExe) {
    Write-Host "[!] Error: MSVC compiler not found!" -ForegroundColor Red
    Write-Host "[!] Please install Visual Studio or Visual Studio Build Tools" -ForegroundColor Red
    Write-Host ""; Write-Host "Download: https://visualstudio.microsoft.com/downloads/" -ForegroundColor Yellow
    Write-Host ""; Write-Host "Tip: Run this from 'Developer Command Prompt for VS' if already installed." -ForegroundColor Yellow
    exit 1
}

Write-Host "[+] Compiler found: $($clExe.Source)" -ForegroundColor Green
Write-Host ""

# Run build.bat
Write-Host "[*] Starting build process..." -ForegroundColor Yellow
Write-Host ""

& ".\build.bat"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host "[SUCCESS] Build completed successfully!" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host ""
    if (Test-Path ".\bin") {
        Write-Host "Executables in 'bin':" -ForegroundColor Cyan
        Get-ChildItem -Path ".\bin" -Filter "*.exe" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  - $($_.Name)" }
        Write-Host ""; Write-Host "Sample DLL(s):" -ForegroundColor Cyan
        Get-ChildItem -Path ".\bin" -Filter "*.dll" -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  - $($_.Name)" }
    }
    Write-Host ""; Write-Host "See TESTING_GUIDE.md for usage instructions" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Red
    Write-Host "[FAILED] Build failed with errors" -ForegroundColor Red
    Write-Host ("=" * 50) -ForegroundColor Red
    exit $LASTEXITCODE
}
