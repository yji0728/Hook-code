# Automated Test Script for Hook-code Project
# WARNING: Only use on test systems with explicit permission!

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Classic", "Hollowing", "APC", "Thread", "Reflective", "All")]
    [string]$TestType = "Classic",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipBuild
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Hook-code Automated Test Suite" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Warning
Write-Host "WARNING: This script performs process injection techniques!" -ForegroundColor Yellow
Write-Host "Only use on systems you own or have explicit permission to test." -ForegroundColor Yellow
Write-Host ""
$confirmation = Read-Host "Do you want to continue? (yes/no)"
if ($confirmation -ne "yes") {
    Write-Host "Aborted by user." -ForegroundColor Red
    exit 0
}
Write-Host ""

# Build if needed
if (-not $SkipBuild) {
    Write-Host "[*] Building project..." -ForegroundColor Yellow
    & ".\quick-build.ps1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Build failed. Exiting." -ForegroundColor Red
        exit 1
    }
    Write-Host ""
}

# Helper function to check if process exists
function Test-ProcessRunning {
    param([string]$ProcessName)
    return (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue) -ne $null
}

# Helper function to start test target
function Start-TestTarget {
    Write-Host "[*] Starting test target (notepad.exe)..." -ForegroundColor Yellow
    Start-Process notepad.exe
    Start-Sleep -Seconds 2
    
    if (Test-ProcessRunning "notepad") {
        Write-Host "[+] Test target started successfully" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[!] Failed to start test target" -ForegroundColor Red
        return $false
    }
}

# Helper function to cleanup
function Stop-TestTarget {
    Write-Host "[*] Cleaning up test target..." -ForegroundColor Yellow
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# Test Classic DLL Injection
function Test-ClassicDllInjection {
    Write-Host ""
    Write-Host "===== Test 1: Classic DLL Injection =====" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Start-TestTarget)) { return $false }
    
    Write-Host "[*] Injecting DLL..." -ForegroundColor Yellow
    $dllPath = (Resolve-Path ".\bin\sample_dll.dll").Path
    & ".\bin\01_classic_dll_injection.exe" "notepad.exe" $dllPath
    
    Write-Host ""
    Write-Host "[?] Did you see a MessageBox from the injected DLL? (yes/no)" -ForegroundColor Yellow
    $result = Read-Host
    
    Stop-TestTarget
    
    if ($result -eq "yes") {
        Write-Host "[+] TEST PASSED: Classic DLL Injection" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] TEST FAILED: Classic DLL Injection" -ForegroundColor Red
        return $false
    }
}

# Test Process Hollowing
function Test-ProcessHollowing {
    Write-Host ""
    Write-Host "===== Test 2: Process Hollowing =====" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "[*] Performing process hollowing (notepad -> calc)..." -ForegroundColor Yellow
    & ".\bin\02_process_hollowing.exe" "C:\Windows\System32\notepad.exe" "C:\Windows\System32\calc.exe"
    
    Start-Sleep -Seconds 2
    
    Write-Host ""
    Write-Host "[?] Did you see calculator running (check Task Manager for notepad.exe)? (yes/no)" -ForegroundColor Yellow
    $result = Read-Host
    
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
    Stop-Process -Name calc* -Force -ErrorAction SilentlyContinue
    
    if ($result -eq "yes") {
        Write-Host "[+] TEST PASSED: Process Hollowing" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] TEST FAILED: Process Hollowing" -ForegroundColor Red
        return $false
    }
}

# Test APC Injection
function Test-APCInjection {
    Write-Host ""
    Write-Host "===== Test 3: APC Injection =====" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Start-TestTarget)) { return $false }
    
    Write-Host "[*] Queueing APC to threads..." -ForegroundColor Yellow
    & ".\bin\03_apc_injection.exe" "notepad.exe"
    
    Write-Host ""
    Write-Host "[*] APC queued. This test may not show visible results." -ForegroundColor Yellow
    Write-Host "[*] Check if the tool reported successful APC queueing." -ForegroundColor Yellow
    Write-Host "[?] Did the tool report success? (yes/no)" -ForegroundColor Yellow
    $result = Read-Host
    
    Stop-TestTarget
    
    if ($result -eq "yes") {
        Write-Host "[+] TEST PASSED: APC Injection" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] TEST FAILED: APC Injection" -ForegroundColor Red
        return $false
    }
}

# Test Thread Hijacking
function Test-ThreadHijacking {
    Write-Host ""
    Write-Host "===== Test 4: Thread Hijacking =====" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Start-TestTarget)) { return $false }
    
    Write-Host "[*] Hijacking thread..." -ForegroundColor Yellow
    Write-Host "[!] Note: This may crash the target process!" -ForegroundColor Yellow
    & ".\bin\04_thread_hijacking.exe" "notepad.exe"
    
    Start-Sleep -Seconds 2
    
    Write-Host ""
    Write-Host "[?] Did the tool report successful thread hijacking? (yes/no)" -ForegroundColor Yellow
    $result = Read-Host
    
    Stop-TestTarget
    
    if ($result -eq "yes") {
        Write-Host "[+] TEST PASSED: Thread Hijacking" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] TEST FAILED: Thread Hijacking" -ForegroundColor Red
        return $false
    }
}

# Test Reflective DLL Injection
function Test-ReflectiveDllInjection {
    Write-Host ""
    Write-Host "===== Test 5: Reflective DLL Injection =====" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Start-TestTarget)) { return $false }
    
    Write-Host "[*] Performing reflective DLL injection..." -ForegroundColor Yellow
    $dllPath = (Resolve-Path ".\bin\sample_dll.dll").Path
    & ".\bin\05_reflective_dll_injection.exe" "notepad.exe" $dllPath
    
    Write-Host ""
    Write-Host "[*] This is a proof-of-concept implementation." -ForegroundColor Yellow
    Write-Host "[?] Did the tool complete without errors? (yes/no)" -ForegroundColor Yellow
    $result = Read-Host
    
    Stop-TestTarget
    
    if ($result -eq "yes") {
        Write-Host "[+] TEST PASSED: Reflective DLL Injection" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[-] TEST FAILED: Reflective DLL Injection" -ForegroundColor Red
        return $false
    }
}

# Run tests
$results = @{}

switch ($TestType) {
    "Classic" {
        $results["Classic DLL Injection"] = Test-ClassicDllInjection
    }
    "Hollowing" {
        $results["Process Hollowing"] = Test-ProcessHollowing
    }
    "APC" {
        $results["APC Injection"] = Test-APCInjection
    }
    "Thread" {
        $results["Thread Hijacking"] = Test-ThreadHijacking
    }
    "Reflective" {
        $results["Reflective DLL Injection"] = Test-ReflectiveDllInjection
    }
    "All" {
        $results["Classic DLL Injection"] = Test-ClassicDllInjection
        $results["Process Hollowing"] = Test-ProcessHollowing
        $results["APC Injection"] = Test-APCInjection
        $results["Thread Hijacking"] = Test-ThreadHijacking
        $results["Reflective DLL Injection"] = Test-ReflectiveDllInjection
    }
}

# Print summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$passed = 0
$failed = 0

foreach ($test in $results.Keys) {
    if ($results[$test]) {
        Write-Host "[+] $test : PASSED" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "[-] $test : FAILED" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "Total: $($results.Count) tests" -ForegroundColor White
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host ""

# Check injection log
if (Test-Path "C:\injection_test_log.txt") {
    Write-Host "[*] Injection log found:" -ForegroundColor Yellow
    Write-Host ""
    Get-Content "C:\injection_test_log.txt" | Select-Object -Last 5 | ForEach-Object {
        Write-Host "  $_" -ForegroundColor Gray
    }
    Write-Host ""
}

Write-Host "Test run complete!" -ForegroundColor Cyan
