@echo off
REM Build script for Windows Process Injection Techniques
REM Requires Visual Studio or Windows SDK
REM
REM Optional parameters:
REM   build.bat                         - Build all with default settings
REM   build.bat autosave                - Build sample DLL with auto-save (Ctrl+S) enabled
REM   build.bat eventlog                - Build sample DLL with event logging enabled
REM   build.bat autosave eventlog       - Build with both features enabled

setlocal enabledelayedexpansion
set SAMPLE_DLL_AUTO_SAVE=0
set SAMPLE_DLL_EVENTLOG=0

if not "%~1"=="" (
    echo "%~1" | findstr /i "autosave" >nul
    if !ERRORLEVEL! EQU 0 set SAMPLE_DLL_AUTO_SAVE=1
    
    echo "%~1" | findstr /i "eventlog" >nul
    if !ERRORLEVEL! EQU 0 set SAMPLE_DLL_EVENTLOG=1
)

if not "%~2"=="" (
    echo "%~2" | findstr /i "autosave" >nul
    if !ERRORLEVEL! EQU 0 set SAMPLE_DLL_AUTO_SAVE=1
    
    echo "%~2" | findstr /i "eventlog" >nul
    if !ERRORLEVEL! EQU 0 set SAMPLE_DLL_EVENTLOG=1
)

echo Building Windows Process Injection Code Samples...
if %SAMPLE_DLL_AUTO_SAVE% EQU 1 echo   [Sample DLL auto-save ENABLED]
if %SAMPLE_DLL_EVENTLOG% EQU 1 echo   [Sample DLL event logging ENABLED]
echo.

REM Check for cl.exe (MSVC compiler)
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: MSVC compiler not found. Please run this from Visual Studio Developer Command Prompt.
    exit /b 1
)

REM Create output directory
if not exist "bin" mkdir bin

REM Common source files and compiler flags
set COMMON_SRC=src\common\common.c
set COMMON_FLAGS=/W3 /O2 /I"src"

echo [1/5] Building Classic DLL Injection...
cl.exe %COMMON_FLAGS% /Fe:bin\01_classic_dll_injection.exe src\01_classic_dll_injection\injector.c %COMMON_SRC% /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Classic DLL Injection
    exit /b 1
)

echo [2/5] Building Process Hollowing...
cl.exe %COMMON_FLAGS% /Fe:bin\02_process_hollowing.exe src\02_process_hollowing\hollowing.c %COMMON_SRC% /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Process Hollowing
    exit /b 1
)

echo [3/5] Building APC Injection...
cl.exe %COMMON_FLAGS% /Fe:bin\03_apc_injection.exe src\03_apc_injection\apc_injector.c %COMMON_SRC% /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build APC Injection
    exit /b 1
)

echo [4/5] Building Thread Hijacking...
cl.exe %COMMON_FLAGS% /Fe:bin\04_thread_hijacking.exe src\04_thread_hijacking\hijack_thread.c %COMMON_SRC% /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Thread Hijacking
    exit /b 1
)

echo [5d/5] Building Reflective DLL Injection...
cl.exe %COMMON_FLAGS% /Fe:bin\05_reflective_dll_injection.exe src\05_reflective_dll_injection\reflective_loader_fixed.c %COMMON_SRC% /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Reflective DLL Injection
    exit /b 1
)

echo [6/6] Building Sample DLL...
rem Build the DLL using MSVC. Requires Developer Command Prompt.
rem Link with user32.lib to resolve MessageBoxA used in the DLL
set SAMPLE_DLL_FLAGS=/D SAMPLE_DLL_EXTENDED_EDITORS=1 /D SAMPLE_DLL_ENHANCED_LOGGING=1
if %SAMPLE_DLL_AUTO_SAVE% EQU 1 set SAMPLE_DLL_FLAGS=!SAMPLE_DLL_FLAGS! /D SAMPLE_DLL_AUTO_SAVE=1
if %SAMPLE_DLL_EVENTLOG% EQU 1 set SAMPLE_DLL_FLAGS=!SAMPLE_DLL_FLAGS! /D SAMPLE_DLL_EVENTLOG=1

cl.exe /W3 /O2 /LD !SAMPLE_DLL_FLAGS! src\sample_dll\sample_dll.c /link user32.lib /OUT:bin\sample_dll.dll
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Sample DLL
    exit /b 1
)

echo.
echo Build completed successfully!
echo Binaries are located in the 'bin' directory.
echo.
echo Build Options for Sample DLL:
echo   build.bat                   - Build all with default DLL behavior
echo   build.bat autosave          - Enable Ctrl+S auto-save after injection
echo   build.bat eventlog          - Enable Windows Event Log writing (requires admin)
echo   build.bat autosave eventlog - Enable both features
echo.

REM Clean up intermediate files
del *.obj 2>nul
