@echo off
REM Build script for Windows Process Injection Techniques
REM Requires Visual Studio or Windows SDK

echo Building Windows Process Injection Code Samples...
echo.

REM Check for cl.exe (MSVC compiler)
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: MSVC compiler not found. Please run this from Visual Studio Developer Command Prompt.
    exit /b 1
)

REM Create output directory
if not exist "bin" mkdir bin

echo [1/5] Building Classic DLL Injection...
cl.exe /W3 /O2 /Fe:bin\01_classic_dll_injection.exe src\01_classic_dll_injection\injector.c /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Classic DLL Injection
    exit /b 1
)

echo [2/5] Building Process Hollowing...
cl.exe /W3 /O2 /Fe:bin\02_process_hollowing.exe src\02_process_hollowing\hollowing.c /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Process Hollowing
    exit /b 1
)

echo [3/5] Building APC Injection...
cl.exe /W3 /O2 /Fe:bin\03_apc_injection.exe src\03_apc_injection\apc_injector.c /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build APC Injection
    exit /b 1
)

echo [4/5] Building Thread Hijacking...
cl.exe /W3 /O2 /Fe:bin\04_thread_hijacking.exe src\04_thread_hijacking\hijack_thread.c /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Thread Hijacking
    exit /b 1
)

echo [5/5] Building Reflective DLL Injection...
cl.exe /W3 /O2 /Fe:bin\05_reflective_dll_injection.exe src\05_reflective_dll_injection\reflective_loader.c /link /SUBSYSTEM:CONSOLE
if %ERRORLEVEL% NEQ 0 (
    echo Failed to build Reflective DLL Injection
    exit /b 1
)

echo.
echo Build completed successfully!
echo Binaries are located in the 'bin' directory.
echo.

REM Clean up intermediate files
del *.obj 2>nul
