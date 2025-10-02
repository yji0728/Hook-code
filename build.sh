#!/bin/bash
# Build script for Windows Process Injection Techniques using MinGW
# For cross-compilation on Linux

echo "Building Windows Process Injection Code Samples with MinGW..."
echo

# Check for MinGW compiler
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: MinGW compiler not found. Please install mingw-w64."
    exit 1
fi

# Create output directory
mkdir -p bin

echo "[1/5] Building Classic DLL Injection..."
x86_64-w64-mingw32-gcc -O2 -Wall -o bin/01_classic_dll_injection.exe src/01_classic_dll_injection/injector.c
if [ $? -ne 0 ]; then
    echo "Failed to build Classic DLL Injection"
    exit 1
fi

echo "[2/5] Building Process Hollowing..."
x86_64-w64-mingw32-gcc -O2 -Wall -o bin/02_process_hollowing.exe src/02_process_hollowing/hollowing.c
if [ $? -ne 0 ]; then
    echo "Failed to build Process Hollowing"
    exit 1
fi

echo "[3/5] Building APC Injection..."
x86_64-w64-mingw32-gcc -O2 -Wall -o bin/03_apc_injection.exe src/03_apc_injection/apc_injector.c
if [ $? -ne 0 ]; then
    echo "Failed to build APC Injection"
    exit 1
fi

echo "[4/5] Building Thread Hijacking..."
x86_64-w64-mingw32-gcc -O2 -Wall -o bin/04_thread_hijacking.exe src/04_thread_hijacking/hijack_thread.c
if [ $? -ne 0 ]; then
    echo "Failed to build Thread Hijacking"
    exit 1
fi

echo "[5/5] Building Reflective DLL Injection..."
x86_64-w64-mingw32-gcc -O2 -Wall -o bin/05_reflective_dll_injection.exe src/05_reflective_dll_injection/reflective_loader.c
if [ $? -ne 0 ]; then
    echo "Failed to build Reflective DLL Injection"
    exit 1
fi

echo
echo "Build completed successfully!"
echo "Binaries are located in the 'bin' directory."
echo
