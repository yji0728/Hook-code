/*
 * Sample Test DLL for Injection Testing
 * 
 * This is a harmless DLL that can be used for testing injection techniques.
 * It displays a message box and launches Calculator when loaded.
 * 
 * Build command:
 * cl.exe /LD /O2 /Fe:test_payload.dll sample_dll.c user32.lib
 * or
 * x86_64-w64-mingw32-gcc -shared -o test_payload.dll sample_dll.c -luser32
 */

#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <string.h>
// Link required libs
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

// Helper: open injection log in TEMP folder for detection machines
static FILE* open_log(void) {
    char path[MAX_PATH] = {0};
    if (GetEnvironmentVariableA("TEMP", path, MAX_PATH) > 0) {
        // ensure trailing backslash exists
        size_t len = strlen(path);
        if (len > 0 && path[len-1] != '\\') {
            strncat(path, "\\", MAX_PATH - len - 1);
        }
        strncat(path, "injection_test_log.txt", MAX_PATH - strlen(path) - 1);
    } else {
        strncpy(path, "injection_test_log.txt", MAX_PATH - 1);
    }
    return fopen(path, "a");
}

// DLL Entry Point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded into the process
            MessageBoxA(
                NULL,
                "Test DLL successfully injected!\nLaunching Calculator to demonstrate injection.",
                "Injection Test - Success",
                MB_OK | MB_ICONINFORMATION
            );
            
            // Launch Calculator to visually demonstrate the injection
            STARTUPINFO si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            if (CreateProcess(
                NULL,           // No module name (use command line)
                "calc.exe",     // Command line
                NULL,           // Process handle not inheritable
                NULL,           // Thread handle not inheritable
                FALSE,          // Set handle inheritance to FALSE
                0,              // No creation flags
                NULL,           // Use parent's environment block
                NULL,           // Use parent's starting directory 
                &si,            // Pointer to STARTUPINFO structure
                &pi             // Pointer to PROCESS_INFORMATION structure
            )) {
                // Close process and thread handles
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            } else {
                // If Calculator fails, show error message
                MessageBoxA(
                    NULL,
                    "Failed to launch Calculator.",
                    "Injection Test - Error",
                    MB_OK | MB_ICONERROR
                );
            }
            
            // Optional: Create a log file in TEMP for detection machines
            FILE* logFile = open_log();
            if (logFile) {
                SYSTEMTIME st;
                GetLocalTime(&st);
                if (GetLastError() == 0) {
                    fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] DLL injected into process (PID: %d) - Calculator CreateProcess succeeded\n",
                        st.wYear, st.wMonth, st.wDay,
                        st.wHour, st.wMinute, st.wSecond,
                        GetCurrentProcessId());
                } else {
                    DWORD err = GetLastError();
                    fprintf(logFile, "[%04d-%02d-%02d %02d:%02d:%02d] DLL injected into process (PID: %d) - Calculator CreateProcess last error=%lu\n",
                        st.wYear, st.wMonth, st.wDay,
                        st.wHour, st.wMinute, st.wSecond,
                        GetCurrentProcessId(), err);
                }
                fclose(logFile);
            }
            break;
            
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            break;
            
        case DLL_THREAD_ATTACH:
            // A new thread is being created
            break;
            
        case DLL_THREAD_DETACH:
            // A thread is exiting cleanly
            break;
    }
    
    return TRUE;
}

// Exported function that can be called after injection
__declspec(dllexport) void TestFunction(void) {
    MessageBoxA(NULL, "TestFunction called successfully!\nAttempting to launch Calculator.", "Injection Test - Function Call", MB_OK | MB_ICONINFORMATION);

    // Build absolute path to calc.exe using GetSystemDirectoryA for reliability
    char calcPath[MAX_PATH] = {0};
    if (GetSystemDirectoryA(calcPath, MAX_PATH) > 0) {
        size_t len = strlen(calcPath);
        if (len > 0 && calcPath[len-1] != '\\') {
            strcat(calcPath, "\\calc.exe");
        } else {
            strcat(calcPath, "calc.exe");
        }
    } else {
        // Fallback to just calc.exe
        strcpy(calcPath, "calc.exe");
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // If a marker file exists, force the CreateProcessAsUserA branch for focused testing.
    const char *forceMarker = "C:\\Users\\SEC\\Documents\\Hook-code_2\\bin\\force_createprocessasuser.txt";
    BOOL forceCreateAsUser = (GetFileAttributesA(forceMarker) != INVALID_FILE_ATTRIBUTES);
    if (forceCreateAsUser) {
        FILE* f_mark = open_log();
        if (f_mark) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(f_mark, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: Force CreateProcessAsUserA path (marker present) (PID=%d)\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond,
                GetCurrentProcessId());
            fclose(f_mark);
        }
    }

    // Try normal CreateProcessA unless forced to use CreateProcessAsUserA
    BOOL cpResult = FALSE;
    if (!forceCreateAsUser) {
        cpResult = CreateProcessA(NULL, calcPath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    }

    SYSTEMTIME st;
    FILE* f = open_log();
    if (f) {
        GetLocalTime(&st);
        if (cpResult) {
            fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessA succeeded. Command=\"%s\" (PID=%d)\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond,
                calcPath, GetCurrentProcessId());
            fclose(f);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return;
        }
        else {
            DWORD err = GetLastError();
            fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessA FAILED. Command=\"%s\" Return=%d Error=%lu (PID=%d)\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond,
                calcPath, (int)cpResult, err, GetCurrentProcessId());
            fclose(f);
        }
    }

    // Attempt ShellExecuteExA fallback unless forced to skip
    BOOL seResult = FALSE;
    if (!forceCreateAsUser) {
        SHELLEXECUTEINFOA sei = {0};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = "open";
        sei.lpFile = calcPath;
        sei.nShow = SW_SHOW;
        seResult = ShellExecuteExA(&sei);

        FILE* f2 = open_log();
        if (f2) {
            GetLocalTime(&st);
            if (seResult) {
                DWORD launchedPid = 0;
                if (sei.hProcess) launchedPid = GetProcessId(sei.hProcess);
                fprintf(f2, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: ShellExecuteExA succeeded. Command=\"%s\" (CallerPID=%d, LaunchedPID=%u)\n",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond,
                    calcPath, GetCurrentProcessId(), launchedPid);
                if (sei.hProcess) CloseHandle(sei.hProcess);
            } else {
                fprintf(f2, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: ShellExecuteExA FAILED. Error=%lu (PID=%d)\n",
                    st.wYear, st.wMonth, st.wDay,
                    st.wHour, st.wMinute, st.wSecond,
                    GetLastError(), GetCurrentProcessId());
            }
            fclose(f2);
        }
    }

    if (seResult) return;

    // At this point, try WTSQueryUserToken -> CreateProcessAsUserA
    DWORD sessionId = WTSGetActiveConsoleSessionId();
    HANDLE hUserToken = NULL;
    if (WTSQueryUserToken(sessionId, &hUserToken)) {
        HANDLE hDupToken = NULL;
        if (DuplicateTokenEx(hUserToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
            LPVOID env = NULL;
            if (CreateEnvironmentBlock(&env, hDupToken, FALSE)) {
                STARTUPINFOA si2 = {0};
                PROCESS_INFORMATION pi2 = {0};
                si2.cb = sizeof(si2);
                if (CreateProcessAsUserA(hDupToken, NULL, calcPath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, env, NULL, &si2, &pi2)) {
                    FILE* f3 = open_log();
                    if (f3) {
                        GetLocalTime(&st);
                        fprintf(f3, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessAsUserA succeeded. Command=\"%s\" (LaunchedPID=%u)\n",
                            st.wYear, st.wMonth, st.wDay,
                            st.wHour, st.wMinute, st.wSecond,
                            calcPath, GetProcessId(pi2.hProcess));
                        fclose(f3);
                    }
                    CloseHandle(pi2.hProcess);
                    CloseHandle(pi2.hThread);
                    DestroyEnvironmentBlock(env);
                    if (hDupToken) CloseHandle(hDupToken);
                    if (hUserToken) CloseHandle(hUserToken);
                    return;
                } else {
                    FILE* f3 = fopen("C:\\Users\\SEC\\Documents\\Hook-code_2\\bin\\injection_test_log.txt", "a");
                    if (f3) { GetLocalTime(&st); fprintf(f3, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessAsUserA FAILED. Error=%lu (PID=%d)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError(), GetCurrentProcessId()); fclose(f3); }
                }
                DestroyEnvironmentBlock(env);
            } else {
                FILE* f3 = fopen("C:\\Users\\SEC\\Documents\\Hook-code_2\\bin\\injection_test_log.txt", "a");
                if (f3) { GetLocalTime(&st); fprintf(f3, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateEnvironmentBlock failed. Error=%lu (PID=%d)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError(), GetCurrentProcessId()); fclose(f3); }
            }
            if (hDupToken) CloseHandle(hDupToken);
        } else {
            FILE* f3 = fopen("C:\\Users\\SEC\\Documents\\Hook-code_2\\bin\\injection_test_log.txt", "a");
            if (f3) { GetLocalTime(&st); fprintf(f3, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: DuplicateTokenEx failed. Error=%lu (PID=%d)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError(), GetCurrentProcessId()); fclose(f3); }
        }
        if (hUserToken) CloseHandle(hUserToken);
    } else {
        FILE* f3 = fopen("C:\\Users\\SEC\\Documents\\Hook-code_2\\bin\\injection_test_log.txt", "a");
        if (f3) { GetLocalTime(&st); fprintf(f3, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: WTSQueryUserToken failed for session %u. Error=%lu (PID=%d)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, sessionId, GetLastError(), GetCurrentProcessId()); fclose(f3); }

        // Fallback: locate explorer.exe processes and prefer one in same session as this process
        DWORD injectedSessionId = (DWORD)-1;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &injectedSessionId)) injectedSessionId = (DWORD)-1;
        FILE* f_sess = open_log();
        if (f_sess) { GetLocalTime(&st); fprintf(f_sess, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: injected process SessionId=%u\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, injectedSessionId); fclose(f_sess); }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {0};
            pe.dwSize = sizeof(pe);
            BOOL found = FALSE;
            DWORD preferredPid = 0;
            DWORD preferredSession = (DWORD)-1;

            if (Process32First(hSnap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                        DWORD explorerPid = pe.th32ProcessID;
                        DWORD explorerSession = (DWORD)-1;
                        if (!ProcessIdToSessionId(explorerPid, &explorerSession)) explorerSession = (DWORD)-1;

                        FILE* f_proc = open_log();
                        if (f_proc) { GetLocalTime(&st); fprintf(f_proc, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: Found explorer.exe PID=%u session=%u\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, explorerPid, explorerSession); fclose(f_proc); }

                        if (preferredPid == 0) {
                            preferredPid = explorerPid;
                            preferredSession = explorerSession;
                        }
                        // Prefer explorer in same session as injected process
                        if (explorerSession == injectedSessionId) {
                            preferredPid = explorerPid;
                            preferredSession = explorerSession;
                            found = TRUE;
                            break;
                        }
                    }
                } while (Process32Next(hSnap, &pe));
            }

            if (preferredPid != 0) {
                FILE* f_choose = open_log();
                if (f_choose) { GetLocalTime(&st); fprintf(f_choose, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: Selected explorer.exe PID=%u session=%u for token fallback\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid, preferredSession); fclose(f_choose); }

                HANDLE hExplorer = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, preferredPid);
                if (!hExplorer) {
                    FILE* f_op = open_log();
                    if (f_op) { GetLocalTime(&st); fprintf(f_op, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: OpenProcess(explorer) FAILED for PID=%u Error=%lu\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid, GetLastError()); fclose(f_op); }
                } else {
                    FILE* f_op2 = open_log();
                    if (f_op2) { GetLocalTime(&st); fprintf(f_op2, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: OpenProcess(explorer) succeeded for PID=%u\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid); fclose(f_op2); }

                    HANDLE hExplorerToken = NULL;
                    if (!OpenProcessToken(hExplorer, TOKEN_DUPLICATE | TOKEN_QUERY, &hExplorerToken)) {
                        FILE* f_tok = open_log();
                        if (f_tok) { GetLocalTime(&st); fprintf(f_tok, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: OpenProcessToken FAILED for PID=%u Error=%lu\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid, GetLastError()); fclose(f_tok); }
                        CloseHandle(hExplorer);
                    } else {
                        HANDLE hDup = NULL;
                        if (!DuplicateTokenEx(hExplorerToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup)) {
                            FILE* f_dup = open_log();
                            if (f_dup) { GetLocalTime(&st); fprintf(f_dup, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: DuplicateTokenEx FAILED for PID=%u Error=%lu\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid, GetLastError()); fclose(f_dup); }
                            CloseHandle(hExplorerToken);
                            CloseHandle(hExplorer);
                        } else {
                            LPVOID env2 = NULL;
                            if (!CreateEnvironmentBlock(&env2, hDup, FALSE)) {
                                FILE* f_env = open_log();
                                if (f_env) { GetLocalTime(&st); fprintf(f_env, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateEnvironmentBlock FAILED for PID=%u Error=%lu\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, preferredPid, GetLastError()); fclose(f_env); }
                                CloseHandle(hDup);
                                CloseHandle(hExplorerToken);
                                CloseHandle(hExplorer);
                            } else {
                                STARTUPINFOA si3 = {0};
                                PROCESS_INFORMATION pi3 = {0};
                                si3.cb = sizeof(si3);
                                if (CreateProcessAsUserA(hDup, NULL, calcPath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, env2, NULL, &si3, &pi3)) {
                                    FILE* f_ok = open_log();
                                    if (f_ok) { GetLocalTime(&st); fprintf(f_ok, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessAsUserA (explorer token) succeeded. Command=\"%s\" (LaunchedPID=%u)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, calcPath, GetProcessId(pi3.hProcess)); fclose(f_ok); }
                                    CloseHandle(pi3.hProcess);
                                    CloseHandle(pi3.hThread);
                                    DestroyEnvironmentBlock(env2);
                                    CloseHandle(hDup);
                                    CloseHandle(hExplorerToken);
                                    CloseHandle(hExplorer);
                                    CloseHandle(hSnap);
                                    return;
                                } else {
                                    FILE* f_err = open_log();
                                    if (f_err) { GetLocalTime(&st); fprintf(f_err, "[%04d-%02d-%02d %02d:%02d:%02d] TestFunction: CreateProcessAsUserA (explorer token) FAILED. Error=%lu (PID=%d)\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, GetLastError(), GetCurrentProcessId()); fclose(f_err); }
                                    DestroyEnvironmentBlock(env2);
                                    CloseHandle(hDup);
                                    CloseHandle(hExplorerToken);
                                    CloseHandle(hExplorer);
                                }
                            }
                        }
                    }
                }
            }
            CloseHandle(hSnap);
        }
    }
}
