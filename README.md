# Hook-code - Windows 프로세스 인젝션 기법 모음

EDR(Endpoint Detection and Response) 장비 도입을 위한 모의 테스트용 Windows 프로세스 인젝션 코드 샘플 모음입니다.

## ⚠️ 중요 공지 / Important Notice

**이 코드는 오직 교육 및 합법적인 보안 테스트 목적으로만 사용되어야 합니다.**

- ✅ 자신이 소유하거나 명시적 권한을 받은 시스템에서만 테스트하세요
- ✅ EDR 솔루션 테스트 및 평가 목적으로 사용하세요
- ✅ 보안 연구 및 교육 목적으로 활용하세요
- ❌ 악의적인 목적으로 사용하지 마세요
- ❌ 권한이 없는 시스템에서 실행하지 마세요

**This code is intended for educational and legitimate security testing purposes only.**

- ✅ Only test on systems you own or have explicit permission to test
- ✅ Use for EDR solution testing and evaluation
- ✅ Use for security research and education
- ❌ Do not use for malicious purposes
- ❌ Do not execute on unauthorized systems

## 📚 포함된 인젝션 기법들

### 1. Classic DLL Injection (CreateRemoteThread)
전통적인 DLL 인젝션 기법으로, `CreateRemoteThread`를 사용하여 대상 프로세스에 DLL을 로드합니다.

**특징:**
- 가장 널리 알려진 인젝션 기법
- LoadLibraryA를 원격 스레드로 실행
- 대부분의 EDR이 탐지 가능

**사용법:**
```
01_classic_dll_injection.exe <프로세스명> <DLL경로>
예: 01_classic_dll_injection.exe notepad.exe C:\test\payload.dll
```

### 2. Process Hollowing (Process Replacement)
정상 프로세스를 생성한 후 메모리를 교체하는 기법입니다.

**특징:**
- 정상 프로세스로 위장 가능
- Suspended 상태로 프로세스 생성
- 메모리 언맵 후 페이로드 주입

**사용법:**
```
02_process_hollowing.exe <대상실행파일> <페이로드실행파일>
예: 02_process_hollowing.exe C:\Windows\System32\notepad.exe C:\payload.exe
```

### 3. APC (Asynchronous Procedure Call) Injection
비동기 프로시저 호출 큐를 이용한 인젝션 기법입니다.

**특징:**
- 스레드가 alertable 상태일 때 실행
- 여러 스레드에 APC 큐잉 가능
- CreateRemoteThread보다 은밀한 실행

**사용법:**
```
03_apc_injection.exe <프로세스명 또는 PID>
예: 03_apc_injection.exe notepad.exe
예: 03_apc_injection.exe 1234
```

### 4. Thread Execution Hijacking
기존 스레드의 실행 컨텍스트를 변조하는 기법입니다.

**특징:**
- 새 스레드 생성 없이 인젝션
- 스레드 컨텍스트 직접 조작
- Instruction Pointer(RIP/EIP) 변조

**사용법:**
```
04_thread_hijacking.exe <프로세스명>
예: 04_thread_hijacking.exe notepad.exe
```

### 5. Reflective DLL Injection
메모리에서 직접 DLL을 로드하는 기법입니다.

**특징:**
- LoadLibrary를 사용하지 않음
- 디스크 I/O 흔적 최소화
- PE 파일 구조를 메모리에서 처리

**사용법:**
```
05_reflective_dll_injection.exe <프로세스명> <DLL경로>
예: 05_reflective_dll_injection.exe notepad.exe C:\test\payload.dll
```

## 🔧 빌드 방법

### Windows에서 빌드 (Visual Studio)

1. Visual Studio Developer Command Prompt 실행
2. 저장소 디렉토리로 이동
3. 빌드 스크립트 실행:

```batch
build.bat
```

### Linux에서 크로스 컴파일 (MinGW)

1. MinGW 설치:
```bash
# Ubuntu/Debian
sudo apt-get install mingw-w64

# Fedora
sudo dnf install mingw64-gcc
```

2. 빌드 스크립트 실행:
```bash
chmod +x build.sh
./build.sh
```

### 수동 빌드

개별 파일을 컴파일하려면:

```batch
# Windows (MSVC)
cl.exe /O2 /Fe:injector.exe src\01_classic_dll_injection\injector.c

# Windows (MinGW) / Linux (cross-compile)
x86_64-w64-mingw32-gcc -O2 -o injector.exe src/01_classic_dll_injection/injector.c
```

## 📁 프로젝트 구조

```
Hook-code/
├── README.md                           # 이 파일
├── .gitignore                          # Git 제외 파일 목록
├── build.bat                           # Windows 빌드 스크립트
├── build.sh                            # Linux 크로스 컴파일 스크립트
├── bin/                                # 컴파일된 실행 파일 (빌드 후 생성)
└── src/
    ├── 01_classic_dll_injection/       # Classic DLL Injection
    │   └── injector.c
    ├── 02_process_hollowing/           # Process Hollowing
    │   └── hollowing.c
    ├── 03_apc_injection/               # APC Injection
    │   └── apc_injector.c
    ├── 04_thread_hijacking/            # Thread Execution Hijacking
    │   └── hijack_thread.c
    └── 05_reflective_dll_injection/    # Reflective DLL Injection
        └── reflective_loader.c
```

## 🧪 테스트 환경 설정

### 안전한 테스트 환경

1. **가상 머신 사용 권장**
   - VMware Workstation/Player
   - VirtualBox
   - Hyper-V

2. **스냅샷 생성**
   - 테스트 전 시스템 스냅샷 생성
   - 문제 발생 시 복구 가능

3. **네트워크 격리**
   - 테스트 환경을 네트워크에서 격리
   - 호스트 전용 네트워크 사용

### 테스트 대상 프로세스

안전한 테스트를 위해 다음 프로세스 사용 권장:
- `notepad.exe` - 메모장
- 직접 작성한 테스트 프로그램
- 가상 머신의 격리된 프로세스

## 🛡️ EDR 탐지 테스트

### 테스트 시나리오

각 인젝션 기법을 실행하면서 EDR이 다음 항목을 탐지하는지 확인:

1. **프로세스 생성 모니터링**
   - CREATE_SUSPENDED 플래그 탐지
   - 비정상적인 프로세스 생성 패턴

2. **메모리 조작 탐지**
   - VirtualAllocEx 호출
   - WriteProcessMemory 호출
   - 실행 가능한 메모리 할당

3. **스레드 생성 탐지**
   - CreateRemoteThread
   - QueueUserAPC
   - 스레드 컨텍스트 변조

4. **API 후킹 탐지**
   - 의심스러운 API 호출 패턴
   - 비정상적인 호출 순서

### 탐지 우회 기법 평가

EDR 솔루션이 다음 우회 기법을 탐지하는지 확인:
- 직접 시스템 호출 (Direct Syscalls)
- API 언후킹
- 프로세스 체인 복잡화
- 타이밍 기반 회피

## 📊 로깅 및 분석

각 인젝션 도구는 상세한 로그를 출력합니다:
- `[*]` - 정보 메시지
- `[+]` - 성공 메시지
- `[!]` - 오류/경고 메시지

로그 출력 예시:
```
[*] Classic DLL Injection Technique
[*] Target Process: notepad.exe
[*] DLL Path: C:\test\payload.dll
[+] Found process with PID: 1234
[+] Process handle obtained
[+] Memory allocated at: 0x00007FF812340000
[+] DLL path written (25 bytes)
[+] LoadLibraryA address: 0x00007FFA12345678
[+] Remote thread created
[+] DLL injection completed successfully
```

## 🔍 디버깅

Windows 디버거를 사용한 분석:

### WinDbg 사용
```
# 프로세스에 attach
windbg -p <PID>

# 인젝션 후 메모리 검사
!address
!vadump
lm  # 로드된 모듈 확인
```

### Process Monitor 사용
1. Procmon 실행
2. 필터 설정: Process Name is <target_process>
3. 다음 이벤트 모니터링:
   - Process and Thread Activity
   - Registry Activity
   - File System Activity

## 🔒 방어 기법

이 코드를 통해 테스트할 수 있는 방어 메커니즘:

1. **DEP (Data Execution Prevention)**
   - 실행 불가능한 메모리 영역에서의 코드 실행 방지

2. **ASLR (Address Space Layout Randomization)**
   - 메모리 주소 무작위화

3. **CFG (Control Flow Guard)**
   - 제어 흐름 무결성 검증

4. **코드 무결성 검사**
   - 서명된 코드만 실행 허용

5. **동작 기반 탐지**
   - 비정상적인 API 호출 패턴 탐지

## 📖 참고 자료

### 프로세스 인젝션 기법
- [MITRE ATT&CK - T1055: Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Windows Internals Book Series](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)

### Windows API 문서
- [Process Security and Access Rights](https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Memory Management Functions](https://docs.microsoft.com/en-us/windows/win32/memory/memory-management-functions)

### 보안 연구
- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
- [Process Hollowing and Portable Executable Relocations](https://www.malwarebytes.com/blog/news/2020/12/process-hollowing)

## 🤝 기여

이 프로젝트에 기여하고 싶으시다면:

1. 새로운 인젝션 기법 추가
2. 코드 개선 및 최적화
3. 문서화 개선
4. 버그 수정

## ⚖️ 라이선스 및 책임

이 코드는 교육 목적으로 제공됩니다. 사용자는 다음 사항에 동의합니다:

- 이 코드의 사용으로 인한 모든 책임은 사용자에게 있습니다
- 합법적인 목적으로만 사용해야 합니다
- 관련 법규를 준수해야 합니다
- 작성자는 오용에 대해 책임지지 않습니다

## 📞 문의

프로젝트 관련 문의나 보안 취약점 보고는 GitHub Issues를 통해 제출해 주세요.

---

**면책 조항:** 이 소프트웨어는 "있는 그대로" 제공되며, 명시적이든 묵시적이든 어떠한 보증도 없습니다. 이 소프트웨어를 사용함으로써 발생하는 모든 위험은 사용자가 부담합니다. 작성자는 이 소프트웨어의 오용이나 불법적인 사용에 대해 책임지지 않습니다.

**Disclaimer:** This software is provided "as is" without warranty of any kind, either express or implied. All risks arising from the use of this software are borne by the user. The authors are not responsible for any misuse or illegal use of this software.