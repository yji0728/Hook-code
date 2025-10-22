# Hook-code 인젝션 테스트 가이드

## 빌드 방법

### Windows (MSVC)
```powershell
# Visual Studio Developer Command Prompt에서 실행
cd C:\Users\SEC\Documents\Hook-code
.\build.bat
```

또는

```powershell
# PowerShell에서 Visual Studio 환경 로드 후 실행
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
cd C:\Users\SEC\Documents\Hook-code
.\build.bat
```

### Linux (MinGW Cross-compile)
```bash
chmod +x build.sh
./build.sh
```

## 테스트 시나리오

### 1. Classic DLL Injection 테스트

#### 준비:
```powershell
# 1. notepad.exe 실행
notepad.exe

# 2. Sample DLL 위치 확인
# bin\sample_dll.dll
```

#### 실행:
```powershell
.\bin\01_classic_dll_injection.exe notepad.exe bin\sample_dll.dll
```

#### 예상 결과:
- MessageBox 팝업: "Test DLL successfully injected!"
- 로그 파일 생성: `C:\injection_test_log.txt`

---

### 2. Process Hollowing 테스트

#### 준비:
```powershell
# 테스트용 간단한 실행 파일 필요
# notepad.exe를 대상으로, calc.exe를 페이로드로 사용
```

#### 실행:
```powershell
.\bin\02_process_hollowing.exe C:\Windows\System32\notepad.exe C:\Windows\System32\calc.exe
```

#### 예상 결과:
- notepad.exe 프로세스가 생성됨
- 실제로는 calc.exe(계산기)가 실행됨
- 프로세스 이름은 notepad.exe로 표시됨

---

### 3. APC Injection 테스트

#### 준비:
```powershell
# notepad.exe 실행
notepad.exe
```

#### 실행:
```powershell
# 프로세스 이름으로
.\bin\03_apc_injection.exe notepad.exe

# 또는 PID로
.\bin\03_apc_injection.exe 1234
```

#### 예상 결과:
- APC가 스레드 큐에 추가됨
- 스레드가 alertable 상태가 될 때 실행됨
- 주의: 샘플 shellcode는 테스트용이므로 프로세스가 크래시될 수 있음

---

### 4. Thread Hijacking 테스트

#### 준비:
```powershell
# notepad.exe 실행
notepad.exe
```

#### 실행:
```powershell
.\bin\04_thread_hijacking.exe notepad.exe
```

#### 예상 결과:
- 스레드가 suspend됨
- Instruction pointer가 shellcode로 변경됨
- 스레드 resume
- 주의: 샘플 shellcode(int3)로 인해 디버거가 attach되거나 프로세스 크래시 가능

---

### 5. Reflective DLL Injection 테스트

#### 준비:
```powershell
# notepad.exe 실행
notepad.exe
```

#### 실행:
```powershell
.\bin\05_reflective_dll_injection.exe notepad.exe bin\sample_dll.dll
```

#### 예상 결과:
- DLL이 메모리에 로드됨
- 섹션별로 로딩 진행 상황 출력
- 주의: 이 구현은 개념 증명용으로 완전한 reflective injection은 아님

---

## 안전한 테스트 방법

### 1. 테스트 환경 준비
```powershell
# 가상 머신 사용 권장
# Windows Sandbox 또는 격리된 테스트 환경

# Windows Sandbox 실행 (Windows 10/11 Pro 이상)
# 설정 -> 앱 -> 선택적 기능 -> Windows Sandbox 활성화
```

### 2. 프로세스 모니터링
```powershell
# Process Explorer 다운로드 및 실행
# https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer

# Process Monitor로 활동 추적
# https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
```

### 3. 테스트 후 정리
```powershell
# 테스트 로그 파일 확인
Get-Content C:\injection_test_log.txt

# 테스트 프로세스 종료
taskkill /F /IM notepad.exe
```

## 트러블슈팅

### 빌드 오류
```powershell
# MSVC 컴파일러가 없는 경우
# Visual Studio Build Tools 설치
# https://visualstudio.microsoft.com/downloads/

# MinGW 사용 (Linux/WSL)
sudo apt-get install mingw-w64
```

### 실행 오류

#### "Access Denied" 에러:
```powershell
# 관리자 권한으로 실행
# PowerShell을 관리자 권한으로 열기
```

#### "Process not found" 에러:
```powershell
# 프로세스가 실행 중인지 확인
Get-Process notepad

# 정확한 프로세스 이름 사용 (notepad.exe)
```

#### DLL 로드 실패:
```powershell
# DLL 경로 확인 (절대 경로 사용 권장)
.\bin\01_classic_dll_injection.exe notepad.exe C:\Users\SEC\Documents\Hook-code\bin\sample_dll.dll
```

## EDR 테스트

### 테스트할 EDR 기능:
1. **프로세스 인젝션 탐지**
   - CreateRemoteThread 모니터링
   - 의심스러운 메모리 할당 탐지

2. **비정상적인 프로세스 동작**
   - Process Hollowing 탐지
   - Parent-Child 프로세스 관계 이상

3. **스레드 조작 탐지**
   - SuspendThread/ResumeThread 모니터링
   - SetThreadContext 호출 탐지

4. **메모리 스캔**
   - 실행 가능 메모리 영역 스캔
   - PE 헤더 감지

### 권장 EDR 테스트 도구:
- Windows Defender ATP
- Sysmon (이벤트 로깅)
- OSSEC
- Wazuh

## 참고 사항

⚠️ **경고**: 이 도구들은 **교육 및 합법적인 보안 테스트 목적으로만** 사용해야 합니다.

- ✅ 자신이 소유하거나 명시적 권한을 받은 시스템에서만 테스트
- ✅ EDR 솔루션 테스트 및 평가 목적
- ✅ 보안 연구 및 교육 목적
- ❌ 악의적인 목적으로 사용 금지
- ❌ 권한이 없는 시스템에서 실행 금지

## 추가 학습 자료

- [MITRE ATT&CK - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Windows Internals Book](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [Reflective DLL Injection](https://github.com/stephenfewer/ReflectiveDLLInjection)
