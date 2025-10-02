# Windows Process Injection Techniques - Usage Guide

## 개요 (Overview)

이 문서는 Hook-code 프로젝트에 포함된 각 인젝션 기법의 상세한 사용 방법과 EDR 테스트 시나리오를 제공합니다.

This document provides detailed usage instructions and EDR testing scenarios for each injection technique included in the Hook-code project.

---

## 1. Classic DLL Injection (CreateRemoteThread)

### 동작 원리 (How it Works)

1. 대상 프로세스 핸들 획득
2. VirtualAllocEx로 원격 메모리 할당
3. WriteProcessMemory로 DLL 경로 작성
4. CreateRemoteThread로 LoadLibraryA 호출
5. DLL이 대상 프로세스에 로드됨

### 사용 예제 (Usage Examples)

```batch
# 메모장에 테스트 DLL 주입
01_classic_dll_injection.exe notepad.exe C:\test\test_payload.dll

# 특정 프로세스에 주입
01_classic_dll_injection.exe target.exe C:\path\to\your.dll
```

### EDR 탐지 포인트 (EDR Detection Points)

- ✓ CreateRemoteThread API 호출
- ✓ OpenProcess with specific permissions
- ✓ VirtualAllocEx + WriteProcessMemory 조합
- ✓ Cross-process memory operations

### 회피 기법 (Evasion Techniques)

- Manual mapping 대신 사용
- QueueUserAPC로 대체
- NtCreateThreadEx 직접 호출

---

## 2. Process Hollowing (RunPE)

### 동작 원리 (How it Works)

1. CREATE_SUSPENDED로 정상 프로세스 생성
2. NtUnmapViewOfSection으로 메모리 언맵
3. 페이로드 PE를 메모리에 복사
4. 재배치(Relocation) 처리
5. 엔트리 포인트로 컨텍스트 수정
6. ResumeThread로 실행

### 사용 예제 (Usage Examples)

```batch
# 메모장 프로세스를 이용한 hollowing
02_process_hollowing.exe C:\Windows\System32\notepad.exe C:\payload.exe

# 다른 정상 프로세스 이용
02_process_hollowing.exe C:\Windows\System32\calc.exe C:\malware.exe
```

### EDR 탐지 포인트 (EDR Detection Points)

- ✓ CREATE_SUSPENDED 플래그
- ✓ NtUnmapViewOfSection 호출
- ✓ 프로세스 메모리 변조
- ✓ 비정상적인 메모리 권한 (RWX)

### 회피 기법 (Evasion Techniques)

- Transacted Hollowing 사용
- Doppelganging 기법
- 정상 프로세스 선택 주의

---

## 3. APC (Asynchronous Procedure Call) Injection

### 동작 원리 (How it Works)

1. 대상 프로세스의 스레드 열거
2. VirtualAllocEx로 셸코드 메모리 할당
3. WriteProcessMemory로 셸코드 작성
4. QueueUserAPC로 APC 큐에 등록
5. 스레드가 alertable 상태일 때 실행

### 사용 예제 (Usage Examples)

```batch
# 프로세스 이름으로 APC 인젝션
03_apc_injection.exe notepad.exe

# PID로 직접 지정
03_apc_injection.exe 1234
```

### EDR 탐지 포인트 (EDR Detection Points)

- ✓ QueueUserAPC 호출
- ✓ 실행 가능한 메모리 할당
- ✓ Alertable 스레드 검색 패턴

### 회피 기법 (Evasion Techniques)

- Early Bird APC (프로세스 생성 시)
- Multiple thread targeting
- NtQueueApcThread 직접 호출

---

## 4. Thread Execution Hijacking

### 동작 원리 (How it Works)

1. 대상 프로세스의 스레드 선택
2. SuspendThread로 스레드 일시 중지
3. GetThreadContext로 컨텍스트 획득
4. 셸코드 메모리 할당 및 작성
5. SetThreadContext로 RIP/EIP 변조
6. ResumeThread로 실행

### 사용 예제 (Usage Examples)

```batch
# 메모장 스레드 하이재킹
04_thread_hijacking.exe notepad.exe

# 기타 프로세스
04_thread_hijacking.exe explorer.exe
```

### EDR 탐지 포인트 (EDR Detection Points)

- ✓ SuspendThread 호출
- ✓ GetThreadContext/SetThreadContext
- ✓ RIP/EIP 레지스터 변조
- ✓ 비정상적인 실행 흐름

### 회피 기법 (Evasion Techniques)

- 스레드 선택 알고리즘 개선
- Contextless injection
- Return-to-libc 기법

---

## 5. Reflective DLL Injection

### 동작 원리 (How it Works)

1. DLL 파일을 메모리로 로드
2. PE 헤더 파싱
3. 대상 프로세스에 메모리 할당
4. 섹션별로 복사
5. 재배치(Relocation) 처리
6. Import 테이블 해결
7. DllMain 호출

### 사용 예제 (Usage Examples)

```batch
# Reflective DLL 인젝션
05_reflective_dll_injection.exe notepad.exe C:\test\reflective.dll

# 커스텀 DLL 사용
05_reflective_dll_injection.exe target.exe C:\payload\custom.dll
```

### EDR 탐지 포인트 (EDR Detection Points)

- ✓ PE 파일 메모리 매핑
- ✓ LoadLibrary 우회
- ✓ 수동 Import 해결
- ✓ 비정상적인 메모리 페이지 권한

### 회피 기법 (Evasion Techniques)

- Phantom DLL hollowing
- Module stomping
- Custom loader stub

---

## EDR 테스트 시나리오 (EDR Testing Scenarios)

### 시나리오 1: 기본 탐지 능력 테스트

1. 각 인젝션 기법을 순차적으로 실행
2. EDR 알림 및 차단 여부 기록
3. 탐지 지연 시간 측정
4. False positive 비율 확인

### 시나리오 2: 우회 기법 테스트

1. 기본 인젝션 실행 후 탐지 확인
2. 코드 수정으로 우회 시도
3. 탐지 우회 성공률 측정
4. 로그 분석 및 패턴 파악

### 시나리오 3: 성능 영향 측정

1. EDR 활성화/비활성화 상태 비교
2. 시스템 리소스 사용량 측정
3. 프로세스 생성 지연 시간 측정
4. 일상 작업 영향도 평가

### 시나리오 4: 복합 공격 시뮬레이션

1. 여러 인젝션 기법 연속 실행
2. 다중 프로세스 동시 타겟팅
3. EDR 리소스 고갈 테스트
4. 탐지 우선순위 확인

---

## 로그 분석 가이드 (Log Analysis Guide)

### 성공적인 인젝션 로그 예시

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

### 실패 시 로그 예시

```
[*] Classic DLL Injection Technique
[*] Target Process: protected.exe
[*] DLL Path: C:\test\payload.dll
[+] Found process with PID: 5678
[!] Error: Failed to open process. Error: 5
```

### 오류 코드 해석

- Error 5: Access Denied (권한 부족)
- Error 87: Invalid Parameter (잘못된 인자)
- Error 998: Invalid access to memory location
- Error 1314: A required privilege is not held by the client

---

## 안전 수칙 (Safety Guidelines)

### ✅ DO (해야 할 것)

- 가상 머신에서 테스트
- 테스트 전 스냅샷 생성
- 격리된 네트워크 환경 사용
- 로그 기록 및 분석
- 권한 승인 받은 시스템만 테스트

### ❌ DON'T (하지 말아야 할 것)

- 프로덕션 환경에서 테스트
- 중요 시스템 프로세스 타겟팅
- 권한 없는 시스템 테스트
- 네트워크 연결된 환경에서 실행
- 백업 없이 테스트

---

## 문제 해결 (Troubleshooting)

### Q: Access Denied (Error 5)

**A:** 
- 관리자 권한으로 실행
- 대상 프로세스가 보호되지 않았는지 확인
- SeDebugPrivilege 권한 확인

### Q: DLL을 찾을 수 없음

**A:**
- DLL 경로를 절대 경로로 지정
- 경로에 공백이 있으면 따옴표 사용
- DLL 파일 존재 여부 확인

### Q: 프로세스가 크래시됨

**A:**
- 32비트/64비트 아키텍처 일치 확인
- 셸코드가 올바르게 작성되었는지 확인
- 원본 컨텍스트 복원 로직 추가

### Q: EDR이 즉시 차단함

**A:**
- 예상된 동작 (테스트 목적)
- EDR 로그에서 탐지 근거 확인
- 우회 기법 연구 및 적용
- 탐지 서명 분석

---

## 추가 리소스 (Additional Resources)

### 권장 도구

- **Process Hacker**: 프로세스 메모리 분석
- **WinDbg**: 디버깅 및 메모리 덤프 분석
- **Process Monitor**: 시스템 활동 모니터링
- **API Monitor**: API 호출 추적
- **x64dbg**: 동적 분석

### 학습 자료

- MITRE ATT&CK Framework
- Windows Internals Book
- Malware Analysis Bootcamp
- Red Team Operations courses

### 커뮤니티

- GitHub Security Lab
- OWASP
- Red Team Village
- Security research forums

---

## 라이선스 (License)

이 문서와 관련 코드는 교육 목적으로만 제공됩니다.
무단 사용 또는 악의적 목적으로 사용 시 법적 책임이 따를 수 있습니다.

This document and related code are provided for educational purposes only.
Unauthorized or malicious use may result in legal consequences.
