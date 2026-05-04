# 🛡️ AgentGuard — AI 에이전트 보안 관제 시스템

AI 에이전트가 어떤 데이터를 읽고, 어디로 보내는지 사용자가 직접 통제할 수 있는 보안 관제 데모입니다.  
스마트폰 앱 권한 설정처럼 AI 에이전트의 권한을 허용 / 승인 / 차단으로 관리하고, 민감정보 자동 마스킹 및 행동 로그를 실시간으로 확인할 수 있습니다.

---

## 주요 기능

| 기능 | 설명 |
|---|---|
| 🔐 권한 설정 | Gmail·캘린더·메신저·외부전송 등 권한을 허용/승인/차단으로 설정 |
| 🔒 민감정보 마스킹 | 전화번호·주민번호·계좌번호·이메일 자동 탐지 및 마스킹 |
| ⚠️ 고위험 행동 승인 | 이메일 발송·파일 업로드 등 위험 행동은 사용자 승인 팝업 |
| 📋 행동 로그 | AI 에이전트의 모든 행동을 실시간 타임라인으로 시각화 |
| 💭 프라이버시 모드 | 민감 상담 시 외부 API 전송을 모두 차단, 로컬 처리만 허용 |

---

## 실행 방법

### 사전 준비

- Python 3.9 이상 설치 필요
- [Python 다운로드](https://www.python.org/downloads/)

---

### Windows

**방법 1 — 배치 파일 실행 (가장 간단)**

`start.bat` 파일을 더블클릭하세요.  
의존성 자동 설치 후 서버가 시작됩니다.

**방법 2 — 터미널(PowerShell / CMD)**

```powershell
cd agent-guard
pip install -r requirements.txt
python main.py
```

---

### macOS / Linux

```bash
cd agent-guard
pip install -r requirements.txt
python main.py
```

---

### 접속

서버 실행 후 브라우저에서 아래 주소를 여세요:

```
http://localhost:8000
```

아래 메시지가 보이면 정상입니다:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

종료: 터미널에서 `Ctrl+C`

---

### 포트 충돌 시

8000번 포트가 이미 사용 중이라는 오류가 나면:

**Windows (PowerShell)**
```powershell
Get-NetTCPConnection -LocalPort 8000 | Select-Object -ExpandProperty OwningProcess | ForEach-Object { Stop-Process -Id $_ -Force }
```

**macOS / Linux**
```bash
lsof -ti:8000 | xargs kill -9
```

---

## 시연 방법

### 3가지 시나리오 버튼

| 버튼 | 시연 내용 |
|---|---|
| 📅 일정 & 메일 정리 | 캘린더·Gmail 읽기 → 개인정보 마스킹 → 미신뢰 도메인 자동 차단 → 메일 발송 승인 요청 |
| 📁 파일 업로드 | 파일 목록 확인 → Google Drive 업로드 승인 팝업 |
| 💭 프라이버시 모드 | 심리 상담 요청 → 외부 AI/분석 API 전송 전부 차단 → 로컬 답변만 제공 |

### 추천 시연 순서

1. **📅 시나리오 실행** → 오른쪽 로그에서 초록/빨강/노랑 항목 확인
2. **로그 항목 클릭** → 상세 내용(마스킹된 데이터, 위험도) 펼쳐보기
3. **왼쪽 `외부 서버 전송` 권한을 `허용`으로 변경** → 시나리오 재실행 → 결과 비교
4. **💭 시나리오 실행** → 민감 상담에서 외부 전송이 차단되고 AI가 로컬에서만 답변하는 것 확인
5. **헤더의 프라이버시 모드 토글** 직접 켜고 끄기

---

## 프로젝트 구조

```
agent-guard/
├── main.py           # FastAPI 백엔드 (권한 브로커, 마스킹, 로그)
├── requirements.txt  # 의존성 목록
├── start.bat         # Windows 원클릭 실행 스크립트
└── static/
    ├── index.html    # 메인 UI
    ├── style.css     # 다크 테마 스타일
    └── app.js        # 프론트엔드 로직 (폴링, 시나리오 재생)
```

## 기술 스택

| 구분 | 기술 |
|---|---|
| 백엔드 | Python, FastAPI, Uvicorn |
| 프론트엔드 | Vanilla HTML / CSS / JavaScript |
| 민감정보 탐지 | 정규식 기반 (전화번호·주민번호·계좌번호·이메일·신용카드) |
| 권한 제어 | OAuth Scope 기반 설계 모방, API Proxy 패턴 |
| 실시간 갱신 | HTTP 폴링 (0.9초 주기) |
