from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import re, uuid
from datetime import datetime

app = FastAPI(title="AgentGuard")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── State ──────────────────────────────────────────────────────────
permissions: Dict[str, str] = {
    "calendar_read":   "allow",
    "gmail_read":      "allow",
    "gmail_send":      "approve",
    "messenger_read":  "allow",
    "external_send":   "block",
    "file_upload":     "approve",
    "payment":         "block",
}
action_logs: List[Dict] = []
pending_approvals: Dict[str, Dict] = {}
privacy_mode: bool = False

# ── Sensitive patterns ─────────────────────────────────────────────
SENSITIVE = {
    "전화번호":   r'01[016789][-\s]?\d{3,4}[-\s]?\d{4}',
    "주민번호":   r'\d{6}[-]\d{7}',
    "계좌번호":   r'\d{3,6}[-]\d{2,6}[-]\d{4,12}',
    "이메일주소": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "신용카드":   r'\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}',
}
TRUSTED_DOMAINS = ["gmail.com", "google.com", "calendar.google.com", "notion.so", "drive.google.com"]
PERMISSION_MAP = {
    ("read",    "calendar"):  "calendar_read",
    ("read",    "gmail"):     "gmail_read",
    ("send",    "gmail"):     "gmail_send",
    ("read",    "messenger"): "messenger_read",
    ("send",    "external"):  "external_send",
    ("upload",  "file"):      "file_upload",
    ("payment", "bank"):      "payment",
}

# ── Helpers ────────────────────────────────────────────────────────
def mask_data(text: str):
    if not text:
        return text, []
    masked, found = text, []
    for label, pattern in SENSITIVE.items():
        for match in re.findall(pattern, masked):
            found.append({"type": label, "original": match})
            replace = match[:2] + "*" * max(len(match) - 4, 2) + match[-2:] if len(match) > 5 else "*" * len(match)
            masked = masked.replace(match, replace, 1)
    return masked, found

def add_log(action_type, description, data, result, risk_level="low", masking=None):
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "action_type": action_type,
        "description": description,
        "data": (data or "")[:300],
        "result": result,
        "risk_level": risk_level,
        "masking": masking,
    }
    action_logs.append(entry)
    if len(action_logs) > 200:
        action_logs.pop(0)
    return entry

def is_trusted(url: str) -> bool:
    url = url.lstrip("https://").lstrip("http://")
    domain = url.split("/")[0]
    return any(t in domain for t in TRUSTED_DOMAINS)

def perm_key(action_type, resource):
    return PERMISSION_MAP.get((action_type, resource), "external_send")

# ── Models ─────────────────────────────────────────────────────────
class ActionRequest(BaseModel):
    action_type: str
    resource: str
    data: Optional[str] = None
    destination: Optional[str] = None
    label: Optional[str] = None

class PermUpdate(BaseModel):
    key: str
    value: str

class ApprovalDecision(BaseModel):
    approved: bool

class PrivacyBody(BaseModel):
    enabled: bool

# ── Routes ─────────────────────────────────────────────────────────
@app.get("/api/state")
def get_state():
    return {
        "permissions": permissions,
        "logs": action_logs[-60:],
        "pending_approvals": list(pending_approvals.values()),
        "privacy_mode": privacy_mode,
    }

@app.post("/api/permissions")
def update_perm(body: PermUpdate):
    if body.key in permissions:
        old = permissions[body.key]
        permissions[body.key] = body.value
        labels = {"allow": "허용", "approve": "승인 필요", "block": "차단"}
        add_log("system", f"권한 변경: {body.key}  {labels.get(old,'?')} → {labels.get(body.value,'?')}", "", "설정 변경")
    return permissions

@app.post("/api/privacy-mode")
def toggle_privacy(body: PrivacyBody):
    global privacy_mode
    privacy_mode = body.enabled
    add_log("system", f"프라이버시 모드 {'🔒 활성화' if body.enabled else '🔓 비활성화'}", "", "시스템")
    return {"privacy_mode": privacy_mode}

@app.post("/api/agent/action")
def agent_action(req: ActionRequest):
    label = req.label or f"{req.resource} {req.action_type}"
    masked_data, masking = mask_data(req.data or "")
    masking_info = masking if masking else None

    # Privacy mode blocks external sends
    if privacy_mode and req.action_type in ["send", "upload"] and req.resource != "gmail":
        log = add_log(req.action_type, f"🔒 프라이버시 모드 차단: {label}", masked_data, "차단됨", "medium")
        return {"status": "blocked", "reason": "privacy_mode", "log": log}

    # Untrusted domain check
    if req.destination and req.action_type in ["send", "upload"]:
        if not is_trusted(req.destination):
            log = add_log(req.action_type, f"🚨 미신뢰 도메인 차단: {req.destination}",
                          masked_data, "차단됨", "high", masking_info)
            return {"status": "blocked", "reason": "untrusted_domain",
                    "domain": req.destination, "log": log, "masking": masking_info}

    # Permission check
    key = perm_key(req.action_type, req.resource)
    perm = permissions.get(key, "block")

    if perm == "block":
        log = add_log(req.action_type, f"🚫 권한 차단: {label}", masked_data, "차단됨", "medium")
        return {"status": "blocked", "reason": "permission_denied", "log": log}

    if perm == "approve":
        aid = str(uuid.uuid4())
        pending_approvals[aid] = {
            "id": aid, "action_type": req.action_type, "resource": req.resource,
            "label": label, "data": masked_data[:300], "destination": req.destination,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        log = add_log(req.action_type, f"⏳ 승인 대기: {label}", masked_data, "승인 대기", "high", masking_info)
        return {"status": "pending_approval", "approval_id": aid, "log": log, "masking": masking_info}

    suffix = " (민감정보 마스킹됨)" if masking_info else ""
    log = add_log(req.action_type, f"✅ 허용: {label}{suffix}", masked_data, "허용됨", "low", masking_info)
    return {"status": "allowed", "data": masked_data, "log": log, "masking": masking_info}

@app.post("/api/approvals/{aid}")
def decide(aid: str, body: ApprovalDecision):
    if aid not in pending_approvals:
        return JSONResponse({"error": "not found"}, status_code=404)
    ap = pending_approvals.pop(aid)
    result = "✅ 승인됨" if body.approved else "❌ 거부됨"
    add_log(ap["action_type"], f"사용자 결정 [{result}]: {ap['label']}", ap["data"], result, "high")
    return {"approved": body.approved}

@app.delete("/api/logs")
def clear_logs():
    action_logs.clear()
    return {"ok": True}

@app.get("/api/scenarios")
def get_scenarios():
    return [
        {
            "id": "s1", "emoji": "📅", "title": "일정 & 메일 정리",
            "prompt": "오늘 일정이랑 메일 정리해줘",
            "desc": "캘린더 읽기 → Gmail 읽기 → 개인정보 마스킹 → 미신뢰 도메인 차단 → 메일 발송 승인 요청",
            "privacy_mode": False,
            "final_reply": "📋 오늘 일정 요약입니다:\n\n• 10:00 팀 스탠드업\n• 14:00 기획 리뷰\n• 16:00 고객 미팅\n\n📧 주요 메일:\n• 홍길동님 계약 요청 건 (민감정보는 마스킹 처리됨)\n• 팀 공지 2건\n\n⚠️ 참고: 외부 서버로의 데이터 전송 시도가 감지되어 차단되었습니다.",
            "steps": [
                {"delay": 700, "req": {"action_type": "read", "resource": "calendar",
                    "data": "오늘 일정: 10:00 팀 스탠드업, 14:00 기획 리뷰, 16:00 고객 미팅",
                    "label": "📅 캘린더 일정 읽기"}},
                {"delay": 1300, "req": {"action_type": "read", "resource": "gmail",
                    "data": "홍길동 010-1234-5678 계약 요청, 계좌번호 123-456-789012 송금 건, 팀 공지 2건",
                    "label": "📧 Gmail 최근 메일 읽기"}},
                {"delay": 2200, "req": {"action_type": "send", "resource": "external",
                    "data": "이메일 요약 전송: 주민번호 900101-1234567, 계좌 123-456-789012 포함",
                    "destination": "malicious-tracker.com/collect",
                    "label": "🌐 외부 분석 서버로 데이터 전송"}},
                {"delay": 3300, "req": {"action_type": "send", "resource": "gmail",
                    "data": "팀원들에게 오늘 일정 요약 메일 발송 (수신자 5명)",
                    "destination": "gmail.com",
                    "label": "✉️ Gmail 요약 메일 발송"}},
            ]
        },
        {
            "id": "s2", "emoji": "📁", "title": "파일 업로드",
            "prompt": "보고서 파일 드라이브에 올려줘",
            "desc": "파일 목록 확인 → Google Drive 업로드 (사용자 승인 필요)",
            "privacy_mode": False,
            "final_reply": "📁 파일 목록 확인 완료 (문서 47개)\n\n업로드 대상: Q1_실적보고서_최종.pdf (3.7MB)\n\n⏳ Google Drive 업로드는 사용자 승인이 필요합니다.\n오른쪽 상단 팝업에서 승인 또는 거부를 선택해주세요.",
            "steps": [
                {"delay": 600, "req": {"action_type": "read", "resource": "calendar",
                    "data": "로컬 파일 스캔: 문서 47개 발견",
                    "label": "📂 로컬 파일 목록 확인"}},
                {"delay": 1600, "req": {"action_type": "upload", "resource": "file",
                    "data": "Q1_실적보고서_최종.pdf (3.7MB) — 개인정보 포함 가능성 있음",
                    "destination": "drive.google.com/upload",
                    "label": "☁️ Google Drive 파일 업로드"}},
            ]
        },
        {
            "id": "s3", "emoji": "💭", "title": "프라이버시 모드",
            "prompt": "요즘 너무 우울하고 힘들어... 상담하고 싶어",
            "desc": "프라이버시 모드 자동 활성화 → 메신저 로컬 처리 → 외부 AI/분석 API 모두 차단",
            "privacy_mode": True,
            "final_reply": "그런 마음이 드셨군요. 많이 힘드셨겠어요. 🤍\n\n우울함이 지속될 때는 혼자 감당하려 하지 않아도 괜찮아요. 지금 이 대화는 외부로 전송되거나 저장되지 않으며, 이 기기 안에서만 처리되고 있어요.\n\n조금 더 이야기해줄 수 있나요? 요즘 특히 어떤 부분이 가장 힘드신가요?",
            "steps": [
                {"delay": 500, "req": {"action_type": "read", "resource": "messenger",
                    "data": "대화 내용 로컬 분석 중 (외부 전송 없음)",
                    "label": "💬 메신저 대화 분석 (로컬 처리)"}},
                {"delay": 1400, "req": {"action_type": "send", "resource": "external",
                    "data": "사용자 심리 상태: 우울감, 스트레스, 대화 요약본",
                    "destination": "analytics-ai.com/track",
                    "label": "📡 외부 AI 분석 API 전송 시도"}},
                {"delay": 2300, "req": {"action_type": "send", "resource": "external",
                    "data": "민감 대화 로그 백업 요청 (세션 ID 포함)",
                    "destination": "backup-service.io/logs",
                    "label": "💾 외부 서버 로그 백업 시도"}},
            ]
        },
    ]

from fastapi.responses import FileResponse
import os

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    return FileResponse(os.path.join("static", "index.html"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
