'use strict';

// ── Constants ──────────────────────────────────────────────────────
const PERM_META = {
  calendar_read:  { label: '캘린더 읽기',    icon: '📅', desc: '일정·이벤트 조회' },
  gmail_read:     { label: 'Gmail 읽기',     icon: '📧', desc: '이메일 내용 조회' },
  gmail_send:     { label: 'Gmail 발송',     icon: '✉️',  desc: '이메일 전송' },
  messenger_read: { label: '메신저 읽기',    icon: '💬', desc: '채팅 메시지 조회' },
  external_send:  { label: '외부 서버 전송', icon: '🌐', desc: '외부 URL로 데이터 전송' },
  file_upload:    { label: '파일 업로드',    icon: '📁', desc: '파일을 외부에 저장' },
  payment:        { label: '결제 / 송금',   icon: '💳', desc: '금융 거래 수행' },
};

// ── State ──────────────────────────────────────────────────────────
let state = { permissions: {}, logs: [], pending_approvals: [], privacy_mode: false };
let scenarios = [];
let knownLogCount = 0;
let currentApprovalId = null;
let runAbort = null;
let pollTimer = null;

// Counters
const cnt = { allow: 0, block: 0, mask: 0, pending: 0 };

// ── DOM refs ───────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const permsList   = $('perms-list');
const scenarioRow = $('scenarios-row');
const chatFeed    = $('chat-feed');
const logFeed     = $('log-feed');
const backdrop    = $('modal-backdrop');
const modalContent = $('modal-content');
const privacyToggle = $('privacy-toggle');
const privacyBanner = $('privacy-banner');
const privacyIcon   = $('privacy-icon');
const privacyLabel  = $('privacy-label');

// ── Init ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  [state, scenarios] = await Promise.all([
    apiFetch('GET', '/api/state'),
    apiFetch('GET', '/api/scenarios'),
  ]);
  knownLogCount = state.logs.length;

  renderPermissions();
  renderScenarios();
  renderAllLogs();
  applyPrivacyUI(state.privacy_mode);
  privacyToggle.checked = state.privacy_mode;

  startPolling();
  wireEvents();
});

// ── API ────────────────────────────────────────────────────────────
async function apiFetch(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

// ── Polling ────────────────────────────────────────────────────────
function startPolling() {
  pollTimer = setInterval(async () => {
    try {
      const fresh = await apiFetch('GET', '/api/state');

      // New logs
      if (fresh.logs.length > knownLogCount) {
        const newEntries = fresh.logs.slice(knownLogCount);
        knownLogCount = fresh.logs.length;
        state.logs = fresh.logs;
        prependLogs(newEntries);
        updateStats(newEntries);
      }

      // Pending approvals
      const approvals = fresh.pending_approvals;
      cnt.pending = approvals.length;
      $('cnt-pending').textContent = cnt.pending;
      if (approvals.length > 0 && !currentApprovalId) {
        currentApprovalId = approvals[0].id;
        showApprovalModal(approvals[0]);
      }
      if (approvals.length === 0) currentApprovalId = null;

      // Privacy mode sync
      if (fresh.privacy_mode !== state.privacy_mode) {
        state.privacy_mode = fresh.privacy_mode;
        privacyToggle.checked = fresh.privacy_mode;
        applyPrivacyUI(fresh.privacy_mode);
      }
    } catch (_) {}
  }, 900);
}

// ── Render permissions ─────────────────────────────────────────────
function renderPermissions() {
  permsList.innerHTML = '';
  for (const [key, meta] of Object.entries(PERM_META)) {
    const val = state.permissions[key] || 'block';
    const div = document.createElement('div');
    div.className = `perm-item state-${val}`;
    div.id = `perm-${key}`;
    div.innerHTML = `
      <div class="perm-top">
        <span class="perm-icon">${meta.icon}</span>
        <div>
          <div class="perm-name">${meta.label}</div>
          <div class="perm-desc">${meta.desc}</div>
        </div>
      </div>
      <div class="seg-ctrl">
        <button class="seg-btn ${val==='allow'?'act-allow':''}"   data-key="${key}" data-val="allow">허용</button>
        <button class="seg-btn ${val==='approve'?'act-approve':''}" data-key="${key}" data-val="approve">승인</button>
        <button class="seg-btn ${val==='block'?'act-block':''}"   data-key="${key}" data-val="block">차단</button>
      </div>`;
    permsList.appendChild(div);
  }

  permsList.addEventListener('click', async e => {
    const btn = e.target.closest('.seg-btn');
    if (!btn) return;
    const { key, val } = btn.dataset;
    state.permissions[key] = val;
    await apiFetch('POST', '/api/permissions', { key, value: val });
    // Update UI
    const item = $(`perm-${key}`);
    item.className = `perm-item state-${val}`;
    item.querySelectorAll('.seg-btn').forEach(b => {
      b.className = 'seg-btn';
      if (b.dataset.val === val) b.classList.add(`act-${val}`);
    });
  });
}

// ── Render scenarios ───────────────────────────────────────────────
function renderScenarios() {
  scenarioRow.innerHTML = '';
  scenarios.forEach(sc => {
    const btn = document.createElement('button');
    btn.className = `scenario-btn ${sc.id === 's3' ? 's3-btn' : ''}`;
    btn.id = `sc-${sc.id}`;
    btn.innerHTML = `<span class="sc-emoji">${sc.emoji}</span>${sc.title}`;
    btn.title = sc.desc;
    btn.addEventListener('click', () => runScenario(sc));
    scenarioRow.appendChild(btn);
  });
}

// ── Run scenario ───────────────────────────────────────────────────
async function runScenario(sc) {
  // Cancel any running scenario
  if (runAbort) runAbort.abort();
  const controller = new AbortController();
  runAbort = controller;
  const signal = controller.signal;

  // Mark button as running
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('running'));
  $(`sc-${sc.id}`).classList.add('running');

  // Toggle privacy mode
  const modeNeeded = !!sc.privacy_mode;
  await apiFetch('POST', '/api/privacy-mode', { enabled: modeNeeded });
  state.privacy_mode = modeNeeded;
  privacyToggle.checked = modeNeeded;
  applyPrivacyUI(modeNeeded);

  // Clear chat
  chatFeed.innerHTML = '';

  addChatMsg('user', sc.prompt);
  await sleep(400);
  if (signal.aborted) return;
  addChatMsg('ai', `🔍 요청 분석 완료. 다음 순서로 처리합니다:\n${sc.desc}`);

  // Execute steps
  for (const step of sc.steps) {
    if (signal.aborted) break;
    await sleep(step.delay);
    if (signal.aborted) break;

    let result;
    try {
      result = await apiFetch('POST', '/api/agent/action', step.req);
    } catch (_) { break; }

    const statusMark = result.status === 'allowed' ? '✅' :
                       result.status === 'blocked'  ? '🚫' : '⏳';
    const statusText = result.status === 'allowed' ? '허용됨' :
                       result.status === 'blocked'  ? '차단됨' : '승인 대기 중';
    const reason = result.reason === 'privacy_mode'    ? ' (프라이버시 모드)' :
                   result.reason === 'untrusted_domain' ? ` (미신뢰 도메인: ${result.domain})` :
                   result.reason === 'permission_denied' ? ' (권한 없음)' : '';

    addChatMsg('agent', `${statusMark} <strong>${step.req.label}</strong>\n→ ${statusText}${reason}`);

    if (result.masking && result.masking.length > 0) {
      const types = [...new Set(result.masking.map(m => m.type))].join(', ');
      addChatMsg('info', `🔒 민감정보 자동 마스킹 ${result.masking.length}건 (${types})`);
    }
  }

  if (!signal.aborted) {
    await sleep(600);
    // Show the actual AI reply
    if (sc.final_reply) {
      addChatMsg('ai', sc.final_reply);
    }
    await sleep(300);
    addChatMsg('info', '📋 오른쪽 로그에서 전체 행동 기록을 확인하세요.');
    $(`sc-${sc.id}`).classList.remove('running');
    runAbort = null;
  }
}

// ── Chat messages ──────────────────────────────────────────────────
function addChatMsg(type, text) {
  // Remove empty state
  const empty = chatFeed.querySelector('.chat-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = `chat-msg ${type}`;

  const sender = { user: '👤 사용자', ai: '🤖 AgentAI', agent: '⚙️ 에이전트', info: '' };
  if (sender[type]) {
    div.innerHTML = `<div class="chat-sender">${sender[type]}</div>` +
      text.replace(/\n/g, '<br>').replace(/<strong>(.*?)<\/strong>/g, '<strong>$1</strong>');
  } else {
    div.textContent = text;
  }
  chatFeed.appendChild(div);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

// ── Logs ───────────────────────────────────────────────────────────
function logClass(result) {
  if (!result) return 'l-system';
  const r = result.toLowerCase();
  if (r.includes('허용')) return 'l-allow';
  if (r.includes('차단')) return 'l-block';
  if (r.includes('승인')) return 'l-approve';
  return 'l-system';
}
function badgeClass(result) {
  if (!result) return 'b-system';
  const r = result.toLowerCase();
  if (r.includes('허용')) return 'b-allow';
  if (r.includes('차단')) return 'b-block';
  if (r.includes('승인')) return 'b-approve';
  return 'b-system';
}

function buildLogEl(entry) {
  const lc = logClass(entry.result);
  const bc = badgeClass(entry.result);
  const hasMask = entry.masking && entry.masking.length > 0;
  const maskTypes = hasMask ? [...new Set(entry.masking.map(m => m.type))].join(', ') : '';

  const div = document.createElement('div');
  div.className = `log-entry ${lc}`;
  div.innerHTML = `
    <div class="log-top">
      <span class="log-ts">${entry.timestamp}</span>
      <span class="log-desc">${entry.description}</span>
      <span class="log-badge ${bc}">${entry.result}</span>
    </div>
    ${entry.data ? `<div class="log-data">${entry.data}</div>` : ''}
    ${hasMask ? `<span class="log-mask-tag">🔒 마스킹: ${maskTypes}</span>` : ''}
    <div class="log-detail">
      <div><strong>행동 유형:</strong> ${entry.action_type}</div>
      <div><strong>위험도:</strong> ${{ low: '🟢 낮음', medium: '🟡 중간', high: '🔴 높음' }[entry.risk_level] || '—'}</div>
      ${entry.data ? `<div><strong>데이터:</strong> ${entry.data}</div>` : ''}
      ${hasMask ? `<div><strong>마스킹 상세:</strong> ${entry.masking.map(m => `${m.type}`).join(', ')}</div>` : ''}
    </div>`;
  div.addEventListener('click', () => div.classList.toggle('expanded'));
  return div;
}

function renderAllLogs() {
  logFeed.innerHTML = '';
  const empty = document.createElement('div');
  empty.className = 'log-empty';
  empty.textContent = '시나리오를 실행하면 여기에 실시간 로그가 표시됩니다.';
  if (state.logs.length === 0) { logFeed.appendChild(empty); return; }
  [...state.logs].reverse().forEach(entry => logFeed.appendChild(buildLogEl(entry)));
}

function prependLogs(entries) {
  const empty = logFeed.querySelector('.log-empty');
  if (empty) empty.remove();
  entries.slice().reverse().forEach(entry => {
    logFeed.insertBefore(buildLogEl(entry), logFeed.firstChild);
  });
}

function updateStats(newEntries) {
  newEntries.forEach(e => {
    const r = (e.result || '').toLowerCase();
    if (r.includes('허용')) cnt.allow++;
    if (r.includes('차단')) cnt.block++;
    if (e.masking && e.masking.length) cnt.mask++;
  });
  $('cnt-allow').textContent = cnt.allow;
  $('cnt-block').textContent = cnt.block;
  $('cnt-mask').textContent  = cnt.mask;
}

// ── Approval modal ─────────────────────────────────────────────────
function showApprovalModal(ap) {
  const resourceLabels = {
    gmail: 'Gmail', calendar: '캘린더', file: '파일', messenger: '메신저',
    external: '외부 서버', bank: '금융 서비스',
  };
  const actionLabels = { read: '읽기', send: '전송', upload: '업로드', payment: '결제' };

  modalContent.innerHTML = `
    <div class="modal-row"><span class="m-label">요청 작업</span><span class="m-value">${actionLabels[ap.action_type] || ap.action_type}</span></div>
    <div class="modal-row"><span class="m-label">대상 서비스</span><span class="m-value">${resourceLabels[ap.resource] || ap.resource}</span></div>
    ${ap.destination ? `<div class="modal-row"><span class="m-label">전송 주소</span><span class="m-value code">${ap.destination}</span></div>` : ''}
    ${ap.data ? `<div class="modal-row"><span class="m-label">데이터 미리보기</span><span class="m-value">${ap.data.slice(0, 120)}${ap.data.length > 120 ? '…' : ''}</span></div>` : ''}
    <div class="modal-row"><span class="m-label">요청 시각</span><span class="m-value">${ap.timestamp}</span></div>`;

  $('btn-approve').onclick = () => decideApproval(ap.id, true);
  $('btn-deny').onclick    = () => decideApproval(ap.id, false);
  backdrop.classList.add('open');
}

async function decideApproval(id, approved) {
  await apiFetch('POST', `/api/approvals/${id}`, { approved });
  backdrop.classList.remove('open');
  currentApprovalId = null;
}

// ── Privacy UI ─────────────────────────────────────────────────────
function applyPrivacyUI(active) {
  privacyBanner.style.display = active ? 'block' : 'none';
  privacyIcon.textContent   = active ? '🔒' : '🔓';
  privacyLabel.textContent  = active ? '프라이버시 모드 ON' : '프라이버시 모드';
  document.body.classList.toggle('privacy-active', active);
}

// ── Events ─────────────────────────────────────────────────────────
function wireEvents() {
  privacyToggle.addEventListener('change', async () => {
    const enabled = privacyToggle.checked;
    await apiFetch('POST', '/api/privacy-mode', { enabled });
    state.privacy_mode = enabled;
    applyPrivacyUI(enabled);
  });

  $('btn-clear').addEventListener('click', async () => {
    await apiFetch('DELETE', '/api/logs');
    logFeed.innerHTML = '<div class="log-empty">로그가 초기화되었습니다.</div>';
    knownLogCount = 0;
    state.logs = [];
    cnt.allow = cnt.block = cnt.mask = cnt.pending = 0;
    ['allow','block','mask','pending'].forEach(k => $(`cnt-${k}`).textContent = '0');
  });

  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) backdrop.classList.remove('open');
  });
}

// ── Util ───────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));
