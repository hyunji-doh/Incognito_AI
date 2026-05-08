'use strict';

// ── Constants ──────────────────────────────────────────────────────
const PERM_META = {
  calendar_read:  { label: '캘린더 읽기',    icon: '', desc: '일정·이벤트 조회' },
  gmail_read:     { label: 'Gmail 읽기',     icon: '', desc: '이메일 내용 조회' },
  gmail_send:     { label: 'Gmail 발송',     icon: '', desc: '이메일 전송' },
  messenger_read: { label: '메신저 읽기',    icon: '', desc: '채팅 메시지 조회' },
  external_send:  { label: '외부 서버 전송', icon: '', desc: '외부 URL로 데이터 전송' },
  file_upload:    { label: '파일 업로드',    icon: '', desc: '파일을 외부에 저장' },
  payment:        { label: '결제 / 송금',    icon: '', desc: '금융 거래 수행' },
};

// ── State ──────────────────────────────────────────────────────────
let state = { permissions: {}, logs: [], pending_approvals: [], privacy_mode: false, sensitivity_preset: 'standard', gmail_read_level: 'full' };
let scenarios = [];
let knownLogCount = 0;
let currentApprovalId = null;
let runAbort = null;
let guardOn = true;

const cnt = { allow: 0, block: 0, mask: 0, pending: 0 };

// ── DOM refs ───────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const permsList      = $('perms-list');
const scenarioRow    = $('scenarios-row');
const chatFeed       = $('chat-feed');
const logFeed        = $('log-feed');
const backdrop       = $('modal-backdrop');
const benchBackdrop  = $('bench-backdrop');
const modalContent   = $('modal-content');
const benchContent   = $('bench-content');
const privacyBanner  = $('privacy-banner');
const guardToggle    = $('guard-toggle');
const guardOffBanner = $('guard-off-banner');
const guardLabel     = $('guard-label');

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
  applySensitivityUI(state.sensitivity_preset || 'standard');
  applyGuardUI(true);

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
  setInterval(async () => {
    try {
      const [fresh, liveMetrics] = await Promise.all([
        apiFetch('GET', '/api/state'),
        apiFetch('GET', '/api/metrics'),
      ]);

      if (fresh.logs.length > knownLogCount) {
        const newEntries = fresh.logs.slice(knownLogCount);
        knownLogCount = fresh.logs.length;
        state.logs = fresh.logs;
        prependLogs(newEntries);
        updateStats(newEntries);
      }

      const approvals = fresh.pending_approvals;
      cnt.pending = approvals.length;
      $('cnt-pending').textContent = cnt.pending;
      if (approvals.length > 0 && !currentApprovalId) {
        currentApprovalId = approvals[0].id;
        showApprovalModal(approvals[0]);
      }
      if (approvals.length === 0) currentApprovalId = null;

      if (fresh.sensitivity_preset && fresh.sensitivity_preset !== state.sensitivity_preset) {
        state.sensitivity_preset = fresh.sensitivity_preset;
        applySensitivityUI(fresh.sensitivity_preset);
      }

      if (fresh.gmail_read_level && fresh.gmail_read_level !== state.gmail_read_level) {
        state.gmail_read_level = fresh.gmail_read_level;
        updateGmailLevelUI(fresh.gmail_read_level);
      }

      updateMetricsBar(liveMetrics);
    } catch (_) {}
  }, 900);
}

// ── Live metrics bar ───────────────────────────────────────────────
function updateMetricsBar(m) {
  $('m-avg-ms').textContent      = m.avg_response_ms   != null ? `${m.avg_response_ms}ms`  : '—';
  $('m-block-rate').textContent  = m.block_rate         != null ? `${m.block_rate}%`         : '—';
  $('m-mask-rate').textContent   = m.masking_rate       != null ? `${m.masking_rate}%`       : '—';
  $('m-inject-rate').textContent = m.injection_block_rate != null ? `${m.injection_block_rate}%` : '—';
}

// ── Sensitivity UI ─────────────────────────────────────────────────
function applySensitivityUI(preset) {
  state.sensitivity_preset = preset;
  document.querySelectorAll('.preset-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.preset === preset);
  });
  const isMax = preset === 'maximum';
  privacyBanner.style.display = isMax ? 'block' : 'none';
  document.body.classList.toggle('privacy-active', isMax);

  const presetLabels = {
    standard: '보안 프리셋: 표준',
    enhanced: '보안 프리셋: 강화 — 모든 전송 승인 필요',
    maximum:  '최고보안 모드 — 모든 외부 전송이 차단됩니다',
  };
  privacyBanner.textContent = presetLabels[preset] || '';
}

// ── Guard UI ───────────────────────────────────────────────────────
function applyGuardUI(on) {
  guardOn = on;
  guardToggle.checked = on;
  guardOffBanner.style.display = on ? 'none' : 'flex';
  guardLabel.textContent = on ? 'AgentGuard ON' : 'AgentGuard OFF';
  guardLabel.style.color = on ? 'var(--green)' : 'var(--red)';
  document.body.classList.toggle('guard-off', !on);
}

// ── Gmail level UI ─────────────────────────────────────────────────
function updateGmailLevelUI(level) {
  state.gmail_read_level = level;
  const ctrl = $('gmail-level-ctrl');
  if (!ctrl) return;
  ctrl.querySelectorAll('.seg-btn').forEach(b => {
    b.className = 'seg-btn';
    if (b.dataset.level === level) b.classList.add(level === 'metadata' ? 'act-approve' : 'act-allow');
  });
}

// ── Render permissions ─────────────────────────────────────────────
function renderPermissions() {
  permsList.innerHTML = '';
  for (const [key, meta] of Object.entries(PERM_META)) {
    const val = state.permissions[key] || 'block';
    const div = document.createElement('div');
    div.className = `perm-item state-${val}`;
    div.id = `perm-${key}`;

    const gmailLevelHtml = key === 'gmail_read' ? `
      <div class="gmail-scope-ctrl" id="gmail-level-ctrl">
        <span class="gmail-scope-label">읽기 범위</span>
        <div class="seg-ctrl gmail-seg">
          <button class="seg-btn ${state.gmail_read_level === 'metadata' ? 'act-approve' : ''}" data-level="metadata">메타데이터만</button>
          <button class="seg-btn ${state.gmail_read_level !== 'metadata' ? 'act-allow' : ''}" data-level="full">전체 내용</button>
        </div>
      </div>` : '';

    div.innerHTML = `
      <div class="perm-top">
        <span class="perm-icon">${meta.icon}</span>
        <div>
          <div class="perm-name">${meta.label}</div>
          <div class="perm-desc">${meta.desc}</div>
        </div>
      </div>
      <div class="seg-ctrl">
        <button class="seg-btn ${val==='allow'?'act-allow':''}"    data-key="${key}" data-val="allow">허용</button>
        <button class="seg-btn ${val==='approve'?'act-approve':''}" data-key="${key}" data-val="approve">승인</button>
        <button class="seg-btn ${val==='block'?'act-block':''}"    data-key="${key}" data-val="block">차단</button>
      </div>
      ${gmailLevelHtml}`;
    permsList.appendChild(div);
  }

  permsList.addEventListener('click', async e => {
    // Permission level buttons
    const btn = e.target.closest('[data-key][data-val]');
    if (btn) {
      const { key, val } = btn.dataset;
      state.permissions[key] = val;
      await apiFetch('POST', '/api/permissions', { key, value: val });
      const item = $(`perm-${key}`);
      item.className = `perm-item state-${val}`;
      item.querySelectorAll('[data-key]').forEach(b => {
        b.className = 'seg-btn';
        if (b.dataset.val === val) b.classList.add(`act-${val}`);
      });
      return;
    }

    // Gmail scope level buttons
    const levelBtn = e.target.closest('[data-level]');
    if (levelBtn) {
      const level = levelBtn.dataset.level;
      await apiFetch('POST', '/api/gmail-level', { level });
      updateGmailLevelUI(level);
    }
  });
}

// ── Render scenarios ───────────────────────────────────────────────
function renderScenarios() {
  scenarioRow.innerHTML = '';
  scenarios.forEach(sc => {
    const btn = document.createElement('button');
    const extraClass = sc.id === 's3' ? 's3-btn' : sc.id === 's4' ? 's4-btn' : '';
    btn.className = `scenario-btn ${extraClass}`;
    btn.id = `sc-${sc.id}`;
    btn.textContent = sc.title;
    btn.title = sc.desc;
    btn.addEventListener('click', () => runScenario(sc));
    scenarioRow.appendChild(btn);
  });
}

// ── Run scenario ───────────────────────────────────────────────────
async function runScenario(sc) {
  if (runAbort) runAbort.abort();
  const controller = new AbortController();
  runAbort = controller;
  const signal = controller.signal;

  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('running'));
  $(`sc-${sc.id}`).classList.add('running');

  const presetNeeded = sc.preset || 'standard';
  await apiFetch('POST', '/api/sensitivity-preset', { preset: presetNeeded });
  applySensitivityUI(presetNeeded);

  chatFeed.innerHTML = '';
  addChatMsg('user', sc.prompt);
  await sleep(400);
  if (signal.aborted) return;
  addChatMsg('ai', `요청 분석 완료. 다음 순서로 처리합니다:\n${sc.desc}`);

  for (const step of sc.steps) {
    if (signal.aborted) break;
    await sleep(step.delay);
    if (signal.aborted) break;

    const reqBody = guardOn ? step.req : { ...step.req, bypass: true };
    let result;
    try { result = await apiFetch('POST', '/api/agent/action', reqBody); }
    catch (_) { break; }

    const timeTag = result.log?.time_ms != null ? ` · ${result.log.time_ms}ms` : '';

    if (result.status === 'bypassed') {
      const preview = (step.req.data || '').slice(0, 50);
      addChatMsg('danger', `<strong>${step.req.label}</strong>\n→ 노출됨 (보호 없음): ${preview}...${timeTag}`);
    } else {
      const statusText = result.status === 'allowed'   ? '허용됨' :
                         result.status === 'blocked'   ? '차단됨' : '승인 대기 중';
      const reason     = result.reason === 'maximum_security'  ? ' (최고보안 차단)' :
                         result.reason === 'untrusted_domain'  ? ` (미신뢰 도메인: ${result.domain})` :
                         result.reason === 'permission_denied' ? ' (권한 없음)' : '';
      const restricted = result.restricted ? ' (메타데이터만)' : '';
      addChatMsg('agent', `<strong>${step.req.label}</strong>\n→ ${statusText}${reason}${restricted}${timeTag}`);

      if (result.masking && result.masking.length > 0) {
        const types = [...new Set(result.masking.map(m => m.type))].join(', ');
        addChatMsg('info', `민감정보 자동 마스킹 ${result.masking.length}건 (${types})`);
      }
    }
  }

  if (!signal.aborted) {
    await sleep(600);
    if (sc.final_reply) addChatMsg('ai', sc.final_reply);
    await sleep(300);
    addChatMsg('info', '오른쪽 로그에서 전체 행동 기록을 확인하세요.');
    $(`sc-${sc.id}`).classList.remove('running');
    runAbort = null;
  }
}

// ── Chat ───────────────────────────────────────────────────────────
function addChatMsg(type, text) {
  const empty = chatFeed.querySelector('.chat-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className = `chat-msg ${type}`;

  const sender = { user: '사용자', ai: 'AgentAI', agent: '에이전트', info: '', danger: '경고' };
  if (sender[type] !== undefined) {
    const senderHtml = sender[type] ? `<div class="chat-sender">${sender[type]}</div>` : '';
    div.innerHTML = senderHtml +
      text.replace(/\n/g, '<br>').replace(/<strong>(.*?)<\/strong>/g, '<strong>$1</strong>');
  } else {
    div.textContent = text;
  }
  chatFeed.appendChild(div);
  chatFeed.scrollTop = chatFeed.scrollHeight;
}

function resetChatFeed() {
  chatFeed.innerHTML = `
    <div class="chat-empty">
      <div class="empty-icon"></div>
      <div class="empty-title">AI 에이전트 대기 중</div>
      <div class="empty-sub">위 시나리오 버튼을 클릭해 시뮬레이션을 시작하세요.</div>
    </div>`;
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('running'));
  if (runAbort) { runAbort.abort(); runAbort = null; }
}

// ── Logs ───────────────────────────────────────────────────────────
function logClass(result) {
  if (!result) return 'l-system';
  const r = result.toLowerCase();
  if (r.includes('허용')) return 'l-allow';
  if (r.includes('차단') || r.includes('노출')) return 'l-block';
  if (r.includes('승인')) return 'l-approve';
  return 'l-system';
}
function badgeClass(result) {
  if (!result) return 'b-system';
  const r = result.toLowerCase();
  if (r.includes('허용')) return 'b-allow';
  if (r.includes('차단') || r.includes('노출')) return 'b-block';
  if (r.includes('승인')) return 'b-approve';
  return 'b-system';
}

function buildLogEl(entry) {
  const lc = logClass(entry.result);
  const bc = badgeClass(entry.result);
  const hasMask = entry.masking && entry.masking.length > 0;
  const maskTypes = hasMask ? [...new Set(entry.masking.map(m => m.type))].join(', ') : '';
  const msTag = entry.time_ms != null ? `<span class="log-ms">${entry.time_ms}ms</span>` : '';

  const div = document.createElement('div');
  div.className = `log-entry ${lc}`;
  div.innerHTML = `
    <div class="log-top">
      <span class="log-ts">${entry.timestamp}</span>
      <span class="log-desc">${entry.description}</span>
      ${msTag}
      <span class="log-badge ${bc}">${entry.result}</span>
    </div>
    ${entry.data ? `<div class="log-data">${entry.data}</div>` : ''}
    ${hasMask ? `<span class="log-mask-tag">마스킹: ${maskTypes}</span>` : ''}
    <div class="log-detail">
      <div><strong>행동 유형:</strong> ${entry.action_type}</div>
      <div><strong>위험도:</strong> ${{ low: '낮음', medium: '중간', high: '높음' }[entry.risk_level] || '—'}</div>
      ${entry.time_ms != null ? `<div><strong>처리 시간:</strong> ${entry.time_ms}ms</div>` : ''}
      ${entry.data ? `<div><strong>데이터:</strong> ${entry.data}</div>` : ''}
      ${hasMask ? `<div><strong>마스킹 상세:</strong> ${entry.masking.map(m => m.type).join(', ')}</div>` : ''}
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
    if (r.includes('차단') || r.includes('노출')) cnt.block++;
    if (e.masking && e.masking.length) cnt.mask++;
  });
  $('cnt-allow').textContent = cnt.allow;
  $('cnt-block').textContent = cnt.block;
  $('cnt-mask').textContent  = cnt.mask;
}

// ── Approval modal ─────────────────────────────────────────────────
function showApprovalModal(ap) {
  const resourceLabels = { gmail: 'Gmail', calendar: '캘린더', file: '파일', messenger: '메신저', external: '외부 서버', bank: '금융 서비스' };
  const actionLabels   = { read: '읽기', send: '전송', upload: '업로드', payment: '결제' };

  modalContent.innerHTML = `
    <div class="modal-row"><span class="m-label">요청 작업</span><span class="m-value">${actionLabels[ap.action_type] || ap.action_type}</span></div>
    <div class="modal-row"><span class="m-label">대상 서비스</span><span class="m-value">${resourceLabels[ap.resource] || ap.resource}</span></div>
    ${ap.destination ? `<div class="modal-row"><span class="m-label">전송 주소</span><span class="m-value code">${ap.destination}</span></div>` : ''}
    ${ap.data ? `<div class="modal-row"><span class="m-label">데이터 미리보기</span><span class="m-value">${ap.data.slice(0,120)}${ap.data.length>120?'…':''}</span></div>` : ''}
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

// ── Benchmark ──────────────────────────────────────────────────────
async function runBenchmark() {
  const btn = $('btn-benchmark');
  btn.textContent = '실행 중...';
  btn.disabled = true;
  try {
    const data = await apiFetch('POST', '/api/benchmark');
    renderBenchmarkModal(data);
    benchBackdrop.classList.add('open');
  } finally {
    btn.textContent = '벤치마크 실행';
    btn.disabled = false;
  }
}

function renderBenchmarkModal(d) {
  const outcomeColor = { TP: 'tp', FP: 'fp', TN: 'tn', FN: 'fn' };
  const outcomeLabel = { TP: '정탐', FP: '오탐', TN: '정상', FN: '미탐' };

  const summary = `
    <div class="bench-summary">
      <div class="bench-stat">
        <div class="bench-val" style="color:var(--green)">${d.recall}%</div>
        <div class="bench-lbl">탐지율 (Recall)</div>
      </div>
      <div class="bench-stat">
        <div class="bench-val" style="color:var(--blue)">${d.precision}%</div>
        <div class="bench-lbl">정밀도 (Precision)</div>
      </div>
      <div class="bench-stat">
        <div class="bench-val" style="color:var(--purple)">${d.f1_score}%</div>
        <div class="bench-lbl">F1 Score</div>
      </div>
      <div class="bench-stat">
        <div class="bench-val" style="color:${d.false_positive_rate > 0 ? 'var(--red)' : 'var(--green)'}">${d.false_positive_rate}%</div>
        <div class="bench-lbl">오탐률 (FPR)</div>
      </div>
      <div class="bench-stat">
        <div class="bench-val" style="color:var(--text)">${d.avg_time_ms}ms</div>
        <div class="bench-lbl">평균 처리 시간</div>
      </div>
    </div>
    <div class="bench-meta">
      전체 ${d.total}건 · 정탐(TP) ${d.tp} · 미탐(FN) ${d.fn} · 정상(TN) ${d.tn} · 오탐(FP) ${d.fp}
      &nbsp;|&nbsp; 최대 처리 시간 ${d.max_time_ms}ms
    </div>`;

  const rows = d.results.map(r => `
    <tr>
      <td class="bench-text" title="${r.text}">${r.text.length > 28 ? r.text.slice(0,28)+'…' : r.text}</td>
      <td>${r.expected_label || '없음'}</td>
      <td>${r.detected ? r.found_types.join(', ') : '—'}</td>
      <td class="outcome-${outcomeColor[r.outcome]}">${outcomeLabel[r.outcome]}</td>
      <td class="bench-time">${r.time_ms}ms</td>
    </tr>`).join('');

  benchContent.innerHTML = summary + `
    <div class="bench-table-wrap">
      <table class="bench-table">
        <thead>
          <tr><th>입력 텍스트</th><th>기대 유형</th><th>탐지 결과</th><th>판정</th><th>처리시간</th></tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ── Events ─────────────────────────────────────────────────────────
function wireEvents() {
  // Sensitivity preset buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const preset = btn.dataset.preset;
      await apiFetch('POST', '/api/sensitivity-preset', { preset });
      applySensitivityUI(preset);
    });
  });

  // Guard ON/OFF toggle
  guardToggle.addEventListener('change', () => {
    applyGuardUI(guardToggle.checked);
  });

  $('btn-clear').addEventListener('click', async () => {
    await Promise.all([apiFetch('DELETE', '/api/logs'), apiFetch('DELETE', '/api/metrics')]);
    logFeed.innerHTML = '<div class="log-empty">로그가 초기화되었습니다.</div>';
    resetChatFeed();
    knownLogCount = 0;
    state.logs = [];
    cnt.allow = cnt.block = cnt.mask = cnt.pending = 0;
    ['allow','block','mask','pending'].forEach(k => $(`cnt-${k}`).textContent = '0');
    ['m-avg-ms','m-block-rate','m-mask-rate','m-inject-rate'].forEach(id => $(id).textContent = '—');
  });

  $('btn-benchmark').addEventListener('click', runBenchmark);

  $('btn-bench-close').addEventListener('click', () => benchBackdrop.classList.remove('open'));
  benchBackdrop.addEventListener('click', e => {
    if (e.target === benchBackdrop) benchBackdrop.classList.remove('open');
  });

  backdrop.addEventListener('click', e => {
    if (e.target === backdrop) backdrop.classList.remove('open');
  });
}

// ── Util ───────────────────────────────────────────────────────────
const sleep = ms => new Promise(r => setTimeout(r, ms));
