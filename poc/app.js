'use strict';

// ── DOM ────────────────────────────────────────────────────────────
const userInput    = document.getElementById('user-input');
const btnExample   = document.getElementById('btn-example');
const btnRun       = document.getElementById('btn-run');
const btnReset     = document.getElementById('btn-reset');
const inputArea    = document.getElementById('input-area');
const requestBubble = document.getElementById('request-bubble');
const agentStatus  = document.getElementById('agent-status');
const cardEmail    = document.getElementById('card-email');
const injectionBox = document.getElementById('injection-box');
const gateIdle     = document.getElementById('gate-idle');
const gateScanning = document.getElementById('gate-scanning');
const gateChecks   = document.getElementById('gate-checks');
const gateResult   = document.getElementById('gate-result');
const gateCard     = document.getElementById('card-gate');
const logList      = document.getElementById('log-list');
const alertCard    = document.getElementById('alert-card');
const dashStats    = document.getElementById('dash-stats');
const resetBar     = document.getElementById('reset-bar');

// ── Stats ──────────────────────────────────────────────────────────
let stats = { allow: 0, block: 0, mask: 0 };

// ── Events ─────────────────────────────────────────────────────────
btnExample.addEventListener('click', () => {
  userInput.value = '최근 이메일을 요약하고 오늘 해야 할 일을 정리해줘.';
  btnRun.disabled = false;
  userInput.focus();
});

userInput.addEventListener('input', () => {
  btnRun.disabled = userInput.value.trim().length === 0;
});

btnRun.addEventListener('click', () => {
  if (!userInput.value.trim()) return;
  runDemo();
});

btnReset.addEventListener('click', () => location.reload());

// ── Step indicator ─────────────────────────────────────────────────
function setStep(n) {
  for (let i = 1; i <= 4; i++) {
    const dot  = document.getElementById(`dot${i}`);
    const line = document.getElementById(`line${i}`);
    dot.classList.remove('active', 'done', 'blocked');
    if (i < n)  dot.classList.add(n === 4 ? 'blocked' : 'done');
    if (i === n) dot.classList.add(n === 4 ? 'blocked' : 'active');
    if (line) {
      line.classList.remove('done', 'active');
      if (i < n) line.classList.add('done');
    }
  }
}

// ── Main demo sequence ─────────────────────────────────────────────
async function runDemo() {
  btnRun.disabled = true;
  btnExample.disabled = true;
  userInput.disabled = true;

  // ── Step 1: show request ──────────────────────────────────────
  setStep(1);
  inputArea.style.display = 'none';
  requestBubble.style.display = 'block';
  agentStatus.style.display   = 'flex';

  await sleep(1200);

  // ── Step 2: show email ────────────────────────────────────────
  setStep(2);
  agentStatus.style.display = 'none';
  cardEmail.classList.add('visible');

  await sleep(1400);

  // Reveal hidden injection
  injectionBox.classList.add('reveal');

  await sleep(1800);

  // ── Step 3: gate scanning ─────────────────────────────────────
  setStep(3);
  gateCard.classList.add('scanning');
  gateIdle.style.display    = 'none';
  gateScanning.style.display = 'block';

  await sleep(900);
  gateScanning.style.display = 'none';

  // Check cards one by one
  const checks = [
    {
      icon: '🌐',
      name: '외부 전송 시도 감지',
      value: 'external-site.com 으로의 데이터 전송 요청 탐지',
      cls: 'danger',
      badge: '감지됨',
      badgeCls: 'badge-danger',
    },
    {
      icon: '📞',
      name: '민감정보 탐지 — 전화번호',
      value: '010-1234-5678',
      cls: 'danger',
      badge: '탐지됨',
      badgeCls: 'badge-danger',
    },
    {
      icon: '🏦',
      name: '민감정보 탐지 — 계좌번호',
      value: '123-456-789012',
      cls: 'danger',
      badge: '탐지됨',
      badgeCls: 'badge-danger',
    },
    {
      icon: '🔎',
      name: '도메인 신뢰도 확인',
      value: 'external-site.com — 신뢰되지 않은 도메인',
      cls: 'danger',
      badge: '미신뢰',
      badgeCls: 'badge-danger',
    },
    {
      icon: '📋',
      name: '정책 판단',
      value: '외부 전송 차단 정책 적용 → 전송 거부',
      cls: 'block',
      badge: 'BLOCKED',
      badgeCls: 'badge-blocked',
    },
  ];

  for (const check of checks) {
    await sleep(620);
    addCheckCard(check);
  }

  await sleep(500);

  // Show BLOCKED
  gateCard.classList.remove('scanning');
  gateCard.classList.add('blocked');
  gateResult.style.display = 'block';

  // ── Step 4: dashboard ─────────────────────────────────────────
  await sleep(700);
  setStep(4);

  const now = new Date();
  const t = (delta = 0) => {
    const d = new Date(now.getTime() - delta * 1000);
    return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}:${String(d.getSeconds()).padStart(2,'0')}`;
  };

  const logs = [
    { time: t(5), icon: '✅', text: '이메일 읽기 허용', cls: 'l-allow',  statKey: 'allow' },
    { time: t(4), icon: '⚠️', text: '숨겨진 명령 탐지 — 간접 프롬프트 인젝션', cls: 'l-warn',   statKey: null },
    { time: t(3), icon: '🚨', text: '외부 전송 시도 감지 → external-site.com', cls: 'l-danger', statKey: 'block' },
    { time: t(2), icon: '🔒', text: '민감정보 마스킹 — 전화번호 010-****-5678', cls: 'l-danger', statKey: 'mask' },
    { time: t(1), icon: '🔒', text: '민감정보 마스킹 — 계좌번호 ***-***-******', cls: 'l-danger', statKey: 'mask' },
    { time: t(0), icon: '🚫', text: 'external-site.com 전송 차단 완료', cls: 'l-block', statKey: null },
  ];

  // Show stat pills
  dashStats.style.display = 'flex';
  const logEmpty = logList.querySelector('.log-empty');
  if (logEmpty) logEmpty.remove();

  for (const log of logs) {
    await sleep(380);
    addLogEntry(log);
    if (log.statKey) {
      stats[log.statKey]++;
      updateStats();
    }
  }

  await sleep(600);
  alertCard.style.display = 'block';
  resetBar.style.display  = 'block';
}

// ── Helpers ────────────────────────────────────────────────────────
function addCheckCard({ icon, name, value, cls, badge, badgeCls }) {
  const div = document.createElement('div');
  div.className = `check-card ${cls}`;
  div.innerHTML = `
    <span class="check-icon">${icon}</span>
    <div class="check-body">
      <div class="check-name">${name}</div>
      <div class="check-value">${value}</div>
    </div>
    <span class="check-badge ${badgeCls}">${badge}</span>`;
  gateChecks.appendChild(div);
  // Trigger animation
  requestAnimationFrame(() => requestAnimationFrame(() => div.classList.add('visible')));
}

function addLogEntry({ time, icon, text, cls }) {
  const div = document.createElement('div');
  div.className = `log-entry ${cls}`;
  div.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-icon">${icon}</span>
    <span class="log-text">${text}</span>`;
  logList.appendChild(div);
  requestAnimationFrame(() => requestAnimationFrame(() => div.classList.add('visible')));
  logList.scrollTop = logList.scrollHeight;
}

function updateStats() {
  document.getElementById('stat-allow').textContent = `허용 ${stats.allow}`;
  document.getElementById('stat-block').textContent = `차단 ${stats.block}`;
  document.getElementById('stat-mask').textContent  = `마스킹 ${stats.mask}`;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
