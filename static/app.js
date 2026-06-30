let lastPayload = null;
let lastReport = null;
let currentJobTimer = null;

const $ = (id) => document.getElementById(id);
const splitCSV = (value) => value.split(',').map(v => v.trim()).filter(Boolean);

const SMART_DEFAULTS = {
  phishing_bec: {
    severity: 'medium',
    environment: 'Microsoft 365 / enterprise email environment',
    analyst: 'SOC L1 Phishing Triage',
    assets: 'user@company.com, Finance mailbox, M365 tenant',
    indicators: 'suspicious email, malicious URL, user clicked link, fake login page, impossible travel',
    notes: 'User reported a suspicious email. Message headers, URL reputation, and login activity need validation before account containment.'
  },
  ransomware: {
    severity: 'critical',
    environment: 'Windows enterprise / file server segment',
    analyst: 'Incident Commander',
    assets: 'WIN-FILE-01, HR-SHARE, Backup-Repository-01',
    indicators: 'ransom note, active encryption, mass file modification, EDR process tree, suspicious admin logon, VSSAdmin delete shadows',
    notes: 'EDR observed mass file encryption and ransom note creation on a file server. There is suspicious admin logon activity and possible backup deletion attempts.'
  },
  credential_compromise: {
    severity: 'high',
    environment: 'Identity provider / VPN / cloud SSO environment',
    analyst: 'SOC L2 Identity Triage',
    assets: 'user@company.com, Okta account, VPN session',
    indicators: 'impossible travel, MFA fatigue, suspicious successful login, new device, abnormal geolocation',
    notes: 'Identity logs show suspicious access from an unusual location. Validate whether the user approved MFA and whether sessions or OAuth grants are active.'
  },
  endpoint_malware: {
    severity: 'high',
    environment: 'Enterprise endpoint / EDR-monitored workstation fleet',
    analyst: 'SOC L2 Endpoint Triage',
    assets: 'WIN-WKS-044, user workstation, EDR sensor',
    indicators: 'malware execution, suspicious process tree, C2 connection, unsigned binary, persistence attempt',
    notes: 'EDR detected suspicious process execution and outbound network traffic. Confirm parent process, hash reputation, persistence, and credential theft behavior.'
  },
  cloud_iam_abuse: {
    severity: 'high',
    environment: 'AWS production / hybrid cloud environment',
    analyst: 'SOC L2 Cloud Triage',
    assets: 'AWS-Prod, IAM-user-backupsvc, S3-customer-records',
    indicators: 'CloudTrail CreateAccessKey, AttachUserPolicy, unknown source IP 185.220.101.22, abnormal user-agent, S3 ListBuckets',
    notes: 'GuardDuty alerted on anomalous IAM activity. User created a new access key and attached a risky policy from a suspicious IP with no approved change ticket.'
  },
  data_exfiltration: {
    severity: 'high',
    environment: 'Enterprise network / cloud storage / DLP-monitored data environment',
    analyst: 'SOC L2 Data Protection Triage',
    assets: 'Finance Share, S3-customer-records, user@company.com',
    indicators: 'large outbound transfer, DLP alert, untrusted destination, public link created, sensitive data path',
    notes: 'DLP/CASB telemetry shows unusual data movement. Validate data classification, destination, user intent, and whether downloads or external shares occurred.'
  },
  web_attack: {
    severity: 'high',
    environment: 'Public web application / WAF-protected production environment',
    analyst: 'AppSec / SOC Triage',
    assets: 'prod-web-app, login API, WAF policy',
    indicators: 'WAF alert, exploit pattern, affected route, HTTP 500 spike, suspicious user-agent',
    notes: 'WAF logs show exploit-like requests against a production route. Confirm exploitation success, app errors, web shell indicators, and false-positive risk.'
  },
  lateral_movement: {
    severity: 'high',
    environment: 'Internal Windows domain / enterprise network segment',
    analyst: 'SOC L2 Network Triage',
    assets: 'WIN-WKS-044, DC-01, APP-SERVER-02',
    indicators: 'SMB anomaly, remote service creation, admin share access, suspicious logon type, WinRM activity',
    notes: 'Internal telemetry shows host-to-host movement patterns. Validate source host, destination host, account used, protocol, and active attacker session risk.'
  },
  insider_threat: {
    severity: 'high',
    environment: 'Enterprise SaaS / file sharing / DLP-monitored environment',
    analyst: 'Insider Risk / SOC Triage',
    assets: 'user@company.com, HR documents, external share link',
    indicators: 'DLP alert, external share, unusual file access, sensitive data, no approved business need',
    notes: 'User activity shows unusual access and sharing behavior. Preserve evidence carefully and coordinate with data owner, legal, HR, and insider-risk process.'
  },
  vulnerability_exploitation: {
    severity: 'high',
    environment: 'Internet-facing application / vulnerable service environment',
    analyst: 'Vulnerability Response / SOC Triage',
    assets: 'internet-facing-service, affected endpoint, WAF rule',
    indicators: 'CVE exploit pattern, vulnerable version, active exploitation, exploit payload, affected endpoint',
    notes: 'Security telemetry suggests exploitation of a known CVE. Validate affected version, exploit success, compensating controls, and business impact before exposure changes.'
  }
};

const KNOWN_DEFAULT_VALUES = new Set(Object.values(SMART_DEFAULTS).flatMap(d => [d.environment, d.analyst, d.assets, d.indicators, d.notes]));

function fieldCanBeReplaced(value) {
  const trimmed = String(value || '').trim();
  return !trimmed || trimmed === 'hybrid enterprise' || trimmed === 'SOC Analyst' || KNOWN_DEFAULT_VALUES.has(trimmed);
}

function applyIncidentDefaults(force = false) {
  const defaults = SMART_DEFAULTS[$('incidentType').value];
  if (!defaults) return;
  if (force || fieldCanBeReplaced($('severity').value)) $('severity').value = defaults.severity;
  if (force || fieldCanBeReplaced($('environment').value)) $('environment').value = defaults.environment;
  if (force || fieldCanBeReplaced($('analyst').value)) $('analyst').value = defaults.analyst;
  if (force || fieldCanBeReplaced($('assets').value)) $('assets').value = defaults.assets;
  if (force || fieldCanBeReplaced($('indicators').value)) $('indicators').value = defaults.indicators;
  if (force || fieldCanBeReplaced($('notes').value)) $('notes').value = defaults.notes;
}


function escapeHtml(text) {
  return String(text).replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
}

async function loadTypes() {
  const res = await fetch('/api/incident-types');
  const types = await res.json();
  $('incidentType').innerHTML = types.map(t => `<option value="${t.id}">${escapeHtml(t.title)}</option>`).join('');
}

function fillList(id, items) {
  const el = $(id);
  el.innerHTML = items.map(item => `<li>${escapeHtml(item)}</li>`).join('');
}

function showToast(message) {
  $('toast').textContent = message;
  $('toast').classList.add('show');
  setTimeout(() => $('toast').classList.remove('show'), 1800);
}

function renderStoryline(items) {
  $('storyline').innerHTML = items.map((item, idx) => {
    const arrow = idx < items.length - 1 ? '<span class="arrow">→</span>' : '';
    return `<span class="node" style="animation-delay:${idx * 0.05}s">${escapeHtml(item)}</span>${arrow}`;
  }).join('');
}

function renderTimeline(items) {
  $('timeline').innerHTML = items.map((p, idx) => `
    <div class="phase" style="animation-delay:${idx * 0.06}s">
      <strong>${escapeHtml(p.phase)}</strong>
      <p>${escapeHtml(p.goal)}</p>
    </div>
  `).join('');
}

function renderGates(gates) {
  $('gates').innerHTML = gates.map((gate, idx) => {
    const pct = Math.round(gate.evidence_confidence * 100);
    const missing = gate.missing_evidence?.length ? gate.missing_evidence.join('; ') : 'None';
    const verified = gate.verified_evidence?.length ? gate.verified_evidence.join('; ') : 'None yet';
    return `
      <div class="gate" style="animation-delay:${idx * 0.06}s">
        <div class="gate-head">
          <h4>${escapeHtml(gate.action)}</h4>
          <span class="badge ${escapeHtml(gate.approval_level)}">${escapeHtml(gate.approval_level)}</span>
        </div>
        <p><strong>Status:</strong> ${escapeHtml(gate.status)}</p>
        <div class="confbar"><span style="width:${pct}%"></span></div>
        <small><strong>Evidence confidence:</strong> ${pct}%</small>
        <small><strong>Verified:</strong> ${escapeHtml(verified)}</small>
        <small><strong>Missing:</strong> ${escapeHtml(missing)}</small>
        <p><strong>Risk if wrong:</strong> ${escapeHtml(gate.risk_if_wrong)}</p>
        <p><strong>Rollback:</strong> ${escapeHtml(gate.rollback)}</p>
      </div>
    `;
  }).join('');
}

function renderApproval(matrix) {
  const labels = ['Green', 'Yellow', 'Red'];
  $('approval').innerHTML = labels.map(label => {
    const actions = matrix[label] || [];
    const text = actions.length ? actions.join(' | ') : 'No action in this category';
    return `<div class="approval-row"><strong>${label}</strong><p>${escapeHtml(text)}</p></div>`;
  }).join('');
}

function renderArchTrace(trace) {
  $('archTrace').innerHTML = Object.entries(trace || {}).map(([k, v]) =>
    `<li><strong>${escapeHtml(k.replaceAll('_', ' '))}:</strong> ${escapeHtml(v)}</li>`
  ).join('');
}

function renderGraph(graph) {
  const nodes = (graph?.nodes || []).slice(0, 32);
  const edges = (graph?.edges || []).slice(0, 50);
  if (!nodes.length) {
    $('graph').innerHTML = '<p>No graph generated.</p>';
    return;
  }
  const width = 980, height = 560, cx = width / 2, cy = height / 2;
  const nodeMap = new Map();
  nodes.forEach((n, idx) => {
    const radius = idx === 0 ? 0 : 120 + (idx % 3) * 35;
    const angle = idx === 0 ? 0 : (Math.PI * 2 * (idx - 1)) / Math.max(1, nodes.length - 1);
    const x = idx === 0 ? cx : cx + Math.cos(angle) * radius;
    const y = idx === 0 ? cy : cy + Math.sin(angle) * radius;
    nodeMap.set(n.id, { ...n, x, y });
  });
  const edgeSvg = edges.map(e => {
    const s = nodeMap.get(e.source), t = nodeMap.get(e.target);
    if (!s || !t) return '';
    return `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" class="graph-edge"><title>${escapeHtml(e.relationship)}</title></line>`;
  }).join('');
  const nodeSvg = [...nodeMap.values()].map((n, idx) => {
    const label = n.label.length > 26 ? n.label.slice(0, 24) + '…' : n.label;
    return `<g class="graph-node ${escapeHtml(n.type)}" style="animation-delay:${idx * .025}s">
      <circle cx="${n.x}" cy="${n.y}" r="${idx === 0 ? 34 : 24}"></circle>
      <text x="${n.x}" y="${n.y + 46}" text-anchor="middle">${escapeHtml(label)}</text>
      <title>${escapeHtml(n.type)}: ${escapeHtml(n.label)}</title>
    </g>`;
  }).join('');
  $('graph').innerHTML = `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Evidence graph">${edgeSvg}${nodeSvg}</svg>`;
}

function renderReport(data) {
  lastReport = data;
  $('output').classList.remove('hidden');
  $('outputTitle').textContent = `${data.case_id ? `Case #${data.case_id} • ` : ''}${data.incident_type}`;
  $('brief').textContent = data.case_summary.commander_brief;
  $('severityPill').textContent = data.severity;

  const scorePct = Math.round(data.playbook_confidence_score * 1000) / 10;
  $('scoreLabel').textContent = `${scorePct}%`;
  $('ringScore').textContent = Math.round(data.playbook_confidence_score * 100);
  document.querySelector('.ring').style.background = `conic-gradient(var(--accent) 0 ${Math.round(data.playbook_confidence_score * 100)}%, rgba(255,255,255,.1) ${Math.round(data.playbook_confidence_score * 100)}% 100%)`;

  const sev = data.severity.toLowerCase();
  const pill = $('severityPill');
  pill.style.color = sev === 'critical' ? 'var(--danger)' : sev === 'high' ? 'var(--warn)' : 'var(--ok)';

  renderStoryline(data.attack_storyline);
  renderTimeline(data.soar_timeline);
  renderGates(data.evidence_gated_actions);
  renderApproval(data.approval_matrix);
  renderArchTrace(data.architecture_trace);
  renderGraph(data.evidence_graph);

  fillList('investigation', data.investigation_checklist);
  fillList('containment', data.containment_plan);
  fillList('evidence', data.evidence_list);
  fillList('priority', data.priority_actions);
  fillList('assurance', data.assurance_checks);
  $('escalation').textContent = data.escalation_summary;
  $('mitre').innerHTML = data.mitre_tactics.map(t => `<span class="chip">${escapeHtml(t)}</span>`).join('');

  loadHistory();
  window.scrollTo({ top: $('output').offsetTop - 20, behavior: 'smooth' });
}

async function generate(payload) {
  lastPayload = payload;
  const res = await fetch('/api/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Could not generate playbook');
  renderReport(await res.json());
}

async function runAsyncJob(payload) {
  lastPayload = payload;
  const res = await fetch('/api/jobs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Could not submit async job');
  const job = await res.json();
  showToast(`SOAR job queued: ${job.job_id.slice(0, 8)}`);
  if (currentJobTimer) clearInterval(currentJobTimer);
  currentJobTimer = setInterval(async () => {
    const statusRes = await fetch(job.status_url);
    const status = await statusRes.json();
    if (status.status === 'completed') {
      clearInterval(currentJobTimer);
      showToast('Async SOAR job completed');
      renderReport(status.result);
    } else if (status.status === 'failed') {
      clearInterval(currentJobTimer);
      showToast(`Job failed: ${status.error}`);
    }
  }, 600);
}

function formPayload() {
  return {
    incident_type: $('incidentType').value,
    severity: $('severity').value,
    environment: $('environment').value || 'enterprise',
    analyst: $('analyst').value || 'SOC Analyst',
    affected_assets: splitCSV($('assets').value),
    indicators: splitCSV($('indicators').value),
    notes: $('notes').value,
    save_case: true
  };
}

async function loadHistory() {
  try {
    const res = await fetch('/api/cases?limit=10');
    const items = await res.json();
    $('history').innerHTML = items.length ? items.map(c => `
      <button class="history-item" data-case-id="${c.id}">
        <strong>#${c.id} ${escapeHtml(c.incident_type)}</strong>
        <span>${escapeHtml(c.severity)} • ${escapeHtml(c.environment)} • ${Math.round(c.confidence_score * 100)}%</span>
      </button>
    `).join('') : '<p>No stored cases yet. Generate a commander plan first.</p>';
    document.querySelectorAll('[data-case-id]').forEach(btn => btn.addEventListener('click', async () => {
      const detail = await fetch(`/api/cases/${btn.dataset.caseId}`).then(r => r.json());
      renderReport(detail);
    }));
  } catch (_) {
    $('history').innerHTML = '<p>History unavailable.</p>';
  }
}

async function searchHistory() {
  const q = $('searchInput').value;
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}&limit=10`);
  const items = await res.json();
  $('history').innerHTML = items.length ? items.map(c => `
    <div class="history-card">
      <strong>${escapeHtml(c.incident_type || 'Incident')}</strong>
      <span>${escapeHtml(c.severity || '')} • ${escapeHtml(c.environment || '')}</span>
      <p>${escapeHtml(c.summary || '')}</p>
    </div>
  `).join('') : '<p>No matching indexed cases found.</p>';
}

$('incidentForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  try { await generate(formPayload()); } catch (err) { showToast(err.message); }
});

$('asyncBtn').addEventListener('click', async () => {
  try { await runAsyncJob(formPayload()); } catch (err) { showToast(err.message); }
});

$('demoBtn').addEventListener('click', async () => {
  $('incidentType').value = 'cloud_iam_abuse';
  applyIncidentDefaults(true);
  await generate(formPayload());
});

$('ransomBtn').addEventListener('click', async () => {
  $('incidentType').value = 'ransomware';
  applyIncidentDefaults(true);
  await generate(formPayload());
});

$('copyBtn').addEventListener('click', async () => {
  if (!lastReport) return showToast('Generate a report first');
  await navigator.clipboard.writeText(JSON.stringify(lastReport, null, 2));
  showToast('Copied report JSON');
});

$('mdBtn').addEventListener('click', async () => {
  if (!lastPayload) return showToast('Generate a report first');
  const res = await fetch('/api/report/markdown', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(lastPayload)
  });
  const data = await res.json();
  await navigator.clipboard.writeText(data.markdown);
  showToast('Copied Markdown report');
});

$('historyBtn').addEventListener('click', loadHistory);
$('searchBtn').addEventListener('click', searchHistory);
$('incidentType').addEventListener('change', () => applyIncidentDefaults(false));


function animateParticles() {
  const canvas = $('particles');
  const ctx = canvas.getContext('2d');
  let w, h, particles;
  function resize() {
    w = canvas.width = innerWidth;
    h = canvas.height = innerHeight;
    particles = Array.from({ length: Math.min(120, Math.floor(w / 13)) }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      vx: (Math.random() - .5) * .45,
      vy: (Math.random() - .5) * .45,
      r: Math.random() * 1.8 + .5
    }));
  }
  function tick() {
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = 'rgba(0,245,255,.7)';
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0 || p.x > w) p.vx *= -1;
      if (p.y < 0 || p.y > h) p.vy *= -1;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2); ctx.fill();
    });
    ctx.strokeStyle = 'rgba(157,78,221,.12)';
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i], b = particles[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < 120) {
          ctx.globalAlpha = 1 - d / 120;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          ctx.globalAlpha = 1;
        }
      }
    }
    requestAnimationFrame(tick);
  }
  addEventListener('resize', resize);
  resize(); tick();
}

loadTypes();
loadHistory();
animateParticles();
