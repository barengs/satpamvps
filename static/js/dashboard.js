/**
 * VPS Sentinel — Dashboard JavaScript
 * Socket.IO client + Chart.js real-time charts
 */

/* ─── Socket.IO ──────────────────────────────────────── */
const socket = io();
const MAX_ROWS = 200;
const CHART_POINTS = 20;

/* ─── State ──────────────────────────────────────────── */
let allEvents = [];
let attackLabels = [];
let attackCounts = [];
let netInData    = new Array(CHART_POINTS).fill(0);
let netOutData   = new Array(CHART_POINTS).fill(0);
let netLabels    = new Array(CHART_POINTS).fill('');

/* ─── Charts setup ───────────────────────────────────── */
const attackCtx  = document.getElementById('attackChart').getContext('2d');
const typeCtx    = document.getElementById('typeChart').getContext('2d');
const networkCtx = document.getElementById('networkChart').getContext('2d');

const gradBlue = attackCtx.createLinearGradient(0, 0, 0, 200);
gradBlue.addColorStop(0, 'rgba(59,130,246,0.5)');
gradBlue.addColorStop(1, 'rgba(59,130,246,0)');

const attackChart = new Chart(attackCtx, {
  type: 'line',
  data: {
    labels: new Array(CHART_POINTS).fill(''),
    datasets: [{
      label: 'Serangan/menit',
      data: new Array(CHART_POINTS).fill(0),
      borderColor: '#3b82f6',
      backgroundColor: gradBlue,
      borderWidth: 2,
      pointRadius: 3,
      pointBackgroundColor: '#3b82f6',
      tension: 0.4,
      fill: true,
    }]
  },
  options: {
    responsive: true,
    animation: { duration: 400 },
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 10 } }, grid: { color: 'rgba(99,179,237,0.06)' } },
      y: { ticks: { color: '#475569', font: { size: 10 } }, grid: { color: 'rgba(99,179,237,0.06)' }, beginAtZero: true, stepSize: 1 },
    }
  }
});

const typeColors = ['#3b82f6','#a855f7','#ef4444','#f59e0b','#10b981','#06b6d4','#ec4899','#8b5cf6','#f97316','#22c55e'];

const typeChart = new Chart(typeCtx, {
  type: 'doughnut',
  data: {
    labels: [],
    datasets: [{ data: [], backgroundColor: typeColors, borderWidth: 0 }]
  },
  options: {
    responsive: true,
    cutout: '65%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: { color: '#94a3b8', font: { size: 10 }, padding: 10, boxWidth: 10 }
      }
    }
  }
});

const gradGreen = networkCtx.createLinearGradient(0, 0, 0, 120);
gradGreen.addColorStop(0, 'rgba(16,185,129,0.4)');
gradGreen.addColorStop(1, 'rgba(16,185,129,0)');
const gradOrange = networkCtx.createLinearGradient(0, 0, 0, 120);
gradOrange.addColorStop(0, 'rgba(245,158,11,0.4)');
gradOrange.addColorStop(1, 'rgba(245,158,11,0)');

const networkChart = new Chart(networkCtx, {
  type: 'line',
  data: {
    labels: netLabels,
    datasets: [
      { label: 'IN (KB/s)',  data: netInData,  borderColor: '#10b981', backgroundColor: gradGreen,  borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0 },
      { label: 'OUT (KB/s)', data: netOutData, borderColor: '#f59e0b', backgroundColor: gradOrange, borderWidth: 1.5, tension: 0.4, fill: true, pointRadius: 0 },
    ]
  },
  options: {
    responsive: true,
    animation: { duration: 300 },
    plugins: {
      legend: { labels: { color: '#94a3b8', font: { size: 10 }, boxWidth: 12 } }
    },
    scales: {
      x: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(99,179,237,0.06)' } },
      y: { ticks: { color: '#475569', font: { size: 9 } }, grid: { color: 'rgba(99,179,237,0.06)' }, beginAtZero: true },
    }
  }
});

/* ─── Attack timeline buffer ─────────────────────────── */
let attackBuffer = 0;
setInterval(() => {
  const now = new Date();
  const label = `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;
  attackChart.data.labels.push(label);
  attackChart.data.datasets[0].data.push(attackBuffer);
  attackBuffer = 0;
  if (attackChart.data.labels.length > CHART_POINTS) {
    attackChart.data.labels.shift();
    attackChart.data.datasets[0].data.shift();
  }
  attackChart.update('none');
}, 5000);

/* ─── Socket Events ──────────────────────────────────── */
socket.on('connect', () => {
  setWsStatus(true);
});
socket.on('disconnect', () => {
  setWsStatus(false);
});

socket.on('initial_data', (data) => {
  // Load events
  allEvents = data.events || [];
  renderEventsTable();
  renderMiniTable();

  // Load blocked IPs
  renderBlockedTable(data.blocked_ips || []);

  // Stats
  updateStatCards(data.stats || {});

  // Type chart
  rebuildTypeChart(data.stats?.top_attacks || []);
});

socket.on('threat_event', (event) => {
  attackBuffer++;
  allEvents.unshift(event);
  if (allEvents.length > MAX_ROWS) allEvents.pop();

  renderEventsTable();
  renderMiniTable();
  showAlertPopup(event);

  // Refresh stats
  fetch('/api/stats').then(r => r.json()).then(data => {
    updateStatCards(data);
    rebuildTypeChart(data.top_attacks || []);
  });

  // Refresh blocked IPs if action was BLOCKED
  if (event.action === 'BLOCKED') {
    fetch('/api/blocked-ips').then(r => r.json()).then(renderBlockedTable);
  }
});

socket.on('system_metrics', updateSystemMetrics);

socket.on('ip_unblocked', ({ ip }) => {
  fetch('/api/blocked-ips').then(r => r.json()).then(renderBlockedTable);
  showToast(`✅ IP ${ip} telah di-unblock`);
});

socket.on('events_cleared', () => {
  allEvents = [];
  renderEventsTable();
  renderMiniTable();
});

/* ─── Render helpers ─────────────────────────────────── */
function severityBadge(s)  { return `<span class="badge badge-${s}">${s}</span>`; }
function actionBadge(a)    { return `<span class="badge badge-action-${a}">${a}</span>`; }

function renderEventsTable() {
  const filter = document.getElementById('filter-severity').value;
  const tbody  = document.getElementById('events-tbody');
  const rows   = filter ? allEvents.filter(e => e.severity === filter) : allEvents;
  tbody.innerHTML = rows.map((e, i) => `
    <tr class="${i === 0 ? 'new-row' : ''}">
      <td style="color:#475569">${e.id || i+1}</td>
      <td style="color:#94a3b8">${e.timestamp}</td>
      <td style="color:#f87171;font-weight:600">${e.ip}</td>
      <td>${e.country}</td>
      <td style="color:#e2e8f0">${e.attack_name}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;color:#64748b" title="${e.details}">${e.details}</td>
      <td>${severityBadge(e.severity)}</td>
      <td>${actionBadge(e.action)}</td>
    </tr>
  `).join('');
}

function renderMiniTable() {
  const tbody = document.getElementById('mini-tbody');
  tbody.innerHTML = allEvents.slice(0, 8).map((e, i) => `
    <tr class="${i === 0 ? 'new-row' : ''}">
      <td style="color:#94a3b8">${e.timestamp}</td>
      <td style="color:#f87171;font-weight:600">${e.ip}</td>
      <td>${e.country}</td>
      <td style="color:#e2e8f0">${e.attack_name}</td>
      <td>${severityBadge(e.severity)}</td>
      <td>${actionBadge(e.action)}</td>
    </tr>
  `).join('');
}

function renderBlockedTable(blocked) {
  document.getElementById('blocked-count').textContent = blocked.length;
  const tbody = document.getElementById('blocked-tbody');
  if (blocked.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:#475569;padding:2rem">Tidak ada IP yang diblokir</td></tr>`;
    return;
  }
  tbody.innerHTML = blocked.map(b => `
    <tr>
      <td style="color:#f87171;font-weight:600">${b.ip}</td>
      <td style="color:#94a3b8">${b.reason || '-'}</td>
      <td style="color:#64748b">${b.blocked_at}</td>
      <td style="color:#64748b">${b.unblock_at || 'Permanen'}</td>
      <td><button class="btn-unblock" onclick="unblockIP('${b.ip}')">Unblock</button></td>
    </tr>
  `).join('');
}

function updateStatCards(stats) {
  setText('stat-total',    stats.total_events  ?? 0);
  setText('stat-blocked',  stats.blocked_ips   ?? 0);
  setText('stat-critical', stats.critical_events ?? 0);
}

function rebuildTypeChart(topAttacks) {
  typeChart.data.labels   = topAttacks.map(a => a.attack_type);
  typeChart.data.datasets[0].data = topAttacks.map(a => a.cnt);
  typeChart.update();
}

/* ─── System Metrics ─────────────────────────────────── */
function updateSystemMetrics(m) {
  setText('stat-connections', m.active_connections);
  setText('sys-connections',  m.active_connections);
  setText('net-in',  `${m.net_in_kbps} KB/s`);
  setText('net-out', `${m.net_out_kbps} KB/s`);
  setText('ram-detail', `${m.ram_used_mb} / ${m.ram_total_mb} MB`);

  setGauge('cpu-fill', 'cpu-text', m.cpu_percent);
  setGauge('ram-fill', 'ram-text', m.ram_percent);
  setGauge('disk-fill', 'disk-text', m.disk_percent);

  // Network chart
  const now = new Date();
  const lbl = `${now.getHours().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;
  netInData.push(m.net_in_kbps);
  netOutData.push(m.net_out_kbps);
  netLabels.push(lbl);
  if (netInData.length > CHART_POINTS) {
    netInData.shift(); netOutData.shift(); netLabels.shift();
  }
  networkChart.update('none');
}

function setGauge(fillId, textId, pct) {
  const fill = document.getElementById(fillId);
  const text = document.getElementById(textId);
  if (fill) {
    fill.style.background = `conic-gradient(${gaugeColor(pct)} ${pct}%, transparent ${pct}%)`;
  }
  if (text) text.textContent = `${pct}%`;

  // Color parent gauge
  const gauge = fill?.parentElement;
  if (gauge) gauge.style.background = `conic-gradient(${gaugeColor(pct)} ${pct}%, #1e293b ${pct}%)`;
}

function gaugeColor(pct) {
  if (pct >= 85) return '#ef4444';
  if (pct >= 60) return '#f59e0b';
  return '#3b82f6';
}

/* ─── Actions ────────────────────────────────────────── */
function unblockIP(ip) {
  if (!confirm(`Unblock IP ${ip}?`)) return;
  fetch('/api/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip })
  });
}

function clearEvents() {
  if (!confirm('Hapus semua event dari database?')) return;
  fetch('/api/clear-events', { method: 'POST' });
}

function filterEvents() { renderEventsTable(); }

/* ─── Tabs ────────────────────────────────────────────── */
function switchTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  if (el) el.classList.add('active');
  document.getElementById('page-title').textContent = el?.textContent?.trim() || name;
  return false;
}

/* ─── WebSocket status ───────────────────────────────── */
function setWsStatus(connected) {
  const dot  = document.getElementById('ws-dot');
  const text = document.getElementById('ws-status');
  dot.className  = 'status-dot ' + (connected ? 'connected' : 'error');
  text.textContent = connected ? 'Terhubung' : 'Terputus';
}

/* ─── Alert Popup ────────────────────────────────────── */
function showAlertPopup(event) {
  if (event.severity === 'LOW') return;
  document.getElementById('alert-title').textContent  = `⚡ ${event.attack_name}`;
  document.getElementById('alert-detail').textContent = `${event.ip} (${event.country}) — ${event.action}`;
  const popup = document.getElementById('alert-popup');
  popup.classList.remove('hidden');
  clearTimeout(popup._timer);
  popup._timer = setTimeout(() => popup.classList.add('hidden'), 5000);
}

function showToast(msg) {
  document.getElementById('alert-title').textContent  = msg;
  document.getElementById('alert-detail').textContent = '';
  const popup = document.getElementById('alert-popup');
  popup.classList.remove('hidden');
  clearTimeout(popup._timer);
  popup._timer = setTimeout(() => popup.classList.add('hidden'), 3000);
}

/* ─── Utility ────────────────────────────────────────── */
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* ─── Clock ──────────────────────────────────────────── */
function updateClock() {
  const now = new Date();
  const s = now.toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', hour12: false });
  setText('current-time', s + ' WIB');
}
updateClock();
setInterval(updateClock, 1000);
