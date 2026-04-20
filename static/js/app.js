// ARISE SOAR - Frontend JavaScript
// Real-time WebSocket connection + UI utilities

const socket = io();

// ── WebSocket Status ──
socket.on('connect', () => {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (dot) { dot.classList.add('connected'); }
  if (text) { text.textContent = 'Connected'; }
  console.log('[ARISE] WebSocket connected');
});

socket.on('disconnect', () => {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (dot) { dot.classList.remove('connected'); }
  if (text) { text.textContent = 'Disconnected'; }
});

// ── Live Alert Feed ──
socket.on('new_alert', (alert) => {
  appendFeedEntry(alert);
  updateKPICount('totalAlerts', 1);
  if (alert.severity === 'CRITICAL') {
    updateKPICount('criticalAlerts', 1);
    showToast(`🚨 CRITICAL: ${alert.type} detected from ${alert.source}`, 'critical');
  } else if (alert.severity === 'HIGH') {
    showToast(`⚠️ HIGH: ${alert.type} from ${alert.source}`, 'high');
  }
});

socket.on('new_case', (caseData) => {
  updateKPICount('openCases', 1);
  showToast(`📁 New case created: ${caseData.title.substring(0, 40)}...`, 'info');
});

socket.on('alert_updated', (alert) => {
  if (alert.status === 'RESOLVED') {
    showToast(`✅ Alert resolved: ${alert.type}`, 'success');
  }
});

function appendFeedEntry(alert) {
  const feed = document.getElementById('liveFeed');
  if (!feed) return;

  const colors = { CRITICAL: '#fca5a5', HIGH: '#fdba74', MEDIUM: '#fde047', LOW: '#86efac' };
  const color = colors[alert.severity] || '#94a3b8';
  const time = new Date().toTimeString().split(' ')[0];

  const entry = document.createElement('div');
  entry.className = 'feed-entry';
  entry.innerHTML = `
    <span class="feed-time">${time}</span>
    <span class="feed-sev" style="color:${color}">[${alert.severity}]</span>
    <span class="feed-text">${alert.type} · ${alert.source} · ${alert.description?.substring(0, 60) || ''}...</span>
  `;
  feed.insertBefore(entry, feed.firstChild);

  // Keep feed manageable
  while (feed.children.length > 30) {
    feed.removeChild(feed.lastChild);
  }
}

function updateKPICount(id, delta) {
  const el = document.getElementById(id);
  if (el) {
    const current = parseInt(el.textContent) || 0;
    el.textContent = current + delta;
    el.style.transform = 'scale(1.15)';
    setTimeout(() => { el.style.transform = 'scale(1)'; }, 300);
  }
}

// ── Toast Notifications ──
let toastQueue = [];
let toastShowing = false;

function showToast(message, type = 'info') {
  toastQueue.push({ message, type });
  if (!toastShowing) processToastQueue();
}

function processToastQueue() {
  if (!toastQueue.length) { toastShowing = false; return; }
  toastShowing = true;

  const { message, type } = toastQueue.shift();
  const colors = {
    critical: '#ef4444', high: '#f97316', success: '#22c55e',
    info: '#3b82f6', warning: '#eab308'
  };
  const bgColors = {
    critical: 'rgba(239,68,68,0.15)', high: 'rgba(249,115,22,0.15)',
    success: 'rgba(34,197,94,0.15)', info: 'rgba(59,130,246,0.15)',
    warning: 'rgba(234,179,8,0.15)'
  };

  const toast = document.createElement('div');
  toast.style.cssText = `
    position:fixed; bottom:20px; right:20px; z-index:1000;
    background:${bgColors[type] || bgColors.info};
    border:1px solid ${colors[type] || colors.info};
    color:#f1f5f9; padding:12px 18px; border-radius:8px;
    font-size:13px; max-width:360px; box-shadow:0 4px 20px rgba(0,0,0,0.4);
    animation:slideIn 0.3s ease; backdrop-filter:blur(8px);
  `;
  toast.textContent = message;

  const style = document.createElement('style');
  style.textContent = `@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }`;
  document.head.appendChild(style);
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'fadeOut 0.3s ease forwards';
    toast.style.cssText += '@keyframes fadeOut { to { opacity:0; transform:translateX(20px); } }';
    setTimeout(() => {
      toast.remove();
      setTimeout(processToastQueue, 100);
    }, 300);
  }, 3500);
}

// ── Attack Simulator ──
function openSimulator() {
  const modal = document.getElementById('simulatorModal');
  if (modal) modal.style.display = 'flex';
}

function closeSimulator() {
  const modal = document.getElementById('simulatorModal');
  if (modal) modal.style.display = 'none';
}

function simulate(scenario) {
  fetch('/api/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scenario }),
  })
    .then(r => r.json())
    .then(data => {
      showToast(`🎯 Simulated: ${scenario.replace('_', ' ')} attack injected`, 'high');
      closeSimulator();
    })
    .catch(err => {
      // Fallback: directly create alert
      const scenarioMap = {
        phishing: { type: 'phishing', severity: 'HIGH', source: 'email_gateway', description: 'Simulated phishing campaign' },
        ransomware: { type: 'ransomware', severity: 'CRITICAL', source: 'edr_agent', description: 'Simulated ransomware detected' },
        brute_force: { type: 'brute_force', severity: 'HIGH', source: 'firewall', description: 'Simulated brute force attack' },
        data_exfil: { type: 'data_exfiltration', severity: 'CRITICAL', source: 'dlp', description: 'Simulated data exfiltration' },
        lateral_movement: { type: 'lateral_movement', severity: 'CRITICAL', source: 'siem', description: 'Simulated lateral movement' },
      };
      const payload = scenarioMap[scenario] || scenarioMap.phishing;
      return fetch('/api/alerts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      }).then(() => {
        showToast(`🎯 ${scenario} attack simulated`, 'high');
        closeSimulator();
      });
    });
}

// Close modal on backdrop click
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal')) {
    e.target.style.display = 'none';
  }
});
