// Scan page JavaScript
const API = '/api';

async function api(path, opts = {}) {
    const res = await fetch(API + path, opts);
    return res.json();
}

async function loadTargets() {
    const targets = await api('/targets');
    const list = document.getElementById('target-list');

    if (targets.length === 0) {
        list.innerHTML = '<p class="muted">No targets configured. <a href="/config">Add a target →</a></p>';
        return;
    }

    list.innerHTML = targets.map(t => `
        <div class="target-card">
            <div class="target-info">
                <h3>${t.name || t.id}</h3>
                <p>${t.target_url} • Auth: ${t.auth?.method || 'none'}</p>
            </div>
            <button class="btn btn-primary" onclick="startScan('${t.id}')">▶ Start Scan</button>
        </div>
    `).join('');
}

async function startScan(targetId) {
    try {
        const res = await api('/scan/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({target_id: targetId}),
        });
        if (res.error) {
            alert(res.error);
            return;
        }
        document.getElementById('scan-progress-section').style.display = 'block';
        document.getElementById('scan-running-msg').style.display = 'block';
        pollScanProgress();
    } catch (e) {
        alert('Failed to start scan: ' + e);
    }
}

async function pollScanProgress() {
    const data = await api('/scan/progress');
    const info = document.getElementById('scan-progress-info');
    const bar = document.getElementById('scan-progress-bar');
    const details = document.getElementById('scan-progress-details');

    if (data.running) {
        info.innerHTML = `
            <strong>Target:</strong> ${data.progress.target_name || '-'}<br>
            <strong>Phase:</strong> ${data.progress.phase || '-'}<br>
            <strong>Findings:</strong> ${data.progress.findings_count || 0}
        `;
        const phases = ['initializing', 'starting_browser', 'scanning', 'complete'];
        const idx = phases.indexOf(data.progress.status);
        bar.style.width = Math.max(10, ((idx + 1) / phases.length) * 100) + '%';

        setTimeout(pollScanProgress, 3000);
    } else if (data.progress?.status === 'complete') {
        info.innerHTML = `
            <strong>✅ Scan Complete!</strong><br>
            Findings: ${data.progress.findings_count || 0}<br>
            ${data.progress.stats ? `
                Critical: ${data.progress.stats.critical || 0} |
                High: ${data.progress.stats.high || 0} |
                Medium: ${data.progress.stats.medium || 0}
            ` : ''}
        `;
        bar.style.width = '100%';
        details.innerHTML = `<a class="btn btn-primary" href="/reports">View Reports →</a>`;
        document.getElementById('scan-running-msg').style.display = 'none';
    } else if (data.progress?.status === 'error') {
        info.innerHTML = `<strong>❌ Error:</strong> ${data.progress.error || 'Unknown'}`;
        bar.style.width = '100%';
        bar.style.background = 'var(--critical)';
        document.getElementById('scan-running-msg').style.display = 'none';
    }
}

// Check if scan already running
async function checkStatus() {
    const data = await api('/scan/progress');
    if (data.running) {
        document.getElementById('scan-running-msg').style.display = 'block';
        document.getElementById('scan-progress-section').style.display = 'block';
        pollScanProgress();
    }
}

loadTargets();
checkStatus();
