// Dashboard JavaScript
const API = '/api';

async function api(path, opts = {}) {
    const res = await fetch(API + path, opts);
    return res.json();
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDate(iso) {
    if (!iso) return 'N/A';
    return new Date(iso).toLocaleString();
}

// Load quick stats
async function loadStats() {
    const [targets, history, reports] = await Promise.all([
        api('/targets'),
        api('/scan/history'),
        api('/reports'),
    ]);

    document.getElementById('total-targets').textContent = targets.length;
    document.getElementById('total-scans').textContent = history.length;

    let totalFindings = 0, critical = 0, high = 0;
    history.forEach(h => {
        const s = h.stats || {};
        totalFindings += s.total_findings || 0;
        critical += s.critical || 0;
        high += s.high || 0;
    });
    document.getElementById('total-findings').textContent = totalFindings;
    document.getElementById('critical-count').textContent = critical;
    document.getElementById('high-count').textContent = high;

    // Scan history
    const historyEl = document.getElementById('scan-history');
    if (history.length === 0) {
        historyEl.innerHTML = '<p class="muted">No scans yet. <a href="/scan">Start your first scan →</a></p>';
    } else {
        historyEl.innerHTML = `
            <table class="data-table">
                <thead><tr><th>Date</th><th>Target</th><th>Findings</th><th>Duration</th><th>Iteration</th></tr></thead>
                <tbody>
                ${history.slice(0, 10).map(h => `
                    <tr>
                        <td>${h.date}</td>
                        <td>${h.target_name || h.target_id}</td>
                        <td>
                            ${(h.stats?.critical || 0) ? `<span class="badge badge-critical">${h.stats.critical} critical</span> ` : ''}
                            ${(h.stats?.high || 0) ? `<span class="badge badge-high">${h.stats.high} high</span> ` : ''}
                            ${(h.stats?.medium || 0) ? `<span class="badge badge-medium">${h.stats.medium} med</span>` : ''}
                            ${h.findings_count} total
                        </td>
                        <td>${h.duration ? h.duration + 's' : 'N/A'}</td>
                        <td>#${h.skills_iteration || '?'}</td>
                    </tr>
                `).join('')}
                </tbody>
            </table>`;
    }

    // Recent reports
    const reportsEl = document.getElementById('recent-reports');
    const pdfs = reports.filter(r => r.filename?.endsWith('.pdf')).slice(0, 5);
    if (pdfs.length === 0) {
        reportsEl.innerHTML = '<p class="muted">No reports yet.</p>';
    } else {
        reportsEl.innerHTML = `
            <table class="data-table">
                <thead><tr><th>Report</th><th>Size</th><th>Date</th><th>Actions</th></tr></thead>
                <tbody>
                ${pdfs.map(r => `
                    <tr>
                        <td>${r.filename}</td>
                        <td>${formatSize(r.size)}</td>
                        <td>${formatDate(r.created)}</td>
                        <td>
                            <a class="btn btn-sm" href="/api/reports/download/${r.filename}">⬇ Download</a>
                        </td>
                    </tr>
                `).join('')}
                </tbody>
            </table>`;
    }
}

// Poll scan progress
async function pollProgress() {
    const data = await api('/scan/progress');
    const bar = document.getElementById('scan-status-bar');
    const card = document.getElementById('progress-card');

    if (data.running) {
        bar.innerHTML = `<span class="badge badge-running">SCANNING</span> ${data.progress.target_name || '...'} — ${data.progress.phase || ''}`;
        card.style.display = 'block';
        document.getElementById('progress-info').innerHTML = `
            <strong>Target:</strong> ${data.progress.target_name || '-'}<br>
            <strong>Status:</strong> ${data.progress.phase || '-'}<br>
            <strong>Findings so far:</strong> ${data.progress.findings_count || 0}
        `;
        // Animate progress bar
        const phases = ['initializing', 'starting_browser', 'scanning', 'complete'];
        const idx = phases.indexOf(data.progress.status);
        const pct = Math.max(10, ((idx + 1) / phases.length) * 100);
        document.getElementById('progress-bar').style.width = pct + '%';
    } else {
        bar.textContent = data.progress?.status === 'complete' ?
            '✅ Last scan completed' : 'Idle — No scan running';
        if (data.progress?.status === 'complete') {
            card.style.display = 'block';
            document.getElementById('progress-info').innerHTML = `
                <strong>Last scan completed!</strong><br>
                Findings: ${data.progress.findings_count || 0} |
                <a href="/reports">View reports →</a>
            `;
            document.getElementById('progress-bar').style.width = '100%';
        } else if (data.progress?.status === 'error') {
            card.style.display = 'block';
            document.getElementById('progress-info').innerHTML = `
                <strong>❌ Scan failed:</strong> ${data.progress.error || 'Unknown error'}
            `;
        } else {
            card.style.display = 'none';
        }
    }
}

// Init
loadStats();
pollProgress();
setInterval(pollProgress, 5000);
setInterval(loadStats, 30000);
