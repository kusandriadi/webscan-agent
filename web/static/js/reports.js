// Reports page JavaScript
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

async function loadReports() {
    const reports = await api('/reports');
    const filter = document.getElementById('report-filter').value;
    const tbody = document.getElementById('reports-tbody');

    let filtered = reports;
    if (filter === 'pdf') filtered = reports.filter(r => r.filename?.endsWith('.pdf'));
    else if (filter === 'json') filtered = reports.filter(r => r.filename?.endsWith('.json'));

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="muted">No reports found.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(r => {
        const isPdf = r.filename?.endsWith('.pdf');
        const icon = isPdf ? '📕' : '📋';
        return `
            <tr>
                <td>${icon} ${r.filename}</td>
                <td>${formatSize(r.size)}</td>
                <td>${formatDate(r.created)}</td>
                <td>
                    <a class="btn btn-sm" href="/api/reports/download/${r.filename}">⬇ Download</a>
                    ${isPdf ? `<a class="btn btn-sm" href="/api/reports/view/${r.filename}" target="_blank">👁 View</a>` : ''}
                    ${!isPdf ? `<a class="btn btn-sm" href="/api/reports/view/${r.filename}" target="_blank">📊 Data</a>` : ''}
                </td>
            </tr>
        `;
    }).join('');
}

document.getElementById('report-filter').addEventListener('change', loadReports);
loadReports();
