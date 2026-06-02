// Skills page JavaScript
const API = '/api';

async function api(path, opts = {}) {
    const res = await fetch(API + path, opts);
    return res.json();
}

async function loadSkills() {
    const skills = await api('/skills');
    const overview = document.getElementById('skills-overview');
    const details = document.getElementById('skills-details');

    if (skills.length === 0) {
        overview.innerHTML = '';
        details.innerHTML = '<div class="card"><p class="muted">No skills accumulated yet. Run your first scan to start learning.</p></div>';
        return;
    }

    // Overview stats
    let totalIter = 0, totalEndpoints = 0, totalParams = 0, totalFindings = 0;
    skills.forEach(s => {
        totalIter += s.iterations;
        totalEndpoints += s.known_endpoints;
        totalParams += s.known_parameters;
        totalFindings += s.past_findings;
    });

    overview.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${totalIter}</div>
            <div class="stat-label">Total Iterations</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${totalEndpoints}</div>
            <div class="stat-label">Known Endpoints</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${totalParams}</div>
            <div class="stat-label">Known Parameters</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${totalFindings}</div>
            <div class="stat-label">Past Findings</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${skills.length}</div>
            <div class="stat-label">Targets</div>
        </div>
    `;

    // Per-target details
    details.innerHTML = skills.map(s => `
        <div class="skill-item">
            <h3>${s.target_name} <span class="badge badge-info">Iteration #${s.iterations}</span></h3>
            <p class="muted">Last tested: ${s.last_test_date || 'Never'}</p>

            <div class="stats-grid" style="margin:12px 0;">
                <div class="stat-card">
                    <div class="stat-value" style="font-size:20px;">${s.known_endpoints}</div>
                    <div class="stat-label">Endpoints</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="font-size:20px;">${s.known_parameters}</div>
                    <div class="stat-label">Parameters</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="font-size:20px;">${s.past_findings}</div>
                    <div class="stat-label">Findings</div>
                </div>
            </div>

            ${s.improvement_notes.length > 0 ? `
                <h3 style="margin-top:12px;">Improvement Notes</h3>
                <ul class="note-list">
                    ${s.improvement_notes.map(n => `<li>${n}</li>`).join('')}
                </ul>
            ` : ''}

            <div style="margin-top:12px;">
                <button class="btn btn-sm btn-danger" onclick="resetSkills('${s.target_id}')">🔄 Reset Skills</button>
                <button class="btn btn-sm" onclick="viewFullSkills('${s.target_id}')">📋 Full Data</button>
            </div>
        </div>
    `).join('');
}

async function resetSkills(targetId) {
    if (!confirm('Reset all learned skills for this target?')) return;
    await api(`/skills/${targetId}/reset`, {method: 'POST'});
    loadSkills();
}

async function viewFullSkills(targetId) {
    const data = await api(`/skills/${targetId}`);
    const w = window.open('', '_blank');
    w.document.write(`<pre>${JSON.stringify(data, null, 2)}</pre>`);
    w.document.title = `Skills: ${targetId}`;
}

loadSkills();
