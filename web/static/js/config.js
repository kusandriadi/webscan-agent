// Configuration page JavaScript
const API = '/api';

async function api(path, opts = {}) {
    const res = await fetch(API + path, opts);
    return res.json();
}

// Auth method toggle
document.getElementById('t-auth-method').addEventListener('change', function() {
    document.getElementById('auth-form-fields').style.display = this.value === 'form' ? 'grid' : 'none';
    document.getElementById('auth-token-fields').style.display = this.value === 'token' ? 'grid' : 'none';
});

// Add target form
document.getElementById('add-target-form').addEventListener('submit', async function(e) {
    e.preventDefault();

    const authMethod = document.getElementById('t-auth-method').value;
    const target = {
        name: document.getElementById('t-name').value,
        target_url: document.getElementById('t-url').value,
        enabled: true,
        auth: {
            method: authMethod,
            username: document.getElementById('t-username').value,
            password: document.getElementById('t-password').value,
            token: document.getElementById('t-token').value,
            login_url: document.getElementById('t-login-url').value,
            login_selectors: {
                username_field: "input[name='username'], input[type='email']",
                password_field: "input[name='password'], input[type='password']",
                submit_button: "button[type='submit'], input[type='submit']",
            }
        },
        issues: {
            url: document.getElementById('t-issues-url').value,
        },
        scope: {
            include_paths: ["*"],
            exclude_paths: ["/logout"],
            max_crawl_depth: 2,
            rate_limit_rps: 3,
            timeout_seconds: 30,
        },
        test_options: {
            test_xss: document.getElementById('to-xss').checked,
            test_sqli: document.getElementById('to-sqli').checked,
            test_csrf: document.getElementById('to-csrf').checked,
            test_idor: document.getElementById('to-idor').checked,
            test_auth_bypass: document.getElementById('to-auth').checked,
            test_authz: document.getElementById('to-authz').checked,
            test_session: document.getElementById('to-session').checked,
            test_info_disclosure: document.getElementById('to-info').checked,
            test_api_endpoints: document.getElementById('to-api').checked,
            test_owasp_top10: document.getElementById('to-owasp').checked,
        }
    };

    try {
        await api('/targets', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(target),
        });
        this.reset();
        document.getElementById('auth-form-fields').style.display = 'none';
        document.getElementById('auth-token-fields').style.display = 'none';
        loadTargets();
    } catch (e) {
        alert('Error: ' + e);
    }
});

async function loadTargets() {
    const targets = await api('/targets');
    const list = document.getElementById('targets-list');

    if (targets.length === 0) {
        list.innerHTML = '<p class="muted">No targets configured.</p>';
        return;
    }

    list.innerHTML = targets.map(t => `
        <div class="target-card">
            <div class="target-info">
                <h3>${t.name || t.id} <span class="badge ${t.enabled ? 'badge-success' : 'badge-info'}">${t.enabled ? 'Active' : 'Disabled'}</span></h3>
                <p>
                    ${t.target_url}<br>
                    Auth: <strong>${t.auth?.method || 'none'}</strong>
                    ${t.issues?.url ? '• Issues: ' + t.issues.url : ''}
                </p>
            </div>
            <div style="display:flex;gap:8px;">
                <button class="btn btn-sm" onclick="toggleTarget('${t.id}', ${!t.enabled})">${t.enabled ? 'Disable' : 'Enable'}</button>
                <button class="btn btn-sm btn-danger" onclick="deleteTarget('${t.id}')">Delete</button>
            </div>
        </div>
    `).join('');
}

async function toggleTarget(id, enabled) {
    const targets = await api('/targets');
    const t = targets.find(t => t.id === id);
    if (t) {
        t.enabled = enabled;
        await api(`/targets/${id}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(t),
        });
        loadTargets();
    }
}

async function deleteTarget(id) {
    if (!confirm('Delete target?')) return;
    await api(`/targets/${id}`, {method: 'DELETE'});
    loadTargets();
}

loadTargets();
