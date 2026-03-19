// ---- PAN-OS Wizard (Modular Step System) ----
import { api, toast, state, navigate } from '../main.js';

/**
 * Main entrance for each step page.
 * Renders the layout and the specific step content.
 */
export async function renderPanosWizard(container, step = 1) {
  const device = state.activeDevice;
  if (!device) {
    container.innerHTML = `<div class="card box-design"><div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> first.</p></div></div>`;
    return;
  }

  const p = state.panos;
  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">PAN-OS Wizard — Step ${step} of 5</h1>
      <p class="page-subtitle">${getStepSubtitle(step, device.name)}</p>
    </div>

    <!-- Step Indicator -->
    <div class="step-indicator-bar box-design">
      ${[1, 2, 3, 4, 5].map(n => `
        <a href="#/panos/step${n}" class="step-btn ${n === step ? 'active' : ''} ${n < step ? 'completed' : ''}">
          <span class="step-num">${n}</span>
          <span class="step-label">${getStepLabel(n)}</span>
        </a>
      `).join('<div class="step-line"></div>')}
    </div>

    <!-- Step Content Container -->
    <div id="wizard-content"></div>

    <!-- Global Preview / Review Area -->
    <div class="card box-design" id="preview-card" style="margin-top:20px;display:none;">
      <div class="card-header">
        <span class="card-title">Review Request</span>
        <button class="btn btn-ghost btn-sm" id="btn-close-preview">Close</button>
      </div>
      <div id="preview-body" style="padding:16px;"></div>
    </div>

    <!-- Global API Response -->
    <div class="card box-design" id="response-card" style="margin-top:20px;display:none;">
      <div class="card-header">
        <span class="card-title">API Response</span>
        <button class="btn btn-ghost btn-sm" id="btn-copy-response">Copy</button>
      </div>
      <div class="rule-preview" id="response-text" style="max-height:300px;overflow-y:auto;white-space:pre-wrap;font-size:0.82rem;font-family:var(--font-mono);"></div>
    </div>
  `;

  const content = container.querySelector('#wizard-content');

  // Render specific step
  switch (step) {
    case 1: renderStep1(content, p); break;
    case 2: renderStep2(content, p); break;
    case 3: await renderStep3(content, p, device); break;
    case 4: await renderStep4(content, p, device); break;
    case 5: renderStep5(content, p, device); break;
  }

  // Common UI logic (Persistence, Copy, etc.)
  setupWizardLogic(container, p);
}

function getStepLabel(n) {
  return ['API Token', 'Connection', 'URL Category', 'Rule Config', 'Push'][n - 1];
}

function getStepSubtitle(n, deviceName) {
  const subs = [
    'Generate an API key for authentication',
    'Configure connection settings for Panorama or Firewall',
    'Create a Custom URL Category from discovered hostnames',
    'Configure the security rule parameters',
    'Preview and push the configuration'
  ];
  return `${subs[n - 1]} for <strong>${deviceName}</strong>`;
}

/**
 * Ensures state object is up-to-date with current values in the DOM fields.
 * This handles cases where fields are auto-filled or edited but not yet blurred.
 */
function syncStateFromFields(container, p) {
  container.querySelectorAll('.pa-persist').forEach(el => {
    p[el.dataset.key] = el.value;
  });
}

// ---- STEP 1: API Token ----
function renderStep1(container, p) {
  container.innerHTML = `
    <div class="card box-design">
      <div class="card-header"><span class="card-title">1. Generate API Key</span></div>
      <p class="text-muted" style="margin-bottom:16px;">Enter credentials to retrieve an API key.</p>
      <div class="form-group">
          <label class="form-label">Management Host</label>
          <input class="form-input pa-persist" id="keygen-host" data-key="keygenHost" placeholder="e.g. 192.168.1.1" value="${p.keygenHost}" />
      </div>
      <div class="form-row">
          <div class="form-group">
            <label class="form-label">Username</label>
            <input class="form-input pa-persist" id="keygen-user" data-key="keygenUser" placeholder="admin" value="${p.keygenUser}" />
          </div>
          <div class="form-group">
            <label class="form-label">Password</label>
            <input class="form-input pa-persist" id="keygen-pass" data-key="keygenPass" type="password" value="${p.keygenPass}" />
          </div>
      </div>
      <div style="display:flex;gap:12px;align-items:center;margin-top:10px;">
        <button class="btn btn-ghost" id="btn-keygen-preview">Review Request</button>
        <button class="btn btn-primary" id="btn-keygen">Generate Key</button>
        <span id="keygen-status" class="text-muted" style="font-size:0.85rem;"></span>
      </div>
      <div id="keygen-result" style="display:none;margin-top:16px;padding-top:16px;border-top:1px solid var(--border-color);">
        <label class="form-label">Resulting API Key</label>
        <div style="display:flex;gap:8px;">
          <input class="form-input" id="keygen-key-output" readonly style="font-family:var(--font-mono);font-size:0.8rem;" />
          <button class="btn btn-secondary btn-sm" id="btn-keygen-use">Apply & Continue</button>
        </div>
      </div>
    </div>
  `;

  container.querySelector('#btn-keygen-preview').onclick = () => {
    syncStateFromFields(container, p);
    const host = p.keygenHost;
    const user = p.keygenUser;
    const pass = p.keygenPass;
    showPreview([
      { label: 'Method', text: 'GET' },
      { label: 'URL', text: `https://${host || '[HOST]'}/api/` },
      { label: 'Parameters', text: `type=keygen\nuser=${user || '[USER]'}\npassword=${pass ? '********' : '[PASS]'}` }
    ]);
  };

  container.querySelector('#btn-keygen').onclick = async () => {
    syncStateFromFields(container, p);
    const host = p.keygenHost;
    const user = p.keygenUser;
    const pass = p.keygenPass;
    if (!host || !user || !pass) { toast('Fill all fields', 'error'); return; }

    const status = container.querySelector('#keygen-status');
    status.textContent = 'Processing...';
    try {
      const res = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'GET', url: `https://${host}/api/`,
          params: { type: 'keygen', user, password: pass }
        }
      });
      showResponse(res.body, res.success);
      const match = (res.body || '').match(/<key>(.*?)<\/key>/);
      if (match) {
        container.querySelector('#keygen-result').style.display = 'block';
        container.querySelector('#keygen-key-output').value = match[1];
        status.textContent = 'Success';
        status.style.color = 'var(--accent-green)';
        if (!p.host) p.host = host;
      } else {
        status.textContent = 'Parse Error';
        status.style.color = 'var(--accent-red)';
      }
    } catch (e) {
      status.textContent = `Error: ${e.message}`;
      status.style.color = 'var(--accent-red)';
      showResponse(e.message, false);
    }
  };

  container.querySelector('#btn-keygen-use').onclick = () => {
    p.key = container.querySelector('#keygen-key-output').value;
    p.host = container.querySelector('#keygen-host').value.trim();
    toast('Key applied', 'success');
    navigate('/panos/step2');
  };
}

// ---- STEP 2: Connection ----
function renderStep2(container, p) {
  container.innerHTML = `
    <div class="card box-design">
      <div class="card-header"><span class="card-title">2. Connection Settings</span></div>
      <div class="form-group">
        <label class="form-label">Host (FQDN or IP)</label>
        <input class="form-input pa-persist" id="pa-host" data-key="host" value="${p.host}" />
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">PAN-OS Version</label>
          <input class="form-input pa-persist" id="pa-version" data-key="version" placeholder="e.g. 11.1" value="${p.version}" />
        </div>
        <div class="form-group">
          <label class="form-label">API Key</label>
          <input class="form-input pa-persist" id="pa-key" data-key="key" type="password" value="${p.key}" />
        </div>
      </div>
      <div class="nav-footer">
        <button class="btn btn-secondary" onclick="window.location.hash='#/panos/step1'">Back</button>
        <button class="btn btn-primary" onclick="window.location.hash='#/panos/step3'">Continue</button>
      </div>
    </div>
  `;
}

// ---- STEP 3: Category ----
async function renderStep3(container, p, device) {
  const urls = state.selectedUrls || [];
  container.innerHTML = `
    <div class="card box-design">
      <div class="card-header">
        <span class="card-title">3. URL Category</span>
        <span class="badge ${urls.length ? 'badge-primary' : 'badge-muted'}">${urls.length} hostnames selected</span>
      </div>
      <p class="text-muted" style="margin-bottom:12px;">Create a Custom URL Category from discovered hostnames.</p>
      
      <div class="url-scroll-box box-design">
        ${urls.length ? urls.map(u => `<div class="url-item">${u}</div>`).join('') : '<p class="text-muted">No hostnames selected. Go to Allow List to select them.</p>'}
      </div>

      <div class="form-group">
        <label class="form-label">Category Name *</label>
        <input class="form-input pa-persist" id="url-grp-name" data-key="urlGroupName" value="${p.urlGroupName || `iot-${device.name.toLowerCase().replace(/\s+/g, '-')}-urls`}" />
      </div>

      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Device Group (Panorama)</label>
          <input class="form-input pa-persist" id="url-pan-dg" data-key="panDg" value="${p.panDg}" />
        </div>
        <div class="form-group">
          <label class="form-label">Target VSYS (Firewall)</label>
          <input class="form-input pa-persist" id="url-fw-vsys" data-key="fwVsys" value="${p.fwVsys}" />
        </div>
      </div>

      <div style="display:flex;gap:12px;margin-top:16px;">
        <button class="btn btn-ghost" id="btn-push-cat-preview">Review Request</button>
        <button class="btn btn-success" id="btn-push-cat">Push Category to Panorama</button>
        <span id="push-cat-status" class="text-muted" style="font-size:0.85rem;"></span>
      </div>

      <div class="nav-footer">
        <button class="btn btn-secondary" onclick="window.location.hash='#/panos/step2'">Back</button>
        <button class="btn btn-primary" onclick="window.location.hash='#/panos/step4'">Continue</button>
      </div>
    </div>
  `;

  container.querySelector('#btn-push-cat-preview').onclick = () => {
    syncStateFromFields(container, p);
    const body = { entry: { '@name': p.urlGroupName, list: { member: urls }, type: 'URL List', description: `IoT URLs - ${device.name}` } };
    let location = 'vsys', locVal = p.fwVsys, locKey = 'vsys';
    if (p.panDg) { location = 'device-group'; locVal = p.panDg; locKey = 'device-group'; }

    showPreview([
      { label: 'Method', text: 'POST' },
      { label: 'URL', text: `https://${p.host || '[HOST]'}/restapi/v${p.version || '[VER]'}/Objects/CustomURLCategories` },
      { label: 'Query Params', text: `name=${p.urlGroupName}\nlocation=${location}\n${locKey}=${locVal}` },
      { label: 'Body', text: JSON.stringify(body, null, 2) }
    ]);
  };

  container.querySelector('#btn-push-cat').onclick = () => {
    syncStateFromFields(container, p);
    pushCategory(p, device);
  };
}

// ---- STEP 4: Rule Config ----
async function renderStep4(container, p, device) {
  container.innerHTML = `
    <div class="card box-design">
      <div class="card-header"><span class="card-title">4. Rule Configuration</span></div>
      <div id="rule-load-banner" class="banner box-design">Auto-loading flows from analysis...</div>
      
      <div class="form-group">
        <label class="form-label">Rule Name</label>
        <input class="form-input pa-persist" id="rule-name" data-key="ruleName" value="${p.ruleName}" />
      </div>

      <div class="form-row">
        <div class="form-group"><label class="form-label">From Zone</label><input class="form-input pa-persist" id="rule-from" data-key="ruleFrom" value="${p.ruleFrom}" /></div>
        <div class="form-group"><label class="form-label">To Zone</label><input class="form-input pa-persist" id="rule-to" data-key="ruleTo" value="${p.ruleTo}" /></div>
      </div>

      <div class="form-row">
        <div class="form-group"><label class="form-label">Source</label><input class="form-input pa-persist" id="rule-source" data-key="ruleSource" value="${p.ruleSource}" /></div>
        <div class="form-group"><label class="form-label">Destination</label><input class="form-input pa-persist" id="rule-dest" data-key="ruleDest" value="${p.ruleDest}" /></div>
      </div>

      <div class="form-row">
        <div class="form-group"><label class="form-label">App</label><input class="form-input pa-persist" id="rule-app" data-key="ruleApp" value="${p.ruleApp}" /></div>
        <div class="form-group"><label class="form-label">Service</label><input class="form-input pa-persist" id="rule-service" data-key="ruleService" value="${p.ruleService}" /></div>
      </div>

      <div class="form-group">
        <label class="form-label">URL Category</label>
        <input class="form-input pa-persist" id="rule-url-group" data-key="urlGroupName" value="${p.urlGroupName}" placeholder="Optional custom category" />
      </div>

      <div class="nav-footer">
        <button class="btn btn-secondary" onclick="window.location.hash='#/panos/step3'">Back</button>
        <button class="btn btn-primary" onclick="window.location.hash='#/panos/step5'">Continue</button>
      </div>
    </div>
  `;

  // Auto-load flows
  try {
    const res = await api(`/api/devices/${device.id}/panos/rules-from-flows`, { method: 'POST', body: { variables: {} } });
    if (res.entry) {
      const e = res.entry;
      if (!p.ruleName) p.ruleName = e['@name'];
      if (!p.ruleSource) p.ruleSource = (e.source?.member || []).join(', ');
      if (!p.ruleDest) p.ruleDest = (e.destination?.member || []).join(', ');
      if (!p.ruleService) p.ruleService = (e.service?.member || []).join(', ');
      if (!p.ruleApp) p.ruleApp = (e.application?.member || []).join(', ');
      const banner = container.querySelector('#rule-load-banner');
      banner.innerHTML = 'Flows loaded successfully';
      banner.style.background = 'var(--accent-green-dim)';
      // update inputs
      container.querySelector('#rule-name').value = p.ruleName;
      container.querySelector('#rule-source').value = p.ruleSource;
      container.querySelector('#rule-dest').value = p.ruleDest;
      container.querySelector('#rule-service').value = p.ruleService;
      container.querySelector('#rule-app').value = p.ruleApp;
    }
  } catch (e) { container.querySelector('#rule-load-banner').textContent = 'Flow load failed. Manual entry required.'; }
}

// ---- STEP 5: Push ----
function renderStep5(container, p, device) {
  container.innerHTML = `
    <div class="card box-design">
      <div class="card-header"><span class="card-title">5. Push Rule</span></div>
      
      <div class="push-toggle box-design">
        <button class="push-btn active" id="tab-panorama">Panorama</button>
        <button class="push-btn" id="tab-firewall">Direct Firewall</button>
      </div>

      <div id="push-panel-panorama" class="push-panel">
        <div class="form-group">
          <label class="form-label">Device Group</label>
          <input class="form-input pa-persist" id="pan-dg" data-key="panDg" value="${p.panDg}" />
        </div>
        <div class="form-group">
          <label class="form-label">Target Devices (Serials)</label>
          <input class="form-input pa-persist" id="pan-target" data-key="panTarget" value="${p.panTarget}" placeholder="Optional: serial1, serial2" />
        </div>
        <div style="display:flex;gap:12px;margin-top:16px;">
          <button class="btn btn-ghost" id="btn-pan-preview">Review Request</button>
          <button class="btn btn-success" id="btn-push-pan" style="flex:1;">Push to Panorama</button>
        </div>
      </div>

      <div id="push-panel-firewall" class="push-panel" style="display:none;">
        <div class="form-group">
          <label class="form-label">VSYS</label>
          <input class="form-input pa-persist" id="fw-vsys" data-key="fwVsys" value="${p.fwVsys}" />
        </div>
        <div style="display:flex;gap:12px;margin-top:16px;">
          <button class="btn btn-ghost" id="btn-fw-preview">Review Request</button>
          <button class="btn btn-success" id="btn-push-fw" style="flex:1;">Push to Firewall</button>
        </div>
      </div>

      <div class="nav-footer">
        <button class="btn btn-secondary" onclick="window.location.hash='#/panos/step4'">Back</button>
      </div>
    </div>
  `;

  // Tab logic
  const tPan = container.querySelector('#tab-panorama');
  const tFw = container.querySelector('#tab-firewall');
  const pPan = container.querySelector('#push-panel-panorama');
  const pFw = container.querySelector('#push-panel-firewall');

  tPan.onclick = () => { tPan.classList.add('active'); tFw.classList.remove('active'); pPan.style.display = 'block'; pFw.style.display = 'none'; };
  tFw.onclick = () => { tFw.classList.add('active'); tPan.classList.remove('active'); pFw.style.display = 'block'; pPan.style.display = 'none'; };

  container.querySelector('#btn-pan-preview').onclick = () => {
    syncStateFromFields(container, p);
    const body = getRuleConfig(p, 'panorama');
    showPreview([
      { label: 'Method', text: 'POST' },
      { label: 'URL', text: `https://${p.host || '[HOST]'}/restapi/v${p.version || '[VER]'}/Policies/SecurityPostRules` },
      { label: 'Query Params', text: `name=${p.ruleName}\nlocation=device-group\ndevice-group=${p.panDg}` },
      { label: 'Body', text: JSON.stringify(body, null, 2) }
    ]);
  };

  container.querySelector('#btn-fw-preview').onclick = () => {
    syncStateFromFields(container, p);
    const body = getRuleConfig(p, 'firewall');
    showPreview([
      { label: 'Method', text: 'POST' },
      { label: 'URL', text: `https://${p.host || '[HOST]'}/restapi/v${p.version || '[VER]'}/Policies/SecurityRules` },
      { label: 'Query Params', text: `name=${p.ruleName}\nlocation=vsys\nvsys=${p.fwVsys}` },
      { label: 'Body', text: JSON.stringify(body, null, 2) }
    ]);
  };

  container.querySelector('#btn-push-pan').onclick = () => {
    syncStateFromFields(container, p);
    pushRule(p, 'panorama');
  };
  container.querySelector('#btn-push-fw').onclick = () => {
    syncStateFromFields(container, p);
    pushRule(p, 'firewall');
  };
}

// ---- HELPERS & LOGIC ----

function setupWizardLogic(container, p) {
  container.querySelectorAll('.pa-persist').forEach(el => {
    el.addEventListener('input', () => { p[el.dataset.key] = el.value; });
  });

  const copyBtn = document.getElementById('btn-copy-response');
  if (copyBtn) {
    copyBtn.onclick = () => {
      const text = document.getElementById('response-text').textContent;
      navigator.clipboard.writeText(text).then(() => toast('Copied!', 'success'));
    };
  }
}

function getRuleConfig(p, mode) {
  const entry = {
    '@name': p.ruleName,
    from: { member: (p.ruleFrom || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    to: { member: (p.ruleTo || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    source: { member: (p.ruleSource || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    destination: { member: (p.ruleDest || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    application: { member: (p.ruleApp || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    service: { member: (p.ruleService || 'any').split(',').map(s => s.trim()).filter(Boolean) },
    action: 'allow'
  };
  if (p.urlGroupName) entry.category = { member: [p.urlGroupName] };
  if (mode === 'panorama' && p.panTarget) {
    entry.target = { devices: { entry: p.panTarget.split(',').map(s => ({ '@name': s.trim() })) } };
  }
  return { entry: [entry] };
}

async function pushCategory(p, device) {
  const status = document.getElementById('push-cat-status');
  if (status) status.textContent = 'Pushing...';

  const urls = state.selectedUrls || [];
  const body = { entry: { '@name': p.urlGroupName, list: { member: urls }, type: 'URL List', description: `IoT URLs - ${device.name}` } };

  let location = 'vsys', locVal = p.fwVsys, locKey = 'vsys';
  if (p.panDg) { location = 'device-group'; locVal = p.panDg; locKey = 'device-group'; }

  try {
    const res = await api('/api/panos/proxy', {
      method: 'POST', body: {
        http_method: 'POST',
        url: `https://${p.host}/restapi/v${p.version}/Objects/CustomURLCategories`,
        params: { name: p.urlGroupName, location, [locKey]: locVal },
        headers: { 'X-PAN-KEY': p.key, 'Content-Type': 'application/json' },
        json_body: body
      }
    });
    showResponse(res.body, res.success);
    if (status) status.textContent = res.success ? 'Success' : 'Failed';
  } catch (e) {
    if (status) status.textContent = 'Error';
    toast(e.message, 'error');
    showResponse(e.message, false);
  }
}

async function pushRule(p, mode) {
  const body = getRuleConfig(p, mode);
  let url, params;
  if (mode === 'panorama') {
    url = `https://${p.host}/restapi/v${p.version}/Policies/SecurityPostRules`;
    params = { name: p.ruleName, location: 'device-group', 'device-group': p.panDg };
  } else {
    url = `https://${p.host}/restapi/v${p.version}/Policies/SecurityRules`;
    params = { name: p.ruleName, location: 'vsys', vsys: p.fwVsys };
  }

  try {
    const res = await api('/api/panos/proxy', {
      method: 'POST', body: {
        http_method: 'POST', url, params,
        headers: { 'X-PAN-KEY': p.key, 'Content-Type': 'application/json' },
        json_body: body
      }
    });
    showResponse(res.body, res.success);
  } catch (e) {
    toast(e.message, 'error');
    showResponse(e.message, false);
  }
}

function showPreview(sections) {
  const card = document.getElementById('preview-card');
  const body = document.getElementById('preview-body');
  const close = document.getElementById('btn-close-preview');

  if (!card || !body) return;

  card.style.display = 'block';
  body.innerHTML = sections.map(s => `
    <div style="margin-bottom:12px;">
      <label style="font-weight:600;font-size:0.75rem;text-transform:uppercase;color:var(--text-muted);">${s.label}</label>
      <div class="rule-preview" style="padding:8px;margin-top:4px;font-size:0.8rem;">${s.text}</div>
    </div>
  `).join('');

  close.onclick = () => card.style.display = 'none';
  card.scrollIntoView({ behavior: 'smooth' });
}

function showResponse(text, success) {
  const card = document.getElementById('response-card');
  const textField = document.getElementById('response-text');
  if (!card || !textField) return;

  card.style.display = 'block';
  textField.textContent = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  card.scrollIntoView({ behavior: 'smooth' });
}
