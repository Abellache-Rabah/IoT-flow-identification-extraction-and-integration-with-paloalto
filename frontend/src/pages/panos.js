// ---- PAN-OS API Page (Firewall Direct + Panorama — REST only) ----
import { api, toast, state } from '../main.js';

export async function renderPanos(container) {
  const device = state.activeDevice;
  if (!device) {
    container.innerHTML = `<div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> first.</p></div>`;
    return;
  }

  const p = state.panos;

  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">PAN-OS API</h1>
      <p class="page-subtitle">Push firewall rules for <strong>${device.name}</strong> to Palo Alto Firewall or Panorama</p>
    </div>

    <!-- Generate API Key -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-header"><span class="card-title">🔑 Generate API Key</span></div>
      <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:12px;">Enter credentials to generate an API key from the firewall/Panorama.</p>
      <div class="var-panel">
        <div class="form-group">
          <label class="form-label">Host</label>
          <input class="form-input pa-persist" id="keygen-host" data-key="keygenHost" placeholder="e.g. 192.168.1.1" value="${p.keygenHost}" />
        </div>
        <div class="form-group">
          <label class="form-label">Username</label>
          <input class="form-input pa-persist" id="keygen-user" data-key="keygenUser" placeholder="admin" value="${p.keygenUser}" />
        </div>
        <div class="form-group">
          <label class="form-label">Password</label>
          <input class="form-input pa-persist" id="keygen-pass" data-key="keygenPass" placeholder="password" type="password" value="${p.keygenPass}" />
        </div>
      </div>
      <div style="display:flex;gap:10px;margin-top:12px;align-items:center;">
        <button class="btn btn-primary" id="btn-keygen">Generate Key</button>
        <span id="keygen-status" style="font-size:0.85rem;color:var(--text-muted);"></span>
      </div>
      <div id="keygen-result" style="display:none;margin-top:12px;">
        <label style="font-weight:600;color:var(--text-secondary);font-size:0.82rem;">API Key:</label>
        <div style="display:flex;gap:8px;align-items:center;margin-top:4px;">
          <input class="form-input" id="keygen-key-output" readonly style="font-family:var(--font-mono,monospace);font-size:0.82rem;" />
          <button class="btn btn-ghost btn-sm" id="btn-keygen-copy">Copy</button>
          <button class="btn btn-ghost btn-sm" id="btn-keygen-use">Use as API Key ↓</button>
        </div>
      </div>
    </div>

    <!-- Connection Settings -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-header"><span class="card-title">⚙️ Connection Settings</span></div>
      <div class="var-panel">
        <div class="form-group">
          <label class="form-label">Host (hostname or IP)</label>
          <input class="form-input pa-persist" id="pa-host" data-key="host" placeholder="e.g. 192.168.1.1 or panorama.example.com" value="${p.host}" />
        </div>
        <div class="form-group">
          <label class="form-label">PAN-OS Version</label>
          <input class="form-input pa-persist" id="pa-version" data-key="version" placeholder="e.g. 11.1" value="${p.version}" />
        </div>
        <div class="form-group">
          <label class="form-label">API Key</label>
          <input class="form-input pa-persist" id="pa-key" data-key="key" placeholder="Your API key" type="password" value="${p.key}" />
        </div>
      </div>
    </div>

    <!-- Rule Configuration -->
    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <span class="card-title">📋 Rule Configuration</span>
        <button class="btn btn-ghost btn-sm" id="btn-load-from-flows" style="gap:4px;">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 7h12M8 2l5 5-5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
          Load from Allowed Flows
        </button>
      </div>
      <div class="var-panel">
        <div class="form-group">
          <label class="form-label">Rule Name</label>
          <input class="form-input pa-persist" id="rule-name" data-key="ruleName" placeholder="e.g. IoT-camera-allow" value="${p.ruleName}" />
        </div>
        <div class="form-group">
          <label class="form-label">Description <span style="color:var(--text-muted);font-weight:normal;">(optional)</span></label>
          <input class="form-input pa-persist" id="rule-description" data-key="ruleDescription" placeholder="Describe the purpose of this rule..." value="${p.ruleDescription}" />
        </div>
        <div class="form-row" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div class="form-group">
            <label class="form-label">From Zone</label>
            <input class="form-input pa-persist" id="rule-from" data-key="ruleFrom" placeholder="e.g. CAMPUS-IoTLab" value="${p.ruleFrom}" />
          </div>
          <div class="form-group">
            <label class="form-label">To Zone</label>
            <input class="form-input pa-persist" id="rule-to" data-key="ruleTo" placeholder="e.g. BACKBONE" value="${p.ruleTo}" />
          </div>
        </div>
        <div class="form-row" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div class="form-group">
            <label class="form-label">Source <span style="color:var(--text-muted);font-weight:normal;">(comma-sep, or "any")</span></label>
            <input class="form-input pa-persist" id="rule-source" data-key="ruleSource" placeholder="e.g. IOT-TEST or any" value="${p.ruleSource}" />
          </div>
          <div class="form-group">
            <label class="form-label">Destination <span style="color:var(--text-muted);font-weight:normal;">(comma-sep, or "any")</span></label>
            <input class="form-input pa-persist" id="rule-dest" data-key="ruleDest" placeholder="e.g. 10.0.1.0/24 or any" value="${p.ruleDest}" />
          </div>
        </div>
        <div class="form-row" style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
          <div class="form-group">
            <label class="form-label">Service <span style="color:var(--text-muted);font-weight:normal;">(comma-sep, or "any")</span></label>
            <input class="form-input pa-persist" id="rule-service" data-key="ruleService" placeholder="e.g. application-default or any" value="${p.ruleService}" />
          </div>
          <div class="form-group">
            <label class="form-label">Application <span style="color:var(--text-muted);font-weight:normal;">(comma-sep, or "any")</span></label>
            <input class="form-input pa-persist" id="rule-app" data-key="ruleApp" placeholder="e.g. ssl, web-browsing or any" value="${p.ruleApp}" />
          </div>
        </div>
        <div class="form-row" style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
          <div class="form-group">
            <label class="form-label">Tags <span style="color:var(--text-muted);font-weight:normal;">(comma-sep)</span></label>
            <input class="form-input pa-persist" id="rule-tags" data-key="ruleTags" placeholder="e.g. iot, onboarding" value="${p.ruleTags}" />
          </div>
          <div class="form-group">
            <label class="form-label">Action</label>
            <select class="form-select pa-persist-select" id="rule-action" data-key="ruleAction">
              <option value="allow" ${p.ruleAction === 'allow' ? 'selected' : ''}>Allow</option>
              <option value="deny" ${p.ruleAction === 'deny' ? 'selected' : ''}>Deny</option>
              <option value="drop" ${p.ruleAction === 'drop' ? 'selected' : ''}>Drop</option>
            </select>
          </div>
          <div class="form-group" style="display:flex;gap:16px;align-items:flex-end;padding-bottom:6px;">
            <label style="display:flex;align-items:center;gap:6px;color:var(--text-secondary);font-size:0.85rem;cursor:pointer;">
              <input type="checkbox" id="rule-log-start" ${p.logStart ? 'checked' : ''} /> Log Start
            </label>
            <label style="display:flex;align-items:center;gap:6px;color:var(--text-secondary);font-size:0.85rem;cursor:pointer;">
              <input type="checkbox" id="rule-log-end" ${p.logEnd ? 'checked' : ''} /> Log End
            </label>
          </div>
        </div>
      </div>
    </div>

    <!-- Tabs: Firewall / Panorama -->
    <div class="card" style="margin-bottom:20px;">
      <div style="display:flex;gap:0;border-bottom:2px solid var(--border-color);">
        <button class="pa-tab active" data-tab="firewall" style="flex:1;padding:12px 16px;background:none;border:none;border-bottom:2px solid var(--accent-indigo);margin-bottom:-2px;color:var(--text-primary);font-weight:600;cursor:pointer;font-size:0.9rem;">🔥 Firewall (Direct)</button>
        <button class="pa-tab" data-tab="panorama" style="flex:1;padding:12px 16px;background:none;border:none;border-bottom:2px solid transparent;margin-bottom:-2px;color:var(--text-muted);font-weight:500;cursor:pointer;font-size:0.9rem;">🏢 Panorama</button>
      </div>

      <!-- Firewall Tab -->
      <div class="pa-panel" id="panel-firewall" style="padding:16px 0;">
        <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:14px;">
          Push security rules directly to a PAN-OS firewall via REST API.
        </p>
        <div class="var-panel" style="margin-bottom:14px;">
          <div class="form-group">
            <label class="form-label">VSYS</label>
            <input class="form-input pa-persist" id="fw-vsys" data-key="fwVsys" placeholder="e.g. vsys1" value="${p.fwVsys}" />
          </div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
          <button class="btn btn-primary" id="btn-fw-preview">Preview Request</button>
          <button class="btn btn-success" id="btn-fw-push">Push Rule</button>
          <button class="btn btn-secondary" id="btn-fw-commit">Commit</button>
        </div>
        <div id="fw-preview" style="display:none;"></div>
      </div>

      <!-- Panorama Tab -->
      <div class="pa-panel" id="panel-panorama" style="padding:16px 0;display:none;">
        <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:14px;">
          Push security post-rules to Panorama, then commit &amp; push to device groups.
        </p>
        <div class="var-panel" style="margin-bottom:14px;">
          <div class="form-group">
            <label class="form-label">Device Group</label>
            <input class="form-input pa-persist" id="pan-dg" data-key="panDg" placeholder="e.g. MY-DEVICE-GROUP" value="${p.panDg}" />
          </div>
          <div class="form-group">
            <label class="form-label">Target Devices <span style="color:var(--text-muted);font-weight:normal;">(comma-sep serials/names, optional)</span></label>
            <input class="form-input pa-persist" id="pan-target" data-key="panTarget" placeholder="e.g. FW-01, FW-02" value="${p.panTarget || ''}" />
          </div>
          <div class="form-group">
            <label class="form-label">Target VSYS <span style="color:var(--text-muted);font-weight:normal;">(comma-sep, optional)</span></label>
            <input class="form-input pa-persist" id="pan-target-vsys" data-key="panTargetVsys" placeholder="e.g. vsys1, vsys2" value="${p.panTargetVsys || ''}" />
          </div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;">
          <button class="btn btn-primary" id="btn-pan-preview">Preview Request</button>
          <button class="btn btn-success" id="btn-pan-push">1. Push Post-Rule</button>
          <button class="btn btn-secondary" id="btn-pan-commit">2. Commit to Panorama</button>
          <button class="btn btn-secondary" id="btn-pan-push-dg" disabled title="Push to Device Group is not available — use Panorama UI after commit" style="opacity:0.45;cursor:not-allowed;">3. Push to Device Group</button>
        </div>
        <div id="pan-preview" style="display:none;"></div>
      </div>
    </div>

    <!-- Response -->
    <div class="card" id="response-card" style="margin-bottom:20px;display:none;">
      <div class="card-header">
        <span class="card-title">API Response</span>
        <button class="btn btn-ghost btn-sm" id="btn-copy-response">Copy</button>
      </div>
      <div class="rule-preview" id="response-text" style="max-height:350px;overflow-y:auto;white-space:pre-wrap;font-size:0.82rem;"></div>
    </div>
  `;

  // ===== STATE PERSISTENCE — save on every input change =====
  container.querySelectorAll('.pa-persist').forEach(el => {
    el.addEventListener('input', () => { p[el.dataset.key] = el.value; });
  });
  container.querySelectorAll('.pa-persist-select').forEach(el => {
    el.addEventListener('change', () => { p[el.dataset.key] = el.value; });
  });
  container.querySelector('#rule-log-start').addEventListener('change', e => { p.logStart = e.target.checked; });
  container.querySelector('#rule-log-end').addEventListener('change', e => { p.logEnd = e.target.checked; });

  // ===== TAB SWITCHING =====
  const tabs = container.querySelectorAll('.pa-tab');
  const panels = container.querySelectorAll('.pa-panel');
  tabs.forEach(tab => {
    tab.onclick = () => {
      tabs.forEach(t => { t.classList.remove('active'); t.style.borderBottomColor = 'transparent'; t.style.color = 'var(--text-muted)'; });
      panels.forEach(pp => pp.style.display = 'none');
      tab.classList.add('active');
      tab.style.borderBottomColor = 'var(--accent-indigo)';
      tab.style.color = 'var(--text-primary)';
      container.querySelector(`#panel-${tab.dataset.tab}`).style.display = 'block';
    };
  });

  // ===== HELPERS =====
  function getConn() {
    return {
      host: container.querySelector('#pa-host').value.trim(),
      version: container.querySelector('#pa-version').value.trim(),
      key: container.querySelector('#pa-key').value.trim(),
    };
  }

  function splitField(id) {
    const val = container.querySelector(id).value.trim();
    if (!val) return ['any'];
    return val.split(',').map(s => s.trim()).filter(Boolean);
  }

  function getRuleBody() {
    const name = container.querySelector('#rule-name').value.trim();
    const rawDesc = container.querySelector('#rule-description').value.trim();
    // Read username from the keygen-user field (whoever tried to generate the API key)
    const username = container.querySelector('#keygen-user').value.trim() || 'unknown';
    const description = rawDesc ? `${rawDesc} — ${username}` : `Created by ${username}`;
    const tagsVal = container.querySelector('#rule-tags').value.trim();
    const tagMembers = tagsVal ? tagsVal.split(',').map(s => s.trim()).filter(Boolean) : [];
    const entry = {
      '@name': name,
      description,
      from: { member: splitField('#rule-from') },
      to: { member: splitField('#rule-to') },
      source: { member: splitField('#rule-source') },
      destination: { member: splitField('#rule-dest') },
      service: { member: splitField('#rule-service') },
      application: { member: splitField('#rule-app') },
      action: container.querySelector('#rule-action').value,
      'log-start': container.querySelector('#rule-log-start').checked ? 'yes' : 'no',
      'log-end': container.querySelector('#rule-log-end').checked ? 'yes' : 'no',
    };
    if (tagMembers.length > 0) entry.tag = { member: tagMembers };
    return { entry: [entry] };
  }

  function getPostRuleBody() {
    const body = getRuleBody();
    const entry = body.entry[0];

    // Add target devices for Panorama if specified
    if (container.querySelector('#pan-target')) {
      const targetStr = container.querySelector('#pan-target').value.trim();
      const vsysStr = container.querySelector('#pan-target-vsys')?.value?.trim();
      const vsysList = vsysStr ? vsysStr.split(',').map(s => s.trim()).filter(Boolean) : [];

      if (targetStr) {
        const targetDevices = targetStr.split(',').map(s => s.trim()).filter(Boolean);
        const deviceEntries = targetDevices.map(name => {
          const d = { '@name': name };
          if (vsysList.length > 0) {
            d.vsys = { entry: vsysList.map(v => ({ '@name': v })) };
          }
          return d;
        });

        if (deviceEntries.length > 0) {
          entry.target = {
            devices: {
              entry: deviceEntries
            }
          };
        }
      }
    }

    return { entry };
  }

  function validate(fields) {
    const missing = [];
    for (const [label, val] of fields) {
      if (!val) missing.push(label);
    }
    if (missing.length) { toast(`Missing: ${missing.join(', ')}`, 'error'); return false; }
    return true;
  }

  function showResponse(text, success) {
    const card = container.querySelector('#response-card');
    card.style.display = 'block';
    container.querySelector('#response-text').textContent = text;
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    toast(success ? 'Request successful!' : 'Request failed — see response', success ? 'success' : 'error');
  }

  function escHtml(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  function previewBlock(targetId, sections) {
    const el = container.querySelector(targetId);
    el.style.display = 'block';
    el.innerHTML = sections.map(s => `
      <div style="margin-bottom:12px;">
        <label style="font-weight:600;color:var(--text-secondary);font-size:0.82rem;text-transform:uppercase;letter-spacing:0.04em;">${s.label}</label>
        <div class="rule-preview" style="font-size:0.82rem;word-break:break-all;margin-top:4px;white-space:pre-wrap;max-height:300px;overflow-y:auto;">${escHtml(s.text)}</div>
      </div>
    `).join('');
  }

  container.querySelector('#btn-copy-response').onclick = () => {
    navigator.clipboard.writeText(container.querySelector('#response-text').textContent).then(() => toast('Copied!', 'success'));
  };

  // Helper to set field + persist
  function setField(id, value) {
    const el = container.querySelector(id);
    el.value = value;
    if (el.dataset.key) p[el.dataset.key] = value;
  }

  // ===== GENERATE API KEY =====
  container.querySelector('#btn-keygen').onclick = async () => {
    const host = container.querySelector('#keygen-host').value.trim();
    const user = container.querySelector('#keygen-user').value.trim();
    const pass = container.querySelector('#keygen-pass').value.trim();
    if (!validate([['Host', host], ['Username', user], ['Password', pass]])) return;

    container.querySelector('#keygen-status').textContent = 'Generating...';
    container.querySelector('#keygen-status').style.color = 'var(--text-muted)';
    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'GET',
          url: `https://${host}/api/`,
          params: { type: 'keygen', user, password: pass },
          headers: {},
          json_body: null,
        }
      });

      if (result.body) {
        const match = result.body.match(/<key>(.*?)<\/key>/);
        if (match) {
          const key = match[1];
          container.querySelector('#keygen-result').style.display = 'block';
          container.querySelector('#keygen-key-output').value = key;
          container.querySelector('#keygen-status').textContent = '✓ Key generated!';
          container.querySelector('#keygen-status').style.color = 'var(--accent-green)';
          if (!container.querySelector('#pa-host').value) setField('#pa-host', host);
        } else {
          container.querySelector('#keygen-status').textContent = '✗ Could not parse key from response';
          container.querySelector('#keygen-status').style.color = 'var(--accent-red)';
          showResponse(result.body, false);
        }
      } else {
        container.querySelector('#keygen-status').textContent = '✗ No response';
        container.querySelector('#keygen-status').style.color = 'var(--accent-red)';
      }
    } catch (err) {
      container.querySelector('#keygen-status').textContent = `✗ ${err.message}`;
      container.querySelector('#keygen-status').style.color = 'var(--accent-red)';
    }
  };

  container.querySelector('#btn-keygen-copy').onclick = () => {
    navigator.clipboard.writeText(container.querySelector('#keygen-key-output').value).then(() => toast('Key copied!', 'success'));
  };

  container.querySelector('#btn-keygen-use').onclick = () => {
    const key = container.querySelector('#keygen-key-output').value;
    setField('#pa-key', key);
    toast('API key applied to connection settings', 'success');
  };

  // ===== LOAD FROM ALLOWED FLOWS =====
  container.querySelector('#btn-load-from-flows').onclick = async () => {
    try {
      const targetStr = container.querySelector('#pan-target')?.value?.trim();
      const vsysStr = container.querySelector('#pan-target-vsys')?.value?.trim();
      const vsysList = vsysStr ? vsysStr.split(',').map(s => s.trim()).filter(Boolean) : [];

      const targetDevices = targetStr ? targetStr.split(',').map(s => {
        const d = { name: s.trim() };
        if (vsysList.length > 0) d.vsys = vsysList;
        return d;
      }).filter(d => d.name) : [];

      const result = await api(`/api/devices/${device.id}/panos/rules-from-flows`, {
        method: 'POST',
        body: { variables: { target_devices: targetDevices } }
      });
      if (result.entry) {
        const e = result.entry;
        setField('#rule-name', e['@name'] || '');
        setField('#rule-source', (e.source?.member || []).join(', '));
        setField('#rule-dest', (e.destination?.member || []).join(', '));
        setField('#rule-service', (e.service?.member || []).join(', '));
        setField('#rule-app', (e.application?.member || []).join(', '));
        setField('#rule-tags', (e.tag?.member || []).join(', '));

        // Populate target devices back if there are any returned in the entry
        if (e.target?.devices?.entry) {
          const targets = e.target.devices.entry.map(d => d['@name']).join(', ');
          if (container.querySelector('#pan-target')) {
            setField('#pan-target', targets);
          }

          const firstTargetWithVsys = e.target.devices.entry.find(d => d.vsys && d.vsys.entry && d.vsys.entry.length > 0);
          if (firstTargetWithVsys && container.querySelector('#pan-target-vsys')) {
            const vsys = firstTargetWithVsys.vsys.entry.map(v => v['@name']).join(', ');
            setField('#pan-target-vsys', vsys);
          }
        }

        const stats = result.stats || {};
        toast(`Loaded: ${stats.allowed_flows || 0} flows → ${stats.unique_destinations || 0} destinations, ${stats.unique_services || 0} services`, 'success');
      }
    } catch (err) { toast(err.message, 'error'); }
  };

  // ========================================
  //  FIREWALL TAB
  // ========================================
  container.querySelector('#btn-fw-preview').onclick = () => {
    const c = getConn();
    const vsys = container.querySelector('#fw-vsys').value.trim();
    const name = container.querySelector('#rule-name').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key], ['VSYS', vsys], ['Rule Name', name]])) return;

    const url = `https://${c.host}/restapi/v${c.version}/Policies/SecurityRules?name=${encodeURIComponent(name)}&location=vsys&vsys=${encodeURIComponent(vsys)}`;
    const headers = `X-PAN-KEY: ${c.key}\nContent-Type: application/json\nAccept: application/json`;
    const body = JSON.stringify(getRuleBody(), null, 2);
    previewBlock('#fw-preview', [
      { label: 'POST URL', text: url },
      { label: 'Headers', text: headers },
      { label: 'Body', text: body },
    ]);
  };

  container.querySelector('#btn-fw-push').onclick = async () => {
    const c = getConn();
    const vsys = container.querySelector('#fw-vsys').value.trim();
    const name = container.querySelector('#rule-name').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key], ['VSYS', vsys], ['Rule Name', name]])) return;

    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'POST',
          url: `https://${c.host}/restapi/v${c.version}/Policies/SecurityRules`,
          params: { name, location: 'vsys', vsys },
          headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          json_body: getRuleBody(),
        }
      });
      showResponse(result.body, result.success);

      // If push succeeded, move rule before DENY-ANY-ANY
      if (result.success) {
        try {
          await api('/api/panos/proxy', {
            method: 'POST', body: {
              http_method: 'POST',
              url: `https://${c.host}/restapi/v${c.version}/Policies/SecurityRules:move`,
              params: { name, location: 'vsys', vsys, where: 'before', dst: 'DENY-ANY-ANY' },
              headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
              json_body: null,
            }
          });
          toast('Rule moved above DENY-ANY-ANY', 'success');
        } catch (_) {
          // DENY-ANY-ANY may not exist — silently ignore
          toast('Rule pushed (could not move above DENY-ANY-ANY — rule may not exist)', 'info');
        }
      }
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-fw-commit').onclick = async () => {
    const c = getConn();
    const vsys = container.querySelector('#fw-vsys').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key]])) return;

    const commitBody = {
      entry: {
        partial: vsys ? {
          vsys: { member: [vsys] },
          'device-and-network': 'excluded',
          'shared-object': 'excluded',
        } : {},
      },
    };

    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'POST',
          url: `https://${c.host}/restapi/v${c.version}/System/Configuration:commit`,
          params: {},
          headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          json_body: commitBody,
        }
      });
      showResponse(result.body, result.success);
    } catch (err) { toast(err.message, 'error'); }
  };

  // ========================================
  //  PANORAMA TAB
  // ========================================
  container.querySelector('#btn-pan-preview').onclick = () => {
    const c = getConn();
    const dg = container.querySelector('#pan-dg').value.trim();
    const name = container.querySelector('#rule-name').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key], ['Device Group', dg], ['Rule Name', name]])) return;

    const url = `https://${c.host}/restapi/v${c.version}/Policies/SecurityPostRules?name=${encodeURIComponent(name)}&location=device-group&device-group=${encodeURIComponent(dg)}`;
    const headers = `X-PAN-KEY: ${c.key}\nContent-Type: application/json\nAccept: application/json`;
    const body = JSON.stringify(getPostRuleBody(), null, 2);
    previewBlock('#pan-preview', [
      { label: 'Step 1 — POST Post-Rule', text: url },
      { label: 'Headers', text: headers },
      { label: 'Body', text: body },
      { label: 'Step 2 — Commit to Panorama', text: `POST https://${c.host}/restapi/v${c.version}/System/Configuration:commit` },
      { label: 'Step 3 — Push to Device Group', text: `POST https://${c.host}/restapi/v${c.version}/Panorama/ScheduledConfigPushProfiles?name=${encodeURIComponent(name + '-push')}` },
    ]);
  };

  container.querySelector('#btn-pan-push').onclick = async () => {
    const c = getConn();
    const dg = container.querySelector('#pan-dg').value.trim();
    const name = container.querySelector('#rule-name').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key], ['Device Group', dg], ['Rule Name', name]])) return;

    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'POST',
          url: `https://${c.host}/restapi/v${c.version}/Policies/SecurityPostRules`,
          params: { name, location: 'device-group', 'device-group': dg },
          headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          json_body: getPostRuleBody(),
        }
      });
      showResponse(result.body, result.success);

      // If push succeeded, move the rule before DENY-ANY-ANY
      if (result.success) {
        try {
          await api('/api/panos/proxy', {
            method: 'POST', body: {
              http_method: 'POST',
              url: `https://${c.host}/restapi/v${c.version}/Policies/SecurityPostRules:move`,
              params: { name, location: 'device-group', 'device-group': dg, where: 'before', dst: 'DENY-ANY-ANY' },
              headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
              json_body: null,
            }
          });
          toast('Rule moved above DENY-ANY-ANY', 'success');
        } catch (_) {
          // DENY-ANY-ANY may not exist — silently ignore
          toast('Rule pushed (could not move above DENY-ANY-ANY — rule may not exist)', 'info');
        }
      }
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-pan-commit').onclick = async () => {
    const c = getConn();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key]])) return;

    const commitBody = {
      entry: {
        partial: {
          'device-and-network': 'excluded',
          'shared-object': 'excluded',
        },
      },
    };

    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'POST',
          url: `https://${c.host}/restapi/v${c.version}/System/Configuration:commit`,
          params: {},
          headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          json_body: commitBody,
        }
      });
      showResponse(result.body, result.success);
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-pan-push-dg').onclick = async () => {
    const c = getConn();
    const dg = container.querySelector('#pan-dg').value.trim();
    const name = container.querySelector('#rule-name').value.trim();
    if (!validate([['Host', c.host], ['Version', c.version], ['API Key', c.key], ['Device Group', dg]])) return;

    const pushBody = {
      entry: {
        '@name': (name || 'iot') + '-push',
        'one-time': {
          'shared-policy-push': {
            'device-group': { member: [dg] },
            'merge-with-candidate-cfg': 'yes',
            'include-template': 'no',
          },
        },
      },
    };

    try {
      const result = await api('/api/panos/proxy', {
        method: 'POST', body: {
          http_method: 'POST',
          url: `https://${c.host}/restapi/v${c.version}/Panorama/ScheduledConfigPushProfiles`,
          params: { name: (name || 'iot') + '-push' },
          headers: { 'X-PAN-KEY': c.key, 'Content-Type': 'application/json', Accept: 'application/json' },
          json_body: pushBody,
        }
      });
      showResponse(result.body, result.success);
    } catch (err) { toast(err.message, 'error'); }
  };
}
