// ---- Firewall Rules Page ----
import { api, toast, state } from '../main.js';

export async function renderRules(container) {
    const device = state.activeDevice;
    if (!device) {
        container.innerHTML = `<div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> first.</p></div>`;
        return;
    }

    container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Palo Alto Firewall Rules</h1>
      <p class="page-subtitle">Generate firewall rules for <strong>${device.name}</strong></p>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <span class="card-title">Variables & Context</span>
      </div>
      <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:16px;">Configure variables for your Palo Alto firewall context. These are used as template variables in the generated rules.</p>
      <div class="var-panel">
        <div class="form-group">
          <label class="form-label">Device Zone</label>
          <input class="form-input var-input" id="v-device-zone" value="IoT" data-var="device_zone" />
        </div>
        <div class="form-group">
          <label class="form-label">Server / Dest Zone</label>
          <input class="form-input var-input" id="v-server-zone" value="Trust" data-var="server_zone" />
        </div>
        <div class="form-group">
          <label class="form-label">Internet Zone</label>
          <input class="form-input var-input" id="v-internet-zone" value="Untrust" data-var="internet_zone" />
        </div>
        <div class="form-group">
          <label class="form-label">VSYS</label>
          <input class="form-input var-input" id="v-vsys" value="vsys1" data-var="vsys" />
        </div>
        <div class="form-group">
          <label class="form-label">Firewall Context</label>
          <input class="form-input var-input" id="v-context" value="PA-DEFAULT" data-var="firewall_context" placeholder="e.g. PA-SITE-A" />
        </div>
        <div class="form-group">
          <label class="form-label">Tag</label>
          <input class="form-input var-input" id="v-tag" value="iot-onboarding" data-var="tag" />
        </div>
        <div class="form-group">
          <label class="form-label">Address Prefix</label>
          <input class="form-input var-input" id="v-addr-prefix" value="IoT" data-var="address_prefix" />
        </div>
        <div class="form-group">
          <label class="form-label">Rule Prefix</label>
          <input class="form-input var-input" id="v-rule-prefix" value="IoT" data-var="rule_prefix" />
        </div>
      </div>
    </div>

    <div class="export-bar">
      <button class="btn btn-primary" id="btn-gen-set">Generate Set Commands</button>
      <button class="btn btn-secondary" id="btn-gen-xml">Generate XML API</button>
      <button class="btn btn-secondary" id="btn-gen-csv">Generate CSV</button>
      <button class="btn btn-ghost" id="btn-copy" style="margin-left:auto;">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/><path d="M11 5V3.5A1.5 1.5 0 009.5 2h-6A1.5 1.5 0 002 3.5v6A1.5 1.5 0 003.5 11H5" stroke="currentColor" stroke-width="1.5"/></svg>
        Copy to Clipboard
      </button>
    </div>

    <div class="rule-preview" id="rule-preview">
      <span style="color:var(--text-muted);">Click a generate button above to preview rules...</span>
    </div>

    <div class="card" style="margin-top:24px;">
      <div class="card-header">
        <span class="card-title">Previous Exports</span>
      </div>
      <div id="exports-list"></div>
    </div>

    <div class="card" style="margin-top:20px;opacity:0.5;">
      <div class="card-header">
        <span class="card-title">ServiceNow Integration</span>
        <span class="coming-soon">🔒 Coming Soon</span>
      </div>
      <p style="color:var(--text-muted);font-size:0.9rem;">Create a change request in ServiceNow with the generated firewall rules for approval and deployment tracking.</p>
    </div>
  `;

    function getVariables() {
        const vars = {};
        container.querySelectorAll('.var-input').forEach(input => {
            vars[input.dataset.var] = input.value.trim();
        });
        vars.device_name = device.name.replace(/\s+/g, '-').toLowerCase();
        return vars;
    }

    async function generateRules(format) {
        const preview = container.querySelector('#rule-preview');
        preview.textContent = 'Generating...';
        try {
            const result = await api(`/api/devices/${device.id}/generate-rules`, {
                method: 'POST',
                body: { format, variables: getVariables() },
            });
            preview.textContent = result.rules_text;
            toast(`Rules generated (${result.flow_count} flows)`, 'success');
            loadExports();
        } catch (err) {
            preview.textContent = `Error: ${err.message}`;
            toast(err.message, 'error');
        }
    }

    container.querySelector('#btn-gen-set').onclick = () => generateRules('set_commands');
    container.querySelector('#btn-gen-xml').onclick = () => generateRules('xml_api');
    container.querySelector('#btn-gen-csv').onclick = () => generateRules('csv');

    container.querySelector('#btn-copy').onclick = () => {
        const text = container.querySelector('#rule-preview').textContent;
        navigator.clipboard.writeText(text).then(() => {
            toast('Copied to clipboard!', 'success');
        });
    };

    async function loadExports() {
        try {
            const exports = await api(`/api/devices/${device.id}/exports`);
            const list = container.querySelector('#exports-list');
            if (exports.length === 0) {
                list.innerHTML = '<p style="color:var(--text-muted);font-size:0.9rem;">No exports yet.</p>';
                return;
            }
            list.innerHTML = `
        <div class="table-container">
          <table class="data-table">
            <thead><tr><th>ID</th><th>Format</th><th>Created</th><th>Actions</th></tr></thead>
            <tbody>
              ${exports.map(e => `
                <tr>
                  <td>${e.id}</td>
                  <td>${e.format}</td>
                  <td>${new Date(e.created_at).toLocaleString()}</td>
                  <td><button class="btn btn-ghost btn-sm view-export-btn" data-id="${e.id}">View</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
            list.querySelectorAll('.view-export-btn').forEach(btn => {
                btn.onclick = async () => {
                    try {
                        const exp = await api(`/api/devices/${device.id}/exports/${btn.dataset.id}`);
                        container.querySelector('#rule-preview').textContent = exp.rules_text;
                    } catch (err) { toast(err.message, 'error'); }
                };
            });
        } catch (e) { /* ignore */ }
    }

    await loadExports();
}
