// ---- Analysis Page ----
import { api, toast, state, navigate, formatBytes } from '../main.js';

const PROTOCOL_COLORS = [
  '#6366f1', '#06b6d4', '#10b981', '#f59e0b', '#ef4444',
  '#a855f7', '#ec4899', '#14b8a6', '#f97316', '#8b5cf6',
];

export async function renderAnalysis(container) {
  const device = state.activeDevice;
  const capture = state.activeCapture;

  if (!device) {
    container.innerHTML = `<div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> first.</p></div>`;
    return;
  }

  container.innerHTML = `
    <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-start;">
      <div>
        <h1 class="page-title">Network Analysis</h1>
        <p class="page-subtitle">Zeek analysis for <strong>${device.name}</strong>${capture ? ` — Capture ${capture.id}` : ''}</p>
      </div>
      <button class="btn btn-danger btn-sm" id="btn-clear-flows" title="Delete all extracted flows and start fresh">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style="margin-right:4px;"><path d="M1.75 3.5h10.5M5.25 3.5V2.333A.583.583 0 015.833 1.75h2.334a.583.583 0 01.583.583V3.5m1.75 0v8.167a.583.583 0 01-.583.583H4.083a.583.583 0 01-.583-.583V3.5h7m-4.667 2.333v4.084m2.334-4.084v4.084" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Clear All Flows
      </button>
    </div>

    <div id="capture-select" class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <span class="card-title">Select Capture to Analyze</span>
      </div>
      <div id="capture-list-for-analysis"></div>
    </div>

    <div id="analysis-results" style="display:none;">
      <div class="stats-row" id="analysis-stats"></div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
        <div class="card">
          <div class="card-header"><span class="card-title">Protocol Distribution</span></div>
          <div class="protocol-bars" id="protocol-chart"></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">Service Breakdown</span></div>
          <div class="protocol-bars" id="service-chart"></div>
        </div>
      </div>

      <div class="card" style="margin-bottom:20px;">
        <div class="card-header">
          <span class="card-title">Connections</span>
          <button class="btn btn-success btn-sm" id="btn-extract-flows">Extract Flows →</button>
        </div>
        <div class="filter-bar" id="conn-filters">
          <div class="form-group">
            <label class="form-label">Protocol</label>
            <select class="form-select" id="f-proto"><option value="">All</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
          </div>
          <div class="form-group">
            <label class="form-label">Source IP</label>
            <input class="form-input" id="f-src" placeholder="Filter..." />
          </div>
          <div class="form-group">
            <label class="form-label">Dest IP</label>
            <input class="form-input" id="f-dst" placeholder="Filter..." />
          </div>
          <div class="form-group">
            <label class="form-label">Dest Port</label>
            <input class="form-input" id="f-port" placeholder="e.g. 443" type="number" />
          </div>
          <div class="form-group">
            <label class="form-label">Service</label>
            <input class="form-input" id="f-svc" placeholder="e.g. dns" />
          </div>
          <div class="form-group">
            <label class="form-label">Source MAC</label>
            <input class="form-input" id="f-mac" placeholder="e.g. AA:BB:CC:DD:EE:FF" />
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-filter" style="align-self:flex-end;">Apply</button>
        </div>
        <div class="table-container" style="max-height:400px;overflow-y:auto;" id="conn-table-wrap"></div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
        <div class="card">
          <div class="card-header"><span class="card-title">DNS Queries</span></div>
          <div class="table-container" style="max-height:300px;overflow-y:auto;" id="dns-table"></div>
        </div>
        <div class="card">
          <div class="card-header"><span class="card-title">TLS/SSL Connections</span></div>
          <div class="table-container" style="max-height:300px;overflow-y:auto;" id="ssl-table"></div>
        </div>
      </div>

      <div class="card" id="ot-section" style="display:none;margin-bottom:20px;">
        <div class="card-header"><span class="card-title">OT / Industrial Protocols</span></div>
        <div id="ot-tables"></div>
      </div>
    </div>
  `;

  // ----- Clear All Flows button -----
  container.querySelector('#btn-clear-flows').onclick = async () => {
    if (!confirm('Delete ALL extracted flows for this device? This cannot be undone.')) return;
    try {
      const result = await api(`/api/devices/${device.id}/flows`, { method: 'DELETE' });
      toast(`Cleared ${result.deleted} flows`, 'success');
    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // ----- DNS reverse-lookup map (IP -> domain) -----
  let dnsMap = {};

  // Load captures for selection
  async function loadCaptures() {
    try {
      const captures = await api(`/api/devices/${device.id}/captures`);
      const list = container.querySelector('#capture-list-for-analysis');
      if (captures.length === 0) {
        list.innerHTML = '<p style="color:var(--text-muted);">No captures available. <a href="#/capture">Start a capture</a> first.</p>';
        return;
      }
      list.innerHTML = captures.map(c => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border-color);">
          <div>
            <strong>${c.id}</strong> — ${c.interface} — ${c.packet_count.toLocaleString()} packets — ${formatBytes(c.file_size)}
            <span style="color:var(--text-muted);font-size:0.82rem;margin-left:8px;">${new Date(c.started_at).toLocaleString()}</span>
          </div>
          <button class="btn btn-primary btn-sm run-analysis-btn" data-id="${c.id}">Run Zeek Analysis</button>
        </div>
      `).join('');

      list.querySelectorAll('.run-analysis-btn').forEach(btn => {
        btn.onclick = async () => {
          state.activeCapture = { id: btn.dataset.id };
          btn.textContent = 'Analyzing...';
          btn.disabled = true;
          try {
            await api(`/api/devices/${device.id}/captures/${btn.dataset.id}/analyze`, { method: 'POST' });
            toast('Zeek analysis complete!', 'success');
            await loadAnalysis(btn.dataset.id);
          } catch (err) {
            toast(err.message, 'error');
            btn.textContent = 'Run Zeek Analysis';
            btn.disabled = false;
          }
        };
      });
    } catch (err) {
      // API unavailable
    }
  }

  async function loadAnalysis(captureId) {
    container.querySelector('#analysis-results').style.display = 'block';

    try {
      // Load DNS map for domain resolution
      try {
        const dns = await api(`/api/devices/${device.id}/captures/${captureId}/dns`);
        dnsMap = {};
        for (const d of dns) {
          const answers = d.answers || '';
          const query = d.query || '';
          if (answers && query) {
            for (const ip of String(answers).split(',')) {
              const trimmed = ip.trim();
              if (trimmed && trimmed !== '-') {
                dnsMap[trimmed] = query;
              }
            }
          }
        }
      } catch (e) { /* no DNS data */ }

      // Load summary
      const summary = await api(`/api/devices/${device.id}/captures/${captureId}/summary`);

      // Stats
      container.querySelector('#analysis-stats').innerHTML = `
        <div class="stat-card"><div class="stat-value">${(summary.total_connections || 0).toLocaleString()}</div><div class="stat-label">Connections</div></div>
        <div class="stat-card"><div class="stat-value">${formatBytes(summary.total_bytes)}</div><div class="stat-label">Total Data</div></div>
        <div class="stat-card"><div class="stat-value">${Object.keys(summary.services || {}).length}</div><div class="stat-label">Services</div></div>
        <div class="stat-card"><div class="stat-value">${(summary.ot_protocols || []).length}</div><div class="stat-label">OT Protocols</div></div>
      `;

      // Protocol chart
      const protos = summary.protocols || {};
      const maxProto = Math.max(...Object.values(protos), 1);
      container.querySelector('#protocol-chart').innerHTML = Object.entries(protos)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([name, count], i) => `
          <div class="protocol-bar-row">
            <span class="protocol-bar-label">${name}</span>
            <div class="protocol-bar-track">
              <div class="protocol-bar-fill" style="width:${(count / maxProto * 100)}%;background:${PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]}">${count}</div>
            </div>
          </div>
        `).join('');

      // Service chart
      const svcs = summary.services || {};
      const maxSvc = Math.max(...Object.values(svcs), 1);
      container.querySelector('#service-chart').innerHTML = Object.entries(svcs)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([name, count], i) => `
          <div class="protocol-bar-row">
            <span class="protocol-bar-label">${name}</span>
            <div class="protocol-bar-track">
              <div class="protocol-bar-fill" style="width:${(count / maxSvc * 100)}%;background:${PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]}">${count}</div>
            </div>
          </div>
        `).join('');

      // Load connections
      await loadConnections(captureId);

      // Load DNS table
      try {
        const dns = await api(`/api/devices/${device.id}/captures/${captureId}/dns`);
        const dnsEl = container.querySelector('#dns-table');
        if (dns.length > 0) {
          dnsEl.innerHTML = `<table class="data-table"><thead><tr><th>Query</th><th>Type</th><th>Answers</th></tr></thead><tbody>
            ${dns.slice(0, 100).map(d => `<tr><td>${d.query || ''}</td><td>${d.qtype_name || d.qtype || ''}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">${d.answers || ''}</td></tr>`).join('')}
          </tbody></table>`;
        } else {
          dnsEl.innerHTML = '<p style="color:var(--text-muted);padding:12px;">No DNS queries found.</p>';
        }
      } catch (e) { /* ignore */ }

      // Load SSL
      try {
        const ssl = await api(`/api/devices/${device.id}/captures/${captureId}/ssl`);
        const sslEl = container.querySelector('#ssl-table');
        if (ssl.length > 0) {
          sslEl.innerHTML = `<table class="data-table"><thead><tr><th>Server Name</th><th>Dest IP</th><th>Port</th><th>Version</th></tr></thead><tbody>
            ${ssl.slice(0, 100).map(s => `<tr><td>${s.server_name || '-'}</td><td>${s['id.resp_h'] || ''}</td><td>${s['id.resp_p'] || ''}</td><td>${s.version || ''}</td></tr>`).join('')}
          </tbody></table>`;
        } else {
          sslEl.innerHTML = '<p style="color:var(--text-muted);padding:12px;">No TLS/SSL connections found.</p>';
        }
      } catch (e) { /* ignore */ }

      // Load OT
      try {
        const ot = await api(`/api/devices/${device.id}/captures/${captureId}/ot`);
        if (Object.keys(ot).length > 0) {
          const otSection = container.querySelector('#ot-section');
          otSection.style.display = 'block';
          const otTables = container.querySelector('#ot-tables');
          otTables.innerHTML = '';
          for (const [proto, records] of Object.entries(ot)) {
            if (records.length === 0) continue;
            const keys = Object.keys(records[0]).slice(0, 6);
            otTables.innerHTML += `
              <h4 style="margin:12px 0 8px;color:var(--accent-amber);text-transform:uppercase;font-size:0.85rem;">${proto} (${records.length} records)</h4>
              <div class="table-container" style="max-height:200px;overflow-y:auto;margin-bottom:12px;">
                <table class="data-table"><thead><tr>${keys.map(k => `<th>${k}</th>`).join('')}</tr></thead>
                <tbody>${records.slice(0, 50).map(r => `<tr>${keys.map(k => `<td>${r[k] || ''}</td>`).join('')}</tr>`).join('')}</tbody>
                </table>
              </div>
            `;
          }
        }
      } catch (e) { /* ignore */ }

      // Extract flows button
      container.querySelector('#btn-extract-flows').onclick = async () => {
        try {
          const result = await api(`/api/devices/${device.id}/captures/${captureId}/extract-flows`, { method: 'POST' });
          toast(`${result.total_flows} flows (${result.new_flows} new, ${result.merged_flows} merged)`, 'success');
          navigate('/allowlist');
        } catch (err) {
          toast(err.message, 'error');
        }
      };

    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function loadConnections(captureId, filters = {}) {
    try {
      const params = new URLSearchParams();
      if (filters.protocol) params.set('protocol', filters.protocol);
      if (filters.src_ip) params.set('src_ip', filters.src_ip);
      if (filters.dst_ip) params.set('dst_ip', filters.dst_ip);
      if (filters.dst_port) params.set('dst_port', filters.dst_port);
      if (filters.service) params.set('service', filters.service);
      if (filters.src_mac) params.set('src_mac', filters.src_mac);
      params.set('limit', '200');

      const data = await api(`/api/devices/${device.id}/captures/${captureId}/connections?${params}`);
      const wrap = container.querySelector('#conn-table-wrap');
      wrap.innerHTML = `
        <table class="data-table">
          <thead><tr><th>Source</th><th>Dest</th><th>Domain</th><th>Port</th><th>Proto</th><th>Service</th><th>Duration</th><th>Bytes</th></tr></thead>
          <tbody>
            ${data.records.slice(0, 200).map(c => {
        const dstIp = c['id.resp_h'] || '';
        const domain = c['server_name'] || dnsMap[dstIp] || '';
        return `
              <tr>
                <td>${c['id.orig_h'] || ''}</td>
                <td>${dstIp}</td>
                <td style="color:var(--accent-amber);max-width:160px;overflow:hidden;text-overflow:ellipsis;" title="${domain}">${domain || '-'}</td>
                <td>${c['id.resp_p'] || ''}</td>
                <td>${c.proto || ''}</td>
                <td>${c.service || '-'}</td>
                <td>${c.duration ? parseFloat(c.duration).toFixed(1) + 's' : '-'}</td>
                <td>${formatBytes((parseInt(c.orig_bytes) || 0) + (parseInt(c.resp_bytes) || 0))}</td>
              </tr>
            `}).join('')}
          </tbody>
        </table>
        <p style="color:var(--text-muted);font-size:0.8rem;padding:8px 14px;">Showing ${Math.min(200, data.records.length)} of ${data.total} connections</p>
      `;

      // Filter handler
      container.querySelector('#btn-filter').onclick = () => {
        loadConnections(captureId, {
          protocol: container.querySelector('#f-proto').value,
          src_ip: container.querySelector('#f-src').value.trim(),
          dst_ip: container.querySelector('#f-dst').value.trim(),
          dst_port: container.querySelector('#f-port').value,
          service: container.querySelector('#f-svc').value.trim(),
          src_mac: container.querySelector('#f-mac').value.trim(),
        });
      };
    } catch (err) { /* ignore */ }
  }

  await loadCaptures();

  // Auto-load if we already have a capture selected
  if (capture) {
    try {
      await loadAnalysis(capture.id);
    } catch (e) { /* need to run analysis first */ }
  }
}
