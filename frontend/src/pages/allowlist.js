// ---- Allow List Page ----
import { api, toast, state, navigate, formatBytes } from '../main.js';


export async function renderAllowlist(container) {
  const device = state.activeDevice;
  if (!device) {
    container.innerHTML = `<div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> first.</p></div>`;
    return;
  }

  container.innerHTML = `
    <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-start;">
      <div>
        <h1 class="page-title">Flow Allow List</h1>
        <p class="page-subtitle">Review and approve flows for <strong>${device.name}</strong></p>
      </div>
      <div style="display:flex;gap:10px;">
        <button class="btn btn-secondary btn-sm" id="btn-allow-all">Allow All</button>
        <button class="btn btn-secondary btn-sm" id="btn-deny-all">Deny All</button>
        <button class="btn btn-danger btn-sm" id="btn-clear-list" title="Delete all flows from the list">Clear Allow List</button>
        <button class="btn btn-success" id="btn-generate-rules">Generate Rules</button>
      </div>
    </div>

    <div id="service-groups" class="stats-row" style="margin-bottom:20px;"></div>

    <!-- Filter bar -->
    <div class="card" style="margin-bottom:16px;padding:12px 16px;">
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;">
        <span style="color:var(--text-muted);font-size:0.85rem;white-space:nowrap;">Filter:</span>
        <input class="form-input" id="filter-src" placeholder="Src IP" style="flex:1;min-width:120px;max-width:160px;padding:6px 10px;font-size:0.82rem;" />
        <input class="form-input" id="filter-dst" placeholder="Dst IP" style="flex:1;min-width:120px;max-width:160px;padding:6px 10px;font-size:0.82rem;" />
        <input class="form-input" id="filter-port" placeholder="Port" style="flex:1;min-width:80px;max-width:100px;padding:6px 10px;font-size:0.82rem;" />
        <input class="form-input" id="filter-proto" placeholder="Proto" style="flex:1;min-width:80px;max-width:100px;padding:6px 10px;font-size:0.82rem;" />
        <input class="form-input" id="filter-app" placeholder="App / DNS / SNI" style="flex:2;min-width:140px;max-width:220px;padding:6px 10px;font-size:0.82rem;" />
        <select class="form-select" id="filter-status" style="flex:1;min-width:100px;max-width:130px;padding:6px 10px;font-size:0.82rem;">
          <option value="">All Status</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <button class="btn btn-ghost btn-sm" id="btn-clear-filter" style="white-space:nowrap;">Clear</button>
      </div>
      <div style="margin-top:8px;font-size:0.8rem;color:var(--text-muted);" id="filter-count"></div>
    </div>

    <div id="flow-table-container"></div>
  `;

  let allFlows = [];
  let activeGroupFilter = null; // set when a service-group card is clicked

  // ---- filter helpers ----
  function getFilters() {
    return {
      src: container.querySelector('#filter-src').value.trim().toLowerCase(),
      dst: container.querySelector('#filter-dst').value.trim().toLowerCase(),
      port: container.querySelector('#filter-port').value.trim(),
      proto: container.querySelector('#filter-proto').value.trim().toLowerCase(),
      app: container.querySelector('#filter-app').value.trim().toLowerCase(),
      status: container.querySelector('#filter-status').value,
    };
  }

  function applyFilters(flows) {
    const f = getFilters();
    return flows.filter(flow => {
      if (f.src && !(flow.src_ip || '').toLowerCase().includes(f.src)) return false;
      if (f.dst && !(flow.dst_ip || '').toLowerCase().includes(f.dst)) return false;
      if (f.port && String(flow.dst_port) !== f.port) return false;
      if (f.proto && !(flow.protocol || '').toLowerCase().includes(f.proto)) return false;
      if (f.app) {
        const haystack = [flow.app_protocol, flow.dns_name, flow.sni].join(' ').toLowerCase();
        if (!haystack.includes(f.app)) return false;
      }
      if (f.status === 'allow' && !flow.allowed) return false;
      if (f.status === 'deny' && flow.allowed) return false;
      return true;
    });
  }

  function refreshTable() {
    let source = allFlows;
    if (activeGroupFilter) source = allFlows.filter(f => f.service_group === activeGroupFilter);
    const filtered = applyFilters(source);
    const countEl = container.querySelector('#filter-count');
    if (countEl) countEl.textContent = `Showing ${filtered.length} of ${allFlows.length} flows`;
    renderFlowTable(filtered);
  }

  // wire filter inputs
  ['filter-src', 'filter-dst', 'filter-port', 'filter-proto', 'filter-app', 'filter-status'].forEach(id => {
    const el = container.querySelector(`#${id}`);
    el.addEventListener('input', refreshTable);
    el.addEventListener('change', refreshTable);
  });
  container.querySelector('#btn-clear-filter').onclick = () => {
    ['filter-src', 'filter-dst', 'filter-port', 'filter-proto', 'filter-app'].forEach(id => {
      container.querySelector(`#${id}`).value = '';
    });
    container.querySelector('#filter-status').value = '';
    activeGroupFilter = null;
    refreshTable();
  };

  async function loadFlows() {
    try {
      allFlows = await api(`/api/devices/${device.id}/flows`);
      refreshTable();
      await loadServiceGroups();
    } catch (err) {
      container.querySelector('#flow-table-container').innerHTML = `
        <div class="empty-state"><h3>No flows extracted</h3><p>Go to <a href="#/analysis">Analysis</a> and extract flows first.</p></div>
      `;
    }
  }

  async function loadServiceGroups() {
    try {
      const groups = await api(`/api/devices/${device.id}/flows/service-groups`);
      const el = container.querySelector('#service-groups');
      el.innerHTML = groups.map(g => `
        <div class="stat-card" style="cursor:pointer;" data-group="${g.service_group}">
          <div class="stat-value" style="font-size:1.4rem;">${g.count}</div>
          <div class="stat-label">${g.service_group}</div>
          <div style="font-size:0.75rem;color:var(--accent-green);margin-top:2px;">${g.allowed_count || 0} allowed</div>
        </div>
      `).join('');

      el.querySelectorAll('.stat-card').forEach(card => {
        card.onclick = () => {
          // toggle: clicking same group resets
          if (activeGroupFilter === card.dataset.group) {
            activeGroupFilter = null;
            el.querySelectorAll('.stat-card').forEach(c => c.style.outline = '');
          } else {
            activeGroupFilter = card.dataset.group;
            el.querySelectorAll('.stat-card').forEach(c => c.style.outline = '');
            card.style.outline = '2px solid var(--accent-indigo)';
          }
          refreshTable();
        };
      });
    } catch (e) { /* ignore */ }
  }

  function renderFlowTable(flows) {
    const wrap = container.querySelector('#flow-table-container');
    if (flows.length === 0) {
      wrap.innerHTML = '<div class="empty-state"><h3>No flows match the current filter</h3></div>';
      return;
    }

    // Group by service_group
    const groups = {};
    flows.forEach(f => {
      const g = f.service_group || 'Other';
      if (!groups[g]) groups[g] = [];
      groups[g].push(f);
    });

    let html = '';
    for (const [group, gFlows] of Object.entries(groups)) {
      html += `
        <div class="flow-group-header">
          ${group}
          <span class="flow-group-count">${gFlows.length} flows</span>
          <button class="btn btn-ghost btn-sm allow-group-btn" data-group="${group}" style="margin-left:auto;">Allow Group</button>
        </div>
        <div class="table-container" style="margin-bottom:8px;">
          <table class="data-table">
            <thead><tr>
              <th style="width:40px;"><input type="checkbox" class="group-check" data-group="${group}" /></th>
              <th>Source</th><th>Destination</th><th>Port</th><th>Proto</th><th>App</th><th>DNS/SNI</th><th>Data</th><th>Conns</th><th>Status</th><th>Notes</th><th style="width:36px;"></th>
            </tr></thead>
            <tbody>
              ${gFlows.map(f => `
                <tr data-flow-id="${f.id}" class="${f.allowed ? '' : 'denied'}">
                  <td><input type="checkbox" class="flow-check" data-id="${f.id}" ${f.allowed ? 'checked' : ''} /></td>
                  <td>${f.src_ip}</td>
                  <td>${f.dst_ip}</td>
                  <td>${f.dst_port}</td>
                  <td>${f.protocol}</td>
                  <td style="color:var(--accent-cyan);">${f.app_protocol || '-'}</td>
                  <td style="color:var(--accent-amber);max-width:180px;overflow:hidden;text-overflow:ellipsis;">${f.dns_name || f.sni || '-'}</td>
                  <td>${formatBytes(f.bytes_total)}</td>
                  <td>${f.connection_count}</td>
                  <td><span class="${f.allowed ? 'status-badge status-reviewed' : 'status-badge status-new'}">${f.allowed ? 'ALLOW' : 'DENY'}</span></td>
                  <td><input class="form-input flow-notes" data-id="${f.id}" value="${f.notes || ''}" style="width:120px;padding:4px 8px;font-size:0.78rem;" placeholder="Notes..." /></td>
                  <td><button class="btn btn-ghost btn-sm flow-delete-btn" data-id="${f.id}" title="Remove this entry" style="color:var(--accent-red);padding:4px 6px;">Delete</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }
    wrap.innerHTML = html;

    // Checkbox handlers
    wrap.querySelectorAll('.flow-check').forEach(cb => {
      cb.onchange = async () => {
        try {
          await api(`/api/devices/${device.id}/flows/${cb.dataset.id}`, {
            method: 'PATCH',
            body: { allowed: cb.checked },
          });
          const row = cb.closest('tr');
          const badge = row.querySelector('.status-badge');
          if (cb.checked) {
            badge.className = 'status-badge status-reviewed';
            badge.textContent = 'ALLOW';
            row.classList.remove('denied');
          } else {
            badge.className = 'status-badge status-new';
            badge.textContent = 'DENY';
            row.classList.add('denied');
          }
          // sync allFlows state
          const fl = allFlows.find(f => f.id === cb.dataset.id);
          if (fl) fl.allowed = cb.checked ? 1 : 0;
        } catch (err) { toast(err.message, 'error'); }
      };
    });

    // Delete buttons
    wrap.querySelectorAll('.flow-delete-btn').forEach(btn => {
      btn.onclick = async () => {
        if (!confirm('Remove this flow entry?')) return;
        try {
          await api(`/api/devices/${device.id}/flows/${btn.dataset.id}`, { method: 'DELETE' });
          allFlows = allFlows.filter(f => f.id !== btn.dataset.id);
          toast('Flow entry removed', 'success');
          refreshTable();
          await loadServiceGroups();
        } catch (err) { toast(err.message, 'error'); }
      };
    });

    // Notes save on blur
    wrap.querySelectorAll('.flow-notes').forEach(input => {
      input.onblur = async () => {
        try {
          await api(`/api/devices/${device.id}/flows/${input.dataset.id}`, {
            method: 'PATCH',
            body: { notes: input.value },
          });
          const fl = allFlows.find(f => f.id === input.dataset.id);
          if (fl) fl.notes = input.value;
        } catch (e) { /* ignore */ }
      };
    });

    // Group check all
    wrap.querySelectorAll('.group-check').forEach(gc => {
      gc.onchange = () => {
        const group = gc.dataset.group;
        wrap.querySelectorAll(`.flow-check`).forEach(fc => {
          const table = fc.closest('.table-container');
          const header = table.previousElementSibling;
          if (header && header.querySelector(`[data-group="${group}"]`)) {
            fc.checked = gc.checked;
            fc.dispatchEvent(new Event('change'));
          }
        });
      };
    });

    // Allow group buttons
    wrap.querySelectorAll('.allow-group-btn').forEach(btn => {
      btn.onclick = async () => {
        const group = btn.dataset.group;
        const ids = allFlows.filter(f => f.service_group === group).map(f => f.id);
        try {
          await api(`/api/devices/${device.id}/flows/bulk-update`, {
            method: 'POST',
            body: { flow_ids: ids, allowed: true },
          });
          ids.forEach(id => {
            const fl = allFlows.find(f => f.id === id);
            if (fl) fl.allowed = 1;
          });
          toast(`Allowed ${ids.length} ${group} flows`, 'success');
          refreshTable();
          await loadServiceGroups();
        } catch (err) { toast(err.message, 'error'); }
      };
    });
  }

  // Allow All / Deny All
  container.querySelector('#btn-allow-all').onclick = async () => {
    const ids = allFlows.map(f => f.id);
    if (ids.length === 0) return;
    try {
      await api(`/api/devices/${device.id}/flows/bulk-update`, {
        method: 'POST',
        body: { flow_ids: ids, allowed: true },
      });
      allFlows.forEach(f => f.allowed = 1);
      toast('All flows allowed', 'success');
      refreshTable();
      await loadServiceGroups();
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-deny-all').onclick = async () => {
    const ids = allFlows.map(f => f.id);
    if (ids.length === 0) return;
    try {
      await api(`/api/devices/${device.id}/flows/bulk-update`, {
        method: 'POST',
        body: { flow_ids: ids, allowed: false },
      });
      allFlows.forEach(f => f.allowed = 0);
      toast('All flows denied', 'success');
      refreshTable();
      await loadServiceGroups();
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-clear-list').onclick = async () => {
    if (!confirm('Delete ALL flows from the allow list? This cannot be undone.')) return;
    try {
      await api(`/api/devices/${device.id}/flows`, { method: 'DELETE' });
      allFlows = [];
      toast('All flows cleared', 'success');
      refreshTable();
      await loadServiceGroups();
    } catch (err) { toast(err.message, 'error'); }
  };

  container.querySelector('#btn-generate-rules').onclick = () => navigate('/panos');

  await loadFlows();

  // ---- URL Selection Panel (from Zeek) ----
  const urlPanel = document.createElement('div');
  urlPanel.innerHTML = `
    <div class="card" style="margin-top:24px;">
      <div class="card-header" style="display:flex;justify-content:space-between;align-items:center;">
        <span class="card-title">URL / Hostname Selection</span>
        <span id="url-sel-count" style="font-size:0.8rem;color:var(--text-muted);"></span>
      </div>
      <p style="color:var(--text-muted);font-size:0.82rem;margin:0 0 12px;">
        Hostnames found by Zeek (DNS + TLS SNI). Select what you want to include in PAN-OS Step 3.
      </p>
      <div id="url-sel-body">
        <span style="color:var(--text-muted);font-size:0.85rem;">Loading hostnames from Zeek…</span>
      </div>
    </div>
  `;
  container.appendChild(urlPanel);

  function syncSelectedUrls() {
    state.selectedUrls = [...container.querySelectorAll('.url-sel-check:checked')].map(cb => cb.dataset.url);
    const badge = container.querySelector('#url-sel-count');
    badge.textContent = state.selectedUrls.length > 0 ? `${state.selectedUrls.length} selected` : '';
  }

  try {
    const data = await api(`/api/devices/${device.id}/urls`);
    const urls = data.urls || [];
    const bodyEl = container.querySelector('#url-sel-body');

    if (urls.length === 0) {
      bodyEl.innerHTML = `<p style="color:var(--text-muted);font-size:0.85rem;">
        No hostnames found yet. Run <strong>Zeek Analysis</strong> first (Analysis page).
      </p>`;
    } else {
      bodyEl.innerHTML = `
        <div style="display:flex;gap:10px;margin-bottom:10px;flex-wrap:wrap;align-items:center;">
          <button class="btn btn-ghost btn-sm" id="btn-url-all">All</button>
          <button class="btn btn-ghost btn-sm" id="btn-url-none">None</button>
          <span style="font-size:0.8rem;color:var(--text-muted);">${urls.length} unique hostname${urls.length > 1 ? 's' : ''}</span>
        </div>
        <div style="max-height:300px;overflow-y:auto;background:var(--bg-tertiary);border-radius:var(--radius-sm);padding:8px 12px;">
          ${urls.map(u => `
            <label style="display:flex;align-items:center;gap:10px;padding:5px 0;border-bottom:1px solid var(--border-color);cursor:pointer;">
              <input type="checkbox" class="url-sel-check" data-url="${u}"
                ${state.selectedUrls.includes(u) ? 'checked' : ''}
                style="cursor:pointer;accent-color:var(--accent-indigo);flex-shrink:0;" />
              <span style="font-family:var(--font-mono,monospace);font-size:0.82rem;color:var(--accent-cyan);word-break:break-all;">${u}</span>
            </label>
          `).join('')}
        </div>
      `;
      container.querySelectorAll('.url-sel-check').forEach(cb => cb.addEventListener('change', syncSelectedUrls));
      container.querySelector('#btn-url-all').onclick = () => { container.querySelectorAll('.url-sel-check').forEach(cb => cb.checked = true); syncSelectedUrls(); };
      container.querySelector('#btn-url-none').onclick = () => { container.querySelectorAll('.url-sel-check').forEach(cb => cb.checked = false); syncSelectedUrls(); };
      syncSelectedUrls();
    }
  } catch (err) {
    container.querySelector('#url-sel-body').innerHTML = `<span style="color:var(--accent-red);">✗ ${err.message}</span>`;
  }
}



