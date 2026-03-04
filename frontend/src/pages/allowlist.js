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
        <button class="btn btn-secondary btn-sm" id="btn-allow-all">✓ Allow All</button>
        <button class="btn btn-secondary btn-sm" id="btn-deny-all">✗ Deny All</button>
        <button class="btn btn-success" id="btn-generate-rules">Generate Rules →</button>
      </div>
    </div>

    <div id="service-groups" class="stats-row" style="margin-bottom:20px;"></div>
    <div id="flow-table-container"></div>
  `;

    let allFlows = [];

    async function loadFlows() {
        try {
            allFlows = await api(`/api/devices/${device.id}/flows`);
            renderFlowTable(allFlows);
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
                    const group = card.dataset.group;
                    const filtered = allFlows.filter(f => f.service_group === group);
                    renderFlowTable(filtered);
                };
            });
        } catch (e) { /* ignore */ }
    }

    function renderFlowTable(flows) {
        const wrap = container.querySelector('#flow-table-container');
        if (flows.length === 0) {
            wrap.innerHTML = '<div class="empty-state"><h3>No flows</h3></div>';
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
              <th>Source</th><th>Destination</th><th>Port</th><th>Proto</th><th>App</th><th>DNS/SNI</th><th>Data</th><th>Conns</th><th>Status</th><th>Notes</th>
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
                    } else {
                        badge.className = 'status-badge status-new';
                        badge.textContent = 'DENY';
                    }
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
                } catch (e) { /* ignore */ }
            };
        });

        // Group check all
        wrap.querySelectorAll('.group-check').forEach(gc => {
            gc.onchange = () => {
                const group = gc.dataset.group;
                wrap.querySelectorAll(`.flow-check`).forEach(fc => {
                    const row = fc.closest('tr');
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
                    toast(`Allowed ${ids.length} ${group} flows`, 'success');
                    await loadFlows();
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
            toast('All flows allowed', 'success');
            await loadFlows();
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
            toast('All flows denied', 'success');
            await loadFlows();
        } catch (err) { toast(err.message, 'error'); }
    };

    container.querySelector('#btn-generate-rules').onclick = () => navigate('/panos');

    await loadFlows();
}
