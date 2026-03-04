// ---- Devices Page (Landing / Device Profile Library) ----
import { api, toast, navigate, setActiveDevice, timeAgo } from '../main.js';

function statusClass(status) {
    return `status-badge status-${status}`;
}

function statusLabel(status) {
    const map = {
        new: '● New',
        capturing: '◉ Capturing',
        captured: '◉ Captured',
        analyzed: '◈ Analyzed',
        flows_extracted: '◈ Flows Ready',
        reviewed: '✓ Reviewed',
        rules_generated: '✓ Rules Ready',
    };
    return map[status] || status;
}

function renderNewDeviceModal(container, onCreated) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
    <div class="modal-content">
      <h2 class="modal-title">New Device Profile</h2>
      <div class="form-group">
        <label class="form-label">Device Name *</label>
        <input class="form-input" id="md-name" placeholder="e.g. Siemens S7-1200 PLC" required />
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Type</label>
          <select class="form-select" id="md-type">
            <option value="">Select type...</option>
            <option value="PLC">PLC</option>
            <option value="HMI">HMI</option>
            <option value="RTU">RTU</option>
            <option value="Sensor">Sensor</option>
            <option value="Actuator">Actuator</option>
            <option value="Gateway">Gateway</option>
            <option value="Camera">Camera</option>
            <option value="Medical">Medical Device</option>
            <option value="HVAC">HVAC Controller</option>
            <option value="Meter">Smart Meter</option>
            <option value="Other">Other</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">Vendor</label>
          <input class="form-input" id="md-vendor" placeholder="e.g. Siemens" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">MAC Address</label>
          <input class="form-input" id="md-mac" placeholder="AA:BB:CC:DD:EE:FF" />
        </div>
        <div class="form-group">
          <label class="form-label">IP Address</label>
          <input class="form-input" id="md-ip" placeholder="10.0.0.100" />
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Description / Notes</label>
        <textarea class="form-textarea" id="md-desc" placeholder="Location, purpose, firmware version..."></textarea>
      </div>
      <div class="modal-actions">
        <button class="btn btn-secondary" id="md-cancel">Cancel</button>
        <button class="btn btn-primary" id="md-submit">Create Device</button>
      </div>
    </div>
  `;

    document.getElementById('modal-root').appendChild(overlay);

    overlay.querySelector('#md-cancel').onclick = () => overlay.remove();
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });

    overlay.querySelector('#md-submit').onclick = async () => {
        const name = overlay.querySelector('#md-name').value.trim();
        if (!name) { toast('Device name is required', 'error'); return; }

        try {
            const device = await api('/api/devices', {
                method: 'POST',
                body: {
                    name,
                    device_type: overlay.querySelector('#md-type').value,
                    vendor: overlay.querySelector('#md-vendor').value.trim(),
                    mac_address: overlay.querySelector('#md-mac').value.trim(),
                    ip_address: overlay.querySelector('#md-ip').value.trim(),
                    description: overlay.querySelector('#md-desc').value.trim(),
                },
            });
            overlay.remove();
            toast('Device profile created!', 'success');
            onCreated(device);
        } catch (err) {
            toast(err.message, 'error');
        }
    };
}

export async function renderDevices(container) {
    container.innerHTML = `
    <div class="page-header" style="display:flex;justify-content:space-between;align-items:flex-start;">
      <div>
        <h1 class="page-title">Device Profiles</h1>
        <p class="page-subtitle">IoT/OT device onboarding library — click a device to continue its workflow</p>
      </div>
      <button class="btn btn-primary btn-lg" id="btn-new-device">
        <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><path d="M9 4v10M4 9h10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        New Device
      </button>
    </div>
    <div id="device-stats" class="stats-row" style="display:none;"></div>
    <div id="device-list"></div>
  `;

    const listEl = container.querySelector('#device-list');
    const statsEl = container.querySelector('#device-stats');

    async function loadDevices() {
        try {
            const devices = await api('/api/devices');

            if (devices.length > 0) {
                const total = devices.length;
                const rulesReady = devices.filter(d => d.status === 'rules_generated').length;
                const inProgress = devices.filter(d => !['new', 'rules_generated'].includes(d.status)).length;

                statsEl.style.display = 'grid';
                statsEl.innerHTML = `
          <div class="stat-card"><div class="stat-value">${total}</div><div class="stat-label">Total Devices</div></div>
          <div class="stat-card"><div class="stat-value">${rulesReady}</div><div class="stat-label">Rules Generated</div></div>
          <div class="stat-card"><div class="stat-value">${inProgress}</div><div class="stat-label">In Progress</div></div>
        `;
            }

            if (devices.length === 0) {
                listEl.innerHTML = `
          <div class="empty-state">
            <svg width="64" height="64" viewBox="0 0 64 64" fill="none"><rect x="8" y="12" width="48" height="40" rx="4" stroke="currentColor" stroke-width="2"/><circle cx="32" cy="32" r="8" stroke="currentColor" stroke-width="2"/><path d="M32 24v-8M32 48v-8M24 32h-8M48 32h-8" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            <h3>No devices yet</h3>
            <p>Start by creating a new device profile to begin the onboarding process.</p>
          </div>
        `;
                return;
            }

            listEl.innerHTML = '<div class="device-grid"></div>';
            const grid = listEl.querySelector('.device-grid');

            devices.forEach(d => {
                const card = document.createElement('div');
                card.className = 'device-card';
                card.innerHTML = `
          <div class="device-card-name">${d.name}</div>
          <div class="device-card-meta">
            ${d.device_type ? `<span><strong>Type:</strong> ${d.device_type}</span>` : ''}
            ${d.vendor ? `<span><strong>Vendor:</strong> ${d.vendor}</span>` : ''}
            ${d.mac_address ? `<span><strong>MAC:</strong> ${d.mac_address}</span>` : ''}
            ${d.ip_address ? `<span><strong>IP:</strong> ${d.ip_address}</span>` : ''}
          </div>
          <div class="device-card-footer">
            <span class="${statusClass(d.status)}">${statusLabel(d.status)}</span>
            <span style="font-size:0.78rem;color:var(--text-muted)">${timeAgo(d.updated_at)}</span>
          </div>
        `;
                card.onclick = () => {
                    setActiveDevice(d);
                    navigate('/capture');
                };
                grid.appendChild(card);
            });
        } catch (err) {
            listEl.innerHTML = `<div class="empty-state"><h3>Cannot connect to backend</h3><p>${err.message}</p></div>`;
        }
    }

    container.querySelector('#btn-new-device').onclick = () => {
        renderNewDeviceModal(container, (device) => {
            setActiveDevice(device);
            navigate('/capture');
        });
    };

    await loadDevices();
}
