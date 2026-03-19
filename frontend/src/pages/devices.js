// ---- Devices Page (Landing / Device Profile Library) ----
import { api, toast, navigate, setActiveDevice, timeAgo } from '../main.js';

function statusClass(status) {
  return `status-badge status-${status}`;
}

function statusLabel(status) {
  const map = {
    new: 'New',
    capturing: 'Capturing',
    captured: 'Captured',
    analyzed: 'Analyzed',
    flows_extracted: 'Flows Ready',
    reviewed: 'Reviewed',
    rules_generated: 'Rules Ready',
  };
  return map[status] || status;
}

function renderNewDeviceModal(container, onCreated) {
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal-content" style="max-width:640px;max-height:90vh;overflow-y:auto;">
      <h2 class="modal-title">New Device Profile</h2>

      <div class="form-group">
        <label class="form-label">Name *</label>
        <input class="form-input" id="md-name" placeholder="e.g. Siemens S7-1200 PLC" required />
      </div>

      <!-- Required new fields -->
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">IoT Group *</label>
          <input class="form-input" id="md-iot-group" placeholder="e.g. Production-Floor" required />
        </div>
        <div class="form-group">
          <label class="form-label">Requester *</label>
          <input class="form-input" id="md-requester" placeholder="e.g. John Doe" required />
        </div>
      </div>
      <div class="form-group">
        <label class="form-label">Homologation Number *</label>
        <input class="form-input" id="md-homologation" placeholder="e.g. HOM-2024-001" required />
      </div>

      <!-- Optional device info -->
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Type</label>
          <input class="form-input" id="md-type" placeholder="e.g. PLC, HMI, Sensor..." />
        </div>
        <div class="form-group">
          <label class="form-label">Vendor</label>
          <input class="form-input" id="md-vendor" placeholder="e.g. kyocera" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Host Name</label>
          <input class="form-input" id="md-hostname" placeholder="e.g. GZYP1111" />
        </div>
        <div class="form-group">
          <label class="form-label">Site</label>
          <input class="form-input" id="md-site" placeholder="e.g. SX" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Family</label>
          <input class="form-input" id="md-family" placeholder="e.g. IID" />
        </div>
        <div class="form-group">
          <label class="form-label">Model</label>
          <input class="form-input" id="md-model" placeholder="e.g. P1200" />
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Serial Number</label>
          <input class="form-input" id="md-serial" placeholder="e.g. R4B1111111" />
        </div>
        <div class="form-group">
          <label class="form-label">FAN</label>
          <input class="form-input" id="md-fan" placeholder="FAN N°" />
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
    const iot_group = overlay.querySelector('#md-iot-group').value.trim();
    const requester = overlay.querySelector('#md-requester').value.trim();
    const homologation_number = overlay.querySelector('#md-homologation').value.trim();

    if (!name) { toast('Device name is required', 'error'); return; }
    if (!iot_group) { toast('IoT Group is required', 'error'); return; }
    if (!requester) { toast('Requester is required', 'error'); return; }
    if (!homologation_number) { toast('Homologation Number is required', 'error'); return; }

    try {
      const device = await api('/api/devices', {
        method: 'POST',
        body: {
          name,
          iot_group,
          requester,
          homologation_number,
          device_type: overlay.querySelector('#md-type').value.trim(),
          vendor: overlay.querySelector('#md-vendor').value.trim(),
          hostname: overlay.querySelector('#md-hostname').value.trim(),
          site: overlay.querySelector('#md-site').value.trim(),
          family: overlay.querySelector('#md-family').value.trim(),
          model: overlay.querySelector('#md-model').value.trim(),
          serial_number: overlay.querySelector('#md-serial').value.trim(),
          fan: overlay.querySelector('#md-fan').value.trim(),
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
            ${d.iot_group ? `<span><strong>IoT Group:</strong> ${d.iot_group}</span>` : ''}
            ${d.requester ? `<span><strong>Requester:</strong> ${d.requester}</span>` : ''}
            ${d.homologation_number ? `<span><strong>Homologation:</strong> ${d.homologation_number}</span>` : ''}
            ${d.device_type ? `<span><strong>Type:</strong> ${d.device_type}</span>` : ''}
            ${d.vendor ? `<span><strong>Vendor:</strong> ${d.vendor}</span>` : ''}
            ${d.model ? `<span><strong>Model:</strong> ${d.model}</span>` : ''}
            ${d.hostname ? `<span><strong>Host:</strong> ${d.hostname}</span>` : ''}
            ${d.site ? `<span><strong>Site:</strong> ${d.site}</span>` : ''}
            ${d.family ? `<span><strong>Family:</strong> ${d.family}</span>` : ''}
            ${d.serial_number ? `<span><strong>Serial:</strong> ${d.serial_number}</span>` : ''}
            ${d.fan ? `<span><strong>FAN:</strong> ${d.fan}</span>` : ''}
            ${d.mac_address ? `<span><strong>MAC:</strong> ${d.mac_address}</span>` : ''}
            ${d.ip_address ? `<span><strong>IP:</strong> ${d.ip_address}</span>` : ''}
          </div>
          <div class="device-card-footer">
            <span class="${statusClass(d.status)}">${statusLabel(d.status)}</span>
            <span style="font-size:0.78rem;color:var(--text-muted)">${timeAgo(d.updated_at)}</span>
            <button class="btn btn-ghost btn-sm remove-device-btn" data-id="${d.id}" title="Remove device" style="color:var(--accent-red);margin-left:auto;padding:2px 8px;">Delete</button>
          </div>
        `;

        card.onclick = (e) => {
          if (e.target.closest('.remove-device-btn')) return;
          setActiveDevice(d);
          navigate('/capture');
        };
        card.querySelector('.remove-device-btn').onclick = async (e) => {
          e.stopPropagation();
          if (!confirm(`Remove device "${d.name}"? This will also delete all its captures and flow data.`)) return;
          try {
            await api(`/api/devices/${d.id}`, { method: 'DELETE' });
            toast(`Device "${d.name}" removed`, 'success');
            await loadDevices();
          } catch (err) {
            toast(err.message, 'error');
          }
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
