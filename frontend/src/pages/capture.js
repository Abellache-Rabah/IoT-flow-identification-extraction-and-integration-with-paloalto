// ---- Capture Page (Polling-based, no WebSocket) ----
import { api, toast, state, navigate, formatBytes, formatDuration } from '../main.js';

const DURATIONS = [
  { label: '1 Hour', seconds: 3600 },
  { label: '2 Hours', seconds: 7200 },
  { label: '1 Day', seconds: 86400 },
  { label: '3 Days', seconds: 259200 },
];

export async function renderCapture(container) {
  const device = state.activeDevice;
  if (!device) {
    container.innerHTML = `<div class="empty-state"><h3>No device selected</h3><p>Go to <a href="#/">Devices</a> and select a device first.</p></div>`;
    return;
  }

  let pollTimer = null;

  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Traffic Capture</h1>
      <p class="page-subtitle">Capturing network traffic for <strong>${device.name}</strong> ${device.ip_address ? `(${device.ip_address})` : ''}</p>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <span class="card-title">Capture Configuration</span>
      </div>

      <div class="form-group">
        <label class="form-label">Duration</label>
        <div class="duration-picker" id="duration-picker">
          ${DURATIONS.map((d, i) => `<button class="duration-btn ${i === 0 ? 'active' : ''}" data-seconds="${d.seconds}">${d.label}</button>`).join('')}
          <button class="duration-btn" data-seconds="custom">Custom</button>
        </div>
        <div id="custom-duration" style="display:none;margin-top:10px;">
          <div class="form-row" style="max-width:300px;">
            <div class="form-group">
              <input type="number" class="form-input" id="custom-val" placeholder="Value" min="1" value="30" />
            </div>
            <div class="form-group">
              <select class="form-select" id="custom-unit">
                <option value="60">Minutes</option>
                <option value="3600" selected>Hours</option>
                <option value="86400">Days</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <div class="form-group">
        <label class="form-label">Interface</label>
        <input class="form-input" id="cap-interface" placeholder="eth0 (default)" value="" style="max-width:300px;" />
      </div>

      <div class="form-row">
        <div class="form-group">
          <label class="form-label">Filter by MAC Address <span style="color:var(--text-muted);font-weight:normal;">(optional)</span></label>
          <input class="form-input" id="cap-mac" placeholder="e.g. AA:BB:CC:DD:EE:FF"
            value="${device.mac_address || ''}" />
        </div>
        <div class="form-group">
          <label class="form-label">Filter by IP Address <span style="color:var(--text-muted);font-weight:normal;">(optional)</span></label>
          <input class="form-input" id="cap-ip" placeholder="e.g. 10.0.0.50"
            value="${device.ip_address || ''}" />
        </div>
      </div>

      <div style="margin-bottom:16px;">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;color:var(--text-secondary);font-size:0.85rem;">
          <input type="checkbox" id="cap-advanced-toggle" />
          Show advanced BPF filter
        </label>
        <div id="cap-advanced-bpf" style="display:none;margin-top:8px;">
          <label class="form-label">Custom BPF Filter <span style="color:var(--text-muted);font-weight:normal;">(overrides MAC/IP fields above)</span></label>
          <input class="form-input" id="cap-filter" placeholder="e.g. host 10.0.0.50 and port 443" value="" />
        </div>
      </div>

      <div id="bpf-preview" style="margin-bottom:14px;padding:8px 12px;border-radius:var(--radius-sm);background:var(--bg-tertiary);font-family:var(--font-mono, monospace);font-size:0.82rem;color:var(--text-secondary);display:none;">
        <strong>BPF:</strong> <span id="bpf-preview-text"></span>
      </div>

      <div style="display:flex;gap:10px;">
        <button class="btn btn-primary btn-lg" id="btn-start">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><polygon points="5,3 15,9 5,15" fill="currentColor"/></svg>
          Start Capture
        </button>
        <button class="btn btn-danger btn-lg" id="btn-stop" style="display:none;">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none"><rect x="4" y="4" width="10" height="10" rx="1" fill="currentColor"/></svg>
          Stop Capture
        </button>
      </div>
    </div>

    <div id="capture-live" style="display:none;">
      <div class="capture-stats" id="cap-stats">
        <div class="capture-stat">Packets: <span class="value" id="stat-packets">0</span></div>
        <div class="capture-stat">Elapsed: <span class="value" id="stat-elapsed">0s</span></div>
        <div class="capture-stat">File Size: <span class="value" id="stat-size">0 B</span></div>
      </div>
      <div class="progress-bar"><div class="progress-fill" id="progress-fill" style="width:0%"></div></div>

      <div style="border-radius:var(--radius-md);overflow:hidden;border:1px solid var(--border-color);">
        <div class="terminal-header">
          <div class="terminal-dots"><span></span><span></span><span></span></div>
          <span class="terminal-title">tcpdump — live capture</span>
        </div>
        <div class="terminal" id="terminal-output">
          <div class="terminal-line info">Capture starting...</div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-bottom:20px;">
      <div class="card-header">
        <span class="card-title">Or Upload a PCAP File</span>
      </div>
      <p style="color:var(--text-muted);font-size:0.85rem;margin-bottom:12px;">Already have a packet capture? Upload a .pcap or .pcapng file to analyze.</p>
      <div id="upload-zone" style="border:2px dashed var(--border-color);border-radius:var(--radius-md);padding:28px;text-align:center;cursor:pointer;transition:all var(--transition-fast);">
        <svg width="36" height="36" viewBox="0 0 36 36" fill="none" style="margin-bottom:8px;opacity:0.4;"><path d="M18 6v18M12 12l6-6 6 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M6 24v4a2 2 0 002 2h20a2 2 0 002-2v-4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        <p style="color:var(--text-secondary);font-size:0.9rem;">Click to select or drag & drop a <strong>.pcap / .pcapng</strong> file</p>
        <input type="file" id="pcap-file-input" accept=".pcap,.pcapng,.cap" style="display:none;" />
      </div>
      <div id="upload-status" style="display:none;margin-top:12px;"></div>
    </div>

    <div class="card" style="margin-top:20px;">
      <div class="card-header">
        <span class="card-title">Previous Captures</span>
      </div>
      <div id="captures-list"></div>
    </div>
  `;

  // Duration picker logic
  let selectedDuration = 3600;
  container.querySelectorAll('.duration-btn').forEach(btn => {
    btn.onclick = () => {
      container.querySelectorAll('.duration-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const sec = btn.dataset.seconds;
      if (sec === 'custom') {
        container.querySelector('#custom-duration').style.display = 'block';
      } else {
        container.querySelector('#custom-duration').style.display = 'none';
        selectedDuration = parseInt(sec);
      }
    };
  });

  function getSelectedDuration() {
    const customDiv = container.querySelector('#custom-duration');
    if (customDiv.style.display !== 'none') {
      const val = parseInt(container.querySelector('#custom-val').value) || 1;
      const unit = parseInt(container.querySelector('#custom-unit').value);
      return val * unit;
    }
    return selectedDuration;
  }

  // Advanced BPF toggle
  const advToggle = container.querySelector('#cap-advanced-toggle');
  advToggle.onchange = () => {
    container.querySelector('#cap-advanced-bpf').style.display = advToggle.checked ? 'block' : 'none';
    updateBpfPreview();
  };

  // Build BPF filter from MAC/IP fields
  function buildBpfFilter() {
    // If advanced BPF is set and toggle is on, use that
    if (advToggle.checked) {
      const custom = container.querySelector('#cap-filter').value.trim();
      if (custom) return custom;
    }

    const mac = container.querySelector('#cap-mac').value.trim();
    const ip = container.querySelector('#cap-ip').value.trim();

    const parts = [];
    if (mac) parts.push(`ether host ${mac}`);
    if (ip) parts.push(`host ${ip}`);

    if (parts.length === 0) return '';
    if (parts.length === 1) return parts[0];
    // Use "or" when both — capture traffic matching either the MAC or the IP
    return `(${parts.join(' or ')})`;
  }

  function updateBpfPreview() {
    const bpf = buildBpfFilter();
    const preview = container.querySelector('#bpf-preview');
    if (bpf) {
      preview.style.display = 'block';
      container.querySelector('#bpf-preview-text').textContent = bpf;
    } else {
      preview.style.display = 'none';
    }
  }

  // Update preview on input changes
  ['#cap-mac', '#cap-ip', '#cap-filter'].forEach(sel => {
    const el = container.querySelector(sel);
    if (el) el.addEventListener('input', updateBpfPreview);
  });
  updateBpfPreview();

  // --- PCAP Upload ---
  const uploadZone = container.querySelector('#upload-zone');
  const fileInput = container.querySelector('#pcap-file-input');
  const uploadStatus = container.querySelector('#upload-status');

  uploadZone.onclick = () => fileInput.click();

  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--accent-indigo)';
    uploadZone.style.background = 'rgba(99,102,241,0.06)';
  });
  uploadZone.addEventListener('dragleave', () => {
    uploadZone.style.borderColor = 'var(--border-color)';
    uploadZone.style.background = '';
  });
  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--border-color)';
    uploadZone.style.background = '';
    if (e.dataTransfer.files.length > 0) handleUpload(e.dataTransfer.files[0]);
  });

  fileInput.onchange = () => {
    if (fileInput.files.length > 0) handleUpload(fileInput.files[0]);
  };

  async function handleUpload(file) {
    uploadStatus.style.display = 'block';
    uploadStatus.innerHTML = `<span style="color:var(--accent-cyan);">Uploading <strong>${file.name}</strong> (${formatBytes(file.size)})...</span>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`/api/devices/${device.id}/upload-pcap`, {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || 'Upload failed');
      }
      const capture = await res.json();
      state.activeCapture = capture;
      uploadStatus.innerHTML = `<span style="color:var(--accent-green);">✓ Uploaded! Redirecting to analysis...</span>`;
      toast('PCAP uploaded successfully!', 'success');
      setTimeout(() => navigate('/analysis'), 800);
    } catch (err) {
      uploadStatus.innerHTML = `<span style="color:var(--accent-red);">✗ ${err.message}</span>`;
      toast(err.message, 'error');
    }
  }

  // Load previous captures
  async function loadCaptures() {
    try {
      const captures = await api(`/api/devices/${device.id}/captures`);
      const list = container.querySelector('#captures-list');
      if (!list) return;
      if (captures.length === 0) {
        list.innerHTML = '<p style="color:var(--text-muted);font-size:0.9rem;">No captures yet.</p>';
        return;
      }
      list.innerHTML = `
        <div class="table-container">
          <table class="data-table">
            <thead><tr><th>ID</th><th>Interface</th><th>Duration</th><th>Packets</th><th>Size</th><th>Started</th><th>Actions</th></tr></thead>
            <tbody>
              ${captures.map(c => `
                <tr>
                  <td>${c.id}</td>
                  <td>${c.interface}</td>
                  <td>${formatDuration(c.duration_seconds)}</td>
                  <td>${c.packet_count.toLocaleString()}</td>
                  <td>${formatBytes(c.file_size)}</td>
                  <td>${new Date(c.started_at).toLocaleString()}</td>
                  <td><button class="btn btn-ghost btn-sm analyze-btn" data-id="${c.id}">Analyze →</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
      list.querySelectorAll('.analyze-btn').forEach(btn => {
        btn.onclick = () => {
          state.activeCapture = { id: btn.dataset.id };
          navigate('/analysis');
        };
      });
    } catch (err) {
      // silently fail
    }
  }

  // Polling function
  let lastLogCount = 0;
  async function pollStatus(captureId, totalDuration) {
    try {
      const status = await api(`/api/devices/${device.id}/capture-status`);
      const terminal = container.querySelector('#terminal-output');
      if (!terminal) { clearInterval(pollTimer); return; }

      // Update stats
      container.querySelector('#stat-packets').textContent = (status.packet_count || 0).toLocaleString();
      container.querySelector('#stat-elapsed').textContent = formatDuration(status.elapsed_seconds || 0);
      container.querySelector('#stat-size').textContent = formatBytes(status.file_size || 0);

      if (totalDuration > 0) {
        const pct = Math.min(100, ((status.elapsed_seconds || 0) / totalDuration) * 100);
        container.querySelector('#progress-fill').style.width = `${pct}%`;
      }

      // Append new logs
      const logs = status.logs || [];
      if (logs.length > lastLogCount) {
        const newLines = logs.slice(lastLogCount);
        for (const line of newLines) {
          const el = document.createElement('div');
          el.className = 'terminal-line';
          el.textContent = line;
          terminal.appendChild(el);
        }
        terminal.scrollTop = terminal.scrollHeight;
        lastLogCount = logs.length;
      }

      // Check if capture finished
      if (!status.running) {
        clearInterval(pollTimer);
        const el = document.createElement('div');
        el.className = 'terminal-line info';
        el.textContent = `✓ Capture complete — ${(status.packet_count || 0).toLocaleString()} packets, ${formatBytes(status.file_size || 0)}`;
        terminal.appendChild(el);
        terminal.scrollTop = terminal.scrollHeight;

        container.querySelector('#progress-fill').style.width = '100%';
        container.querySelector('#btn-stop').style.display = 'none';
        container.querySelector('#btn-start').style.display = 'inline-flex';
        toast('Capture completed!', 'success');
        loadCaptures();
      }
    } catch (err) {
      // polling error, ignore
    }
  }

  // Start capture
  const btnStart = container.querySelector('#btn-start');
  const btnStop = container.querySelector('#btn-stop');

  btnStart.onclick = async () => {
    const duration = getSelectedDuration();
    const bpfFilter = buildBpfFilter();
    try {
      const capture = await api(`/api/devices/${device.id}/captures`, {
        method: 'POST',
        body: {
          interface: container.querySelector('#cap-interface').value.trim(),
          duration_seconds: duration,
          bpf_filter: bpfFilter,
        },
      });

      state.activeCapture = capture;
      btnStart.style.display = 'none';
      btnStop.style.display = 'inline-flex';
      container.querySelector('#capture-live').style.display = 'block';

      const terminal = container.querySelector('#terminal-output');
      terminal.innerHTML = `<div class="terminal-line info">Capture started — monitoring traffic...</div>`;
      if (bpfFilter) {
        const bpfLine = document.createElement('div');
        bpfLine.className = 'terminal-line';
        bpfLine.textContent = `BPF filter: ${bpfFilter}`;
        terminal.appendChild(bpfLine);
      }
      lastLogCount = 0;

      // Poll every 2 seconds
      pollTimer = setInterval(() => pollStatus(capture.id, duration), 2000);

      // Stop handler
      btnStop.onclick = async () => {
        clearInterval(pollTimer);
        try {
          const result = await api(`/api/devices/${device.id}/captures/${capture.id}/stop`, { method: 'POST' });
          toast(`Capture stopped — ${(result.packet_count || 0).toLocaleString()} packets`, 'success');
        } catch (err) {
          toast(err.message, 'error');
        }
        btnStart.style.display = 'inline-flex';
        btnStop.style.display = 'none';
        loadCaptures();
      };

    } catch (err) {
      toast(err.message, 'error');
    }
  };

  // Clean up poll on page navigation
  const origHash = window.location.hash;
  const navCheck = setInterval(() => {
    if (window.location.hash !== origHash) {
      clearInterval(pollTimer);
      clearInterval(navCheck);
    }
  }, 500);

  await loadCaptures();

  // Check if there's already an active capture
  try {
    const status = await api(`/api/devices/${device.id}/capture-status`);
    if (status.running) {
      btnStart.style.display = 'none';
      btnStop.style.display = 'inline-flex';
      container.querySelector('#capture-live').style.display = 'block';
      lastLogCount = 0;
      pollTimer = setInterval(() => pollStatus(status.capture_id, 0), 2000);

      btnStop.onclick = async () => {
        clearInterval(pollTimer);
        try {
          await api(`/api/devices/${device.id}/captures/${status.capture_id}/stop`, { method: 'POST' });
          toast('Capture stopped', 'success');
        } catch (err) { toast(err.message, 'error'); }
        btnStart.style.display = 'inline-flex';
        btnStop.style.display = 'none';
        loadCaptures();
      };
    }
  } catch (e) { /* no active capture */ }
}
