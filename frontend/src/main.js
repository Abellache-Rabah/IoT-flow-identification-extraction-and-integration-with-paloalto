// IoT Onboarding — Main App Entry & Router

// ---- State ----
export const state = {
    activeDevice: null, // current device profile being worked on
    activeCapture: null,
    panos: {
        keygenHost: '', keygenUser: '', keygenPass: '',
        host: '', version: '11.1', key: '',
        ruleName: '', ruleFrom: '', ruleTo: '',
        ruleSource: '', ruleDest: '', ruleService: '',
        ruleApp: '', ruleTags: 'iot', ruleAction: 'allow',
        logStart: true, logEnd: true,
        fwVsys: '', panDg: '', panVsys: '',
    }
};

// ---- API Helper ----
const API = '';
export async function api(path, opts = {}) {
    const res = await fetch(`${API}${path}`, {
        headers: { 'Content-Type': 'application/json', ...opts.headers },
        ...opts,
        body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || 'Request failed');
    }
    if (res.status === 204) return null;
    return res.json();
}

// ---- Toast ----
export function toast(message, type = 'info') {
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3000);
}

// ---- Page Imports ----
import { renderDevices } from './pages/devices.js';
import { renderCapture } from './pages/capture.js';
import { renderAnalysis } from './pages/analysis.js';
import { renderAllowlist } from './pages/allowlist.js';
import { renderPanos } from './pages/panos.js';

const routes = {
    '/': renderDevices,
    '/capture': renderCapture,
    '/analysis': renderAnalysis,
    '/allowlist': renderAllowlist,
    '/panos': renderPanos,
};

// ---- Router ----
function getPath() {
    return window.location.hash.replace('#', '') || '/';
}

function updateNav(path) {
    document.querySelectorAll('.nav-link').forEach(link => {
        const page = link.dataset.page;
        const linkPath = page === 'devices' ? '/' : `/${page}`;
        link.classList.toggle('active', linkPath === path);
    });
}

export function navigate(path) {
    window.location.hash = `#${path}`;
}

function updateDeviceBadge() {
    const badge = document.getElementById('active-device-badge');
    const nameEl = document.getElementById('active-device-name');
    if (state.activeDevice) {
        badge.style.display = 'flex';
        nameEl.textContent = state.activeDevice.name;
    } else {
        badge.style.display = 'none';
    }
}

export function setActiveDevice(device) {
    state.activeDevice = device;
    updateDeviceBadge();
}

async function render() {
    const path = getPath();
    updateNav(path);
    const container = document.getElementById('page-container');
    container.innerHTML = '';
    const renderFn = routes[path] || routes['/'];
    await renderFn(container);
}

// ---- Format helpers ----
export function formatBytes(bytes) {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function formatDuration(seconds) {
    if (!seconds) return '0s';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

export function timeAgo(dateStr) {
    if (!dateStr) return '';
    const d = new Date(dateStr);
    const now = new Date();
    const diff = Math.floor((now - d) / 1000);
    if (diff < 60) return 'just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

// ---- Init ----
window.addEventListener('hashchange', render);
window.addEventListener('DOMContentLoaded', render);
