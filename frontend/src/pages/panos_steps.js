// ---- PAN-OS API Step Pages (Simple Wizards) ----
import { renderPanosWizard } from './panos.js';

export async function renderPanosStep1(container) { await renderPanosWizard(container, 1); }
export async function renderPanosStep2(container) { await renderPanosWizard(container, 2); }
export async function renderPanosStep3(container) { await renderPanosWizard(container, 3); }
export async function renderPanosStep4(container) { await renderPanosWizard(container, 4); }
export async function renderPanosStep5(container) { await renderPanosWizard(container, 5); }
