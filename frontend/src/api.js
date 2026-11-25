/**
 * Centralized API Client for IPsec Sentinel AI v2.0
 */

export async function fetchHealth() {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Backend offline');
  return res.json();
}

export async function fetchSamples() {
  const res = await fetch('/api/samples');
  if (!res.ok) throw new Error('Failed to load samples');
  return res.json();
}

export async function fetchTestbedStatus() {
  const res = await fetch('/api/testbed/status');
  if (!res.ok) return { docker_running: false, containers: [], real_captures_count: 0 };
  return res.json();
}

export async function analyzeSample(filename) {
  const res = await fetch(`/api/analyze/sample/${encodeURIComponent(filename)}`, { method: 'POST' });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function uploadPcap(file) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch('/api/analyze/upload', { method: 'POST', body: formData });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function fetchSessions() {
  const res = await fetch('/api/sessions');
  if (!res.ok) return [];
  return res.json();
}

export async function fetchSessionById(sessionId) {
  const res = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}`);
  if (!res.ok) throw new Error('Session not found');
  return res.json();
}

export async function runActiveScan(payload) {
  const res = await fetch('/api/scan/target', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
