const API_BASE =
  import.meta.env.VITE_API_BASE_URL ||
  (window.location.port === "5173" ? "http://127.0.0.1:8000" : window.location.origin);

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(data?.detail || response.statusText);
  }
  return data;
}

export function health() {
  return api("/api/health");
}

export function listEndpoints() {
  return api("/api/discovery/endpoints");
}

export function importOpenApi(payload) {
  return api("/api/discovery/openapi", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function generateAttacks(endpointId) {
  return api("/api/discovery/attacks", {
    method: "POST",
    body: JSON.stringify({ endpoint_id: endpointId })
  });
}

export function runScan(payload) {
  return api("/api/scans", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function getReport(scanId) {
  return api(`/api/reports/${scanId}`);
}

export async function getReportMarkdown(scanId) {
  const response = await fetch(`${API_BASE}/api/reports/${scanId}.md`);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(text || response.statusText);
  }
  return text;
}

export function listScans() {
  return api("/api/scans");
}

export function listAttacks() {
  return api("/api/attacks");
}

export function replayAttack(attackId, payload) {
  return api(`/api/attacks/${attackId}/replay`, {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function getGraph() {
  return api("/api/graph");
}

export function analyzeJwt(payload) {
  return api("/api/jwt/analyze", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}
