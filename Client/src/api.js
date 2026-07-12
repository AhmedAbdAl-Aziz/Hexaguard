/**
 * HexaGuard API client
 * Wraps all fetch calls to the Flask backend.
 */

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:5000";

function getToken() {
  return localStorage.getItem("hg_token");
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };

  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const msg = data.error || data.message || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function login(username, password) {
  const data = await request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  localStorage.setItem("hg_token", data.access_token);
  return data.user;
}

export async function getCurrentUser() {
  // اتصل بالباك عشان يتحقق من الـ token
  const data = await request("/api/auth/me");
  const user = normalizeUser(data.user || data);
  localStorage.setItem("hg_user", JSON.stringify(user));
  return user;
}

export function logout() {
  localStorage.removeItem("hg_token");
}

// ── CVEs ──────────────────────────────────────────────────────────────────────

export async function fetchCves({ search = "", severity = "", technology = "" } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (severity && severity !== "ALL") params.set("severity", severity);
  if (technology && technology !== "ALL") params.set("technology", technology);
  params.set("limit", "500");

  const qs = params.toString();
  const data = await request(`/api/cves?${qs}`);

  // الباك بيرجع array مباشرة مش { cves: [...] }
  const arr = Array.isArray(data) ? data : (data.cves || data.data || []);
  return arr.map(normalizeCve);
}
export async function ingestCve(cvePayload) {
  return request("/api/cves/", {
    method: "POST",
    body: JSON.stringify(cvePayload),
  });
}

// ── Customers ─────────────────────────────────────────────────────────────────

export async function fetchCustomers() {
  return request("/api/customers/");
}

export async function provisionCustomer(customerData) {
  return request("/api/customers/", {
    method: "POST",
    body: JSON.stringify(customerData),
  });
}

export async function updateCustomerStack(customerId, techStack) {
  return request(`/api/customers/${customerId}/stack`, {
    method: "PUT",
    body: JSON.stringify({ tech_stack: techStack }),
  });
}

export async function updateCustomerNotifications(customerId, settings) {
  return request(`/api/customers/${customerId}/notifications`, {
    method: "PUT",
    body: JSON.stringify(settings),
  });
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export async function fetchAlerts({ severity = "", cve_id = "", status = "" } = {}) {
  const params = new URLSearchParams();
  if (severity && severity !== "ALL") params.set("severity", severity);
  if (cve_id) params.set("cve_id", cve_id);
  if (status) params.set("status", status);

  const qs = params.toString();
  return request(`/api/alerts/${qs ? "?" + qs : ""}`);
}

export async function markAlertRead(alertId) {
  return request(`/api/alerts/${alertId}/read`, { method: "PUT" });
}

export async function fetchAlertStats() {
  return request("/api/alerts/stats");
}

export { BASE as API_BASE_URL };
