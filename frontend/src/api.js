const BASE = import.meta.env.VITE_API_URL || "";

async function req(path, opts) {
  const r = await fetch(`${BASE}${path}`, opts);
  if (!r.ok) {
    let msg = r.statusText;
    try { msg = (await r.json()).detail || msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
}

export const api = {
  health: () => req("/api/health"),
  stats: () => req("/api/stats"),
  threats: (opts = {}) => {
    const q = new URLSearchParams(opts).toString();
    return req(`/api/threats${q ? `?${q}` : ""}`);
  },
  threat: (id) => req(`/api/threats/${id}`),
  alerts: () => req("/api/alerts"),
  cves: () => req("/api/cves"),
  map: () => req("/api/map"),
  analyze: (id, use_ai = true) =>
    req("/api/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id, use_ai }) }),
  importFile: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return req("/api/import", { method: "POST", body: fd });
  },
  seed: () => req("/api/seed", { method: "POST" }),
  collect: (src) => req(`/api/collect/${src}`, { method: "POST" }),

  // Allowlist & False Positive Protection
  allowlist: () => req("/api/allowlist"),
  addAllowlist: (item) =>
    req("/api/allowlist", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(item) }),
  deleteAllowlist: (id) => req(`/api/allowlist/${id}`, { method: "DELETE" }),
  markFalsePositive: (threatId, reason = "Legitimate CDN or verified false alarm", penalizeSource = true) =>
    req(`/api/threats/${threatId}/false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reason, penalize_source: penalizeSource }),
    }),
  unmarkFalsePositive: (threatId) =>
    req(`/api/threats/${threatId}/unmark-false-positive`, { method: "POST" }),
  allowlistThreat: (threatId, reason) =>
    req(`/api/threats/${threatId}/allowlist${reason ? `?reason=${encodeURIComponent(reason)}` : ""}`, { method: "POST" }),
  sources: () => req("/api/sources"),

  // Live Log Matching & Ingestion
  matchLogsFile: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return req("/api/logs/match", { method: "POST", body: fd });
  },
  matchLogsText: (logText) =>
    req("/api/logs/match", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ log_text: logText }),
    }),
  simulateLogs: () => req("/api/logs/simulate", { method: "POST" }),
  logMatches: () => req("/api/logs/matches"),
  clearLogMatches: () => req("/api/logs/matches", { method: "DELETE" }),

  // Export Clean Blocklist
  exportBlocklistUrl: (excludeStale = true, excludeAllowlist = true) =>
    `${BASE}/api/export/blocklist?format=txt&exclude_stale=${excludeStale}&exclude_allowlist=${excludeAllowlist}`,
};

export const SEV = {
  critical: { color: "#f43f5e", dot: "🔴", cls: "bg-rose-500/15 text-rose-400 border-rose-500/40", badgeCls: "bg-rose-500/10 text-rose-400 border-rose-500/30" },
  high: { color: "#f97316", dot: "🟠", cls: "bg-orange-500/15 text-orange-400 border-orange-500/40", badgeCls: "bg-orange-500/10 text-orange-400 border-orange-500/30" },
  medium: { color: "#eab308", dot: "🟡", cls: "bg-amber-500/15 text-amber-400 border-amber-500/40", badgeCls: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  low: { color: "#10b981", dot: "🟢", cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40", badgeCls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
};
