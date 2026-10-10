import { useState, useEffect } from "react";
import { api } from "../api";
import {
  ShieldCheck,
  Plus,
  Trash2,
  Download,
  Copy,
  Check,
  AlertTriangle,
  Radio,
  Server,
  Layers,
  Sparkles,
} from "lucide-react";

export default function AllowlistManager({ isOpen, onClose, onRefresh }) {
  const [tab, setTab] = useState("allowlist"); // allowlist | sources | export
  const [items, setItems] = useState([]);
  const [sources, setSources] = useState([]);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  // Form states
  const [newIndicator, setNewIndicator] = useState("");
  const [newType, setNewType] = useState("ip");
  const [newReason, setNewReason] = useState("");

  // Export options
  const [excludeStale, setExcludeStale] = useState(true);
  const [excludeAllowlist, setExcludeAllowlist] = useState(true);
  const [exportPreview, setExportPreview] = useState("");

  const loadData = async () => {
    setLoading(true);
    try {
      const [al, src] = await Promise.all([api.allowlist(), api.sources()]);
      setItems(al || []);
      setSources(src || []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadData();
    }
  }, [isOpen]);

  const handleAdd = async (e) => {
    e.preventDefault();
    if (!newIndicator.trim()) return;
    try {
      await api.addAllowlist({
        indicator: newIndicator.trim(),
        indicator_type: newType,
        reason: newReason.trim() || "Verified legitimate infrastructure",
      });
      setNewIndicator("");
      setNewReason("");
      await loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Failed to add allowlist entry: " + err.message);
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.deleteAllowlist(id);
      await loadData();
      if (onRefresh) onRefresh();
    } catch (err) {
      alert("Failed to delete allowlist entry: " + err.message);
    }
  };

  const handleFetchExport = async () => {
    try {
      const url = api.exportBlocklistUrl(excludeStale, excludeAllowlist);
      const res = await fetch(url);
      const text = await res.text();
      setExportPreview(text);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    if (tab === "export" && isOpen) {
      handleFetchExport();
    }
  }, [tab, excludeStale, excludeAllowlist, isOpen]);

  const copyExport = () => {
    navigator.clipboard.writeText(exportPreview);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="card w-full max-w-3xl max-h-[85vh] flex flex-col space-y-4 border-slate-700/80 bg-slate-900 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">
                Allowlist & False-Positive Protection Center
              </h2>
              <p className="text-xs text-slate-400">
                Protects legitimate CDNs, internal subnets & monitors feed reputation scores to prevent outages.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100"
          >
            ✕
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800/80 pb-2 text-xs">
          <button
            onClick={() => setTab("allowlist")}
            className={`rounded-lg px-3 py-1.5 font-semibold transition ${
              tab === "allowlist"
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Protected Allowlist ({items.length})
          </button>
          <button
            onClick={() => setTab("sources")}
            className={`rounded-lg px-3 py-1.5 font-semibold transition ${
              tab === "sources"
                ? "bg-sky-500/20 text-sky-300 border border-sky-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Feed Trust Scorecard ({sources.length})
          </button>
          <button
            onClick={() => setTab("export")}
            className={`rounded-lg px-3 py-1.5 font-semibold transition ${
              tab === "export"
                ? "bg-purple-500/20 text-purple-300 border border-purple-500/40"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            Clean Blocklist Export
          </button>
        </div>

        {/* Tab 1: Allowlist Management */}
        {tab === "allowlist" && (
          <div className="flex-1 flex flex-col space-y-3 overflow-hidden">
            {/* Add new entry form */}
            <form onSubmit={handleAdd} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-xs font-semibold text-slate-300 mb-2">Add Protected Indicator / Subnet</div>
              <div className="grid gap-2 sm:grid-cols-4">
                <input
                  type="text"
                  placeholder="e.g. 1.1.1.1 or 10.0.0.0/8 or cloudflare.com"
                  value={newIndicator}
                  onChange={(e) => setNewIndicator(e.target.value)}
                  className="sm:col-span-2 rounded border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-emerald-500/50"
                  required
                />
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value)}
                  className="rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="ip">IP Address</option>
                  <option value="cidr">CIDR Subnet</option>
                  <option value="domain">Domain / CDN</option>
                </select>
                <button
                  type="submit"
                  className="flex items-center justify-center gap-1 rounded bg-emerald-500 px-3 py-1 text-xs font-semibold text-slate-950 hover:bg-emerald-400 transition"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>Protect</span>
                </button>
              </div>
              <input
                type="text"
                placeholder="Reason (e.g. Primary Corporate DNS resolver, Cloudflare CDN)"
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
                className="mt-2 w-full rounded border border-slate-800 bg-slate-900 px-2.5 py-1 text-xs text-slate-300 placeholder-slate-500 focus:outline-none"
              />
            </form>

            {/* List */}
            <div className="flex-1 overflow-y-auto space-y-1.5 pr-1 max-h-[300px]">
              {items.map((it) => (
                <div
                  key={it.id}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/40 p-2.5 text-xs hover:border-slate-700"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-1.5 py-0.2 font-mono text-[9px] font-bold text-emerald-400 uppercase">
                      {it.indicator_type}
                    </span>
                    <span className="font-mono font-bold text-slate-200">{it.indicator}</span>
                    <span className="text-slate-500 truncate text-[11px]">· {it.reason}</span>
                  </div>
                  <button
                    onClick={() => handleDelete(it.id)}
                    title="Remove from allowlist"
                    className="p-1 text-slate-500 hover:text-rose-400 rounded transition"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 2: Feed Trust Scorecard */}
        {tab === "sources" && (
          <div className="flex-1 overflow-y-auto space-y-3 pr-1">
            <div className="rounded-lg border border-sky-500/20 bg-sky-950/20 p-3 text-xs text-slate-300 leading-relaxed">
              <span className="font-bold text-sky-400">Dynamic Source Reputation: </span>
              Intelligence feeds start at 100% trust. When analysts flag an indicator as a False Positive,
              a 15% trust penalty is automatically deducted from that feed, lowering the risk score of all other indicators reported by that source.
            </div>

            <div className="space-y-2">
              {sources.map((s) => (
                <div
                  key={s.source}
                  className="rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs flex flex-wrap items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Radio className="h-3.5 w-3.5 text-sky-400" />
                      <span className="font-semibold text-slate-200">{s.source}</span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      <span>Total Indicators: {s.indicator_count}</span>
                      <span className="mx-2">·</span>
                      <span className={s.false_positives > 0 ? "text-amber-400 font-semibold" : ""}>
                        False Positives: {s.false_positives}
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="w-24 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          s.trust_score >= 80 ? "bg-emerald-400" : s.trust_score >= 50 ? "bg-amber-400" : "bg-rose-500"
                        }`}
                        style={{ width: `${s.trust_score}%` }}
                      />
                    </div>
                    <span className="font-mono font-bold text-xs tabular-nums text-slate-200 w-10 text-right">
                      {s.trust_score}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tab 3: Clean Blocklist Export */}
        {tab === "export" && (
          <div className="flex-1 flex flex-col space-y-3 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs">
              <div className="flex flex-wrap items-center gap-4">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={excludeStale}
                    onChange={(e) => setExcludeStale(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-purple-500"
                  />
                  <span>Exclude Stale / Expired IPs</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={excludeAllowlist}
                    onChange={(e) => setExcludeAllowlist(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-purple-500"
                  />
                  <span>Exclude Protected Allowlist</span>
                </label>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={copyExport}
                  className="flex items-center gap-1 rounded bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 hover:bg-slate-700 transition"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copied ? "Copied" : "Copy Blocklist"}</span>
                </button>
                <a
                  href={api.exportBlocklistUrl(excludeStale, excludeAllowlist)}
                  download="clean_blocklist.txt"
                  className="flex items-center gap-1 rounded bg-purple-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-purple-400 transition"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Download Feed</span>
                </a>
              </div>
            </div>

            <div className="flex-1 overflow-hidden rounded-lg border border-slate-800 bg-slate-950 p-2 font-mono text-[11px] text-slate-300">
              <pre className="h-full overflow-y-auto whitespace-pre-wrap">{exportPreview}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
