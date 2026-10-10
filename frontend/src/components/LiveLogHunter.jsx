import { useState, useEffect } from "react";
import { api, SEV } from "../api";
import {
  FileText,
  Play,
  Upload,
  AlertTriangle,
  CheckCircle2,
  Trash2,
  RefreshCw,
  ExternalLink,
  ShieldAlert,
  Terminal,
  Activity,
  Layers,
  Sparkles,
} from "lucide-react";

export default function LiveLogHunter({ onSelectThreat, isOpen, onClose }) {
  const [matches, setMatches] = useState([]);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [logText, setLogText] = useState("");
  const [statsMsg, setStatsMsg] = useState(null);

  const loadMatches = async () => {
    try {
      const data = await api.logMatches();
      setMatches(data || []);
    } catch (e) {
      console.error("Failed to load log matches:", e);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadMatches();
    }
  }, [isOpen]);

  const handleFileUpload = async (file) => {
    if (!file) return;
    setLoading(true);
    setStatsMsg(null);
    try {
      const res = await api.matchLogsFile(file);
      setStatsMsg({
        ok: true,
        text: `Processed ${res.lines_processed} log lines • Found ${res.threat_hits} malicious indicator hits!`,
      });
      await loadMatches();
    } catch (e) {
      setStatsMsg({ ok: false, text: `Log processing failed: ${e.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handlePasteSubmit = async () => {
    if (!logText.trim()) return;
    setLoading(true);
    setStatsMsg(null);
    try {
      const res = await api.matchLogsText(logText);
      setStatsMsg({
        ok: true,
        text: `Processed ${res.lines_processed} lines • Detected ${res.threat_hits} threats!`,
      });
      setLogText("");
      await loadMatches();
    } catch (e) {
      setStatsMsg({ ok: false, text: `Log parsing error: ${e.message}` });
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async () => {
    setSimulating(true);
    setStatsMsg(null);
    try {
      const res = await api.simulateLogs();
      setStatsMsg({
        ok: true,
        text: `Injected simulated live stream: ${res.lines_processed} events processed, ${res.threat_hits} threat alerts raised!`,
      });
      await loadMatches();
    } catch (e) {
      setStatsMsg({ ok: false, text: `Simulation error: ${e.message}` });
    } finally {
      setSimulating(false);
    }
  };

  const handleClear = async () => {
    try {
      await api.clearLogMatches();
      setMatches([]);
      setStatsMsg({ ok: true, text: "Detection history cleared." });
      setTimeout(() => setStatsMsg(null), 3000);
    } catch (e) {
      console.error(e);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 p-4 backdrop-blur-sm animate-fadeIn">
      <div className="card w-full max-w-4xl max-h-[90vh] flex flex-col space-y-4 border-slate-700/80 bg-slate-900 shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-sky-500/20 text-sky-400 border border-sky-500/30">
              <Terminal className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-slate-100">
                  Live Log Hunter & Continuous Matching
                </h2>
                <span className="rounded bg-sky-500/20 px-1.5 py-0.5 text-[10px] font-bold text-sky-300 uppercase">
                  Suricata · Zeek · Wazuh
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Correlate streaming or uploaded telemetry against known threat indicators with false-positive suppression.
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

        {/* Action Controls & Ingestion Box */}
        <div className="grid gap-3 md:grid-cols-2">
          {/* File Upload / Paste Box */}
          <div className="space-y-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Ingest Logs (eve.json, Zeek, Wazuh, Syslog)
              </span>
              <label className="flex cursor-pointer items-center gap-1 text-[11px] font-semibold text-sky-400 hover:text-sky-300">
                <Upload className="h-3 w-3" />
                <span>Upload File</span>
                <input
                  type="file"
                  accept=".json,.log,.txt"
                  hidden
                  onChange={(e) => handleFileUpload(e.target.files[0])}
                />
              </label>
            </div>
            <textarea
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              placeholder="Paste Suricata EVE JSON lines, Zeek logs, Wazuh JSON, or firewall lines here…"
              rows={3}
              className="w-full rounded-md border border-slate-800 bg-slate-900/90 p-2 font-mono text-[11px] text-slate-200 placeholder-slate-500 focus:border-sky-500/50 focus:outline-none"
            />
            <div className="flex justify-end gap-2">
              <button
                disabled={loading || !logText.trim()}
                onClick={handlePasteSubmit}
                className="rounded bg-sky-500 px-3 py-1 text-xs font-semibold text-slate-950 transition hover:bg-sky-400 disabled:opacity-40"
              >
                {loading ? "Matching…" : "Scan Pasted Logs"}
              </button>
            </div>
          </div>

          {/* Stream Simulator & Operational Actions */}
          <div className="flex flex-col justify-between rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div>
              <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-300">
                <Sparkles className="h-3.5 w-3.5 text-amber-400" />
                <span>One-Click Live Stream Test</span>
              </div>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">
                Injects real-world Suricata eve.json, Zeek, and Wazuh telemetry combining active C2 beaconing hits and benign background traffic.
              </p>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                onClick={handleSimulate}
                disabled={simulating}
                className="flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300 shadow transition hover:bg-amber-500/20 disabled:opacity-50"
              >
                <Play className={`h-3.5 w-3.5 ${simulating ? "animate-spin" : ""}`} />
                <span>Simulate Live Stream Hits</span>
              </button>

              <button
                onClick={loadMatches}
                className="flex items-center gap-1 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-slate-700"
              >
                <RefreshCw className="h-3 w-3" />
                <span>Sync</span>
              </button>

              {matches.length > 0 && (
                <button
                  onClick={handleClear}
                  className="flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 text-xs text-rose-300 hover:bg-rose-500/20"
                >
                  <Trash2 className="h-3 w-3" />
                  <span>Clear</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Status Toast */}
        {statsMsg && (
          <div
            className={`flex items-center gap-2 rounded-lg border p-2 text-xs ${
              statsMsg.ok
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                : "border-rose-500/30 bg-rose-500/10 text-rose-300"
            }`}
          >
            {statsMsg.ok ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="h-4 w-4 text-rose-400" />
            )}
            <span>{statsMsg.text}</span>
          </div>
        )}

        {/* Live Detected Hits Stream */}
        <div className="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[220px]">
          <div className="flex items-center justify-between text-xs font-bold uppercase tracking-wider text-slate-400">
            <span className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-rose-400 animate-pulse" />
              <span>Real-Time Log Match Detections ({matches.length})</span>
            </span>
          </div>

          {matches.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center text-slate-500 border border-dashed border-slate-800 rounded-lg">
              <ShieldAlert className="h-8 w-8 text-slate-600 mb-2" />
              <p className="text-xs">No active log detections yet.</p>
              <p className="text-[11px] text-slate-600 mt-0.5">
                Upload a log file or click "Simulate Live Stream Hits" to test continuous matching.
              </p>
            </div>
          ) : (
            matches.map((m) => {
              const sevInfo = SEV[m.severity] || SEV.high;
              return (
                <div
                  key={m.id}
                  className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs transition hover:border-slate-700"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded border px-1.5 py-0.2 font-mono text-[9px] font-extrabold uppercase ${sevInfo.badgeCls || sevInfo.cls}`}
                      >
                        {m.severity}
                      </span>
                      <span className="rounded bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-sky-400 font-bold uppercase">
                        {m.format}
                      </span>
                      <span className="font-mono font-bold text-slate-100">
                        Hit on: <span className="text-rose-400">{m.matched_indicator}</span>
                      </span>
                      {m.malware && (
                        <span className="rounded bg-rose-500/15 border border-rose-500/30 px-1.5 py-0.2 text-[10px] text-rose-300 font-medium">
                          {m.malware}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-slate-400">
                        {m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : ""}
                      </span>
                      <button
                        onClick={() => {
                          onSelectThreat(m.threat_id);
                          onClose();
                        }}
                        className="flex items-center gap-1 rounded bg-sky-500/20 px-2 py-0.5 text-[11px] font-semibold text-sky-300 hover:bg-sky-500/30"
                      >
                        <span>Investigate IoC</span>
                        <ExternalLink className="h-3 w-3" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px] text-slate-300 bg-slate-900/60 p-2 rounded">
                    <div>
                      <span className="text-slate-500">SRC: </span>
                      <span className="text-sky-300">{m.src_ip}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">DST: </span>
                      <span className="text-rose-300">{m.dest_ip}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">PROTO: </span>
                      <span>{m.proto}</span>
                    </div>
                  </div>

                  {m.signature && (
                    <p className="mt-1.5 text-[11px] text-slate-400 italic">
                      Signature / Alert: {m.signature}
                    </p>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
