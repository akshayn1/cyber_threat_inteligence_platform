import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import StatCards from "./components/StatCards";
import ThreatMap from "./components/ThreatMap";
import Alerts from "./components/Alerts";
import Charts from "./components/Charts";
import ThreatDetail from "./components/ThreatDetail";
import ImportPanel from "./components/ImportPanel";
import {
  ShieldCheck,
  RefreshCw,
  Sun,
  Moon,
  Terminal,
  Database,
  Radio,
  AlertTriangle,
  ArrowRight,
  X,
} from "lucide-react";

const THEMES = [
  { id: "dark", label: "Executive Dark", icon: Moon },
  { id: "cyber", label: "Cyber Stealth", icon: Terminal },
  { id: "light", label: "Clean Light", icon: Sun },
];

export default function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [points, setPoints] = useState([]);
  const [selected, setSelected] = useState(null);
  const [newIds, setNewIds] = useState(new Set());
  const [banner, setBanner] = useState(null);
  const [error, setError] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [theme, setTheme] = useState(() => localStorage.getItem("sentinel_theme") || "dark");

  // Apply theme to html root
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove("dark", "cyber", "light");
    if (theme === "dark") {
      root.classList.add("dark");
    } else if (theme === "cyber") {
      root.classList.add("dark", "cyber");
    } else if (theme === "light") {
      root.classList.add("light");
    }
    localStorage.setItem("sentinel_theme", theme);
  }, [theme]);

  const load = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [s, a, m] = await Promise.all([api.stats(), api.alerts(), api.map()]);
      setStats(s);
      setAlerts(a);
      setPoints(m);
      setError(null);
      return a;
    } catch (e) {
      setError(`Cannot reach API (${e.message}). Start the backend: uvicorn main:app --port 8000`);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const onImported = async (res) => {
    await load();
    const fresh = res?.new_threats || [];
    if (fresh.length) {
      setNewIds(new Set(fresh.map((t) => t.id)));
      const worst = [...fresh].sort((a, b) => b.risk_score - a.risk_score)[0];
      setSelected(worst.id);
      if (worst.severity === "critical" || worst.severity === "high") {
        setBanner({
          severity: worst.severity,
          indicator: worst.indicator,
          score: worst.risk_score,
          id: worst.id,
        });
      }
      setTimeout(() => setBanner(null), 10000);
    }
  };

  return (
    <div className="mx-auto max-w-[1520px] min-h-screen space-y-4 px-4 py-4 sm:px-6">
      {/* Enterprise Top Navigation Bar */}
      <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        {/* Brand identity */}
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-sky-500/40 bg-gradient-to-br from-sky-500/20 to-indigo-500/10 text-sky-400 shadow-md">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-black tracking-wider text-slate-100 sm:text-xl">
                CYBER THREAT INTELIGENCE PLATFORM
              </h1>
              <span className="rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] font-bold tracking-widest text-sky-400 uppercase">
                Threat Intel SOC
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                <span className="font-medium text-slate-300">Telemetry Active</span>
              </span>
              <span className="text-slate-600">·</span>
              <span>Correlation Engine v2.4</span>
              {stats && (
                <>
                  <span className="text-slate-600">·</span>
                  <span className="flex items-center gap-1 rounded bg-slate-800/80 px-1.5 py-0.2 text-[10px] text-slate-300">
                    <Database className="h-3 w-3 text-slate-400" />
                    {stats.database}
                  </span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Global Toolbar & Theme Switcher */}
        <div className="flex flex-wrap items-center gap-2.5">
          <ImportPanel onImported={onImported} />

          <div className="h-5 w-[1px] bg-slate-800 mx-1 hidden sm:block" />

          {/* Refresh Action */}
          <button
            onClick={load}
            disabled={isRefreshing}
            title="Refresh threat telemetry"
            className="flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 px-2.5 py-1.5 text-xs text-slate-300 transition hover:bg-slate-700 hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin text-sky-400" : ""}`} />
            <span className="hidden md:inline">Sync</span>
          </button>

          {/* Theme Selector Toggle */}
          <div className="flex items-center rounded-lg border border-slate-800 bg-slate-900/80 p-0.5">
            {THEMES.map((t) => {
              const Icon = t.icon;
              const isActive = theme === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setTheme(t.id)}
                  title={`Switch to ${t.label}`}
                  className={`flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium transition ${isActive
                    ? "bg-sky-500 text-slate-950 shadow-sm font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                    }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span className="hidden lg:inline">{t.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </header>

      {/* Critical Threat Alert Banner */}
      {banner && (
        <div className="flex items-center justify-between rounded-xl border border-rose-500/40 bg-gradient-to-r from-rose-950/40 via-slate-900/80 to-slate-900/80 p-3 shadow-lg backdrop-blur-md">
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/20 text-rose-400">
              <AlertTriangle className="h-4 w-4 animate-bounce" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-rose-500 px-1.5 py-0.2 text-[10px] font-extrabold uppercase text-white">
                  {banner.severity} Alert Detected
                </span>
                <span className="font-mono text-xs font-bold text-slate-100">
                  {banner.indicator}
                </span>
                <span className="rounded bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-rose-400">
                  Risk {banner.score}/100
                </span>
              </div>
              <p className="mt-0.5 text-xs text-slate-300">
                New malicious telemetry signature correlated with high risk indicators.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelected(banner.id)}
              className="flex items-center gap-1 rounded-lg bg-rose-500 px-3 py-1.5 text-xs font-semibold text-white shadow transition hover:bg-rose-400"
            >
              <span>Investigate</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => setBanner(null)}
              className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-rose-400" />
            <span>{error}</span>
          </div>
          <button
            onClick={load}
            className="rounded bg-rose-500/20 px-2 py-1 text-rose-300 hover:bg-rose-500/30"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* KPI Stats Row */}
      <StatCards stats={stats} />

      {/* Main Analysis Grid */}
      <div className="grid gap-4.5 lg:grid-cols-[1.12fr_1fr]">
        <div className="space-y-4">
          <ThreatMap points={points} selectedId={selected} onSelect={setSelected} />
          <Alerts alerts={alerts} selectedId={selected} onSelect={setSelected} newIds={newIds} />
          <Charts stats={stats} />
        </div>
        <div className="lg:sticky lg:top-4 self-start">
          <ThreatDetail id={selected} />
        </div>
      </div>

      {/* Professional Footer
      <footer className="mt-6 flex flex-wrap items-center justify-between border-t border-slate-800/60 pt-4 text-[11px] text-slate-500">
        <div>
          <span>Sentinel Threat Intelligence Center</span> · <span>Enterprise SecOps Edition</span>
        </div>
        <div className="flex items-center gap-3">
          <span>MITRE ATT&CK® v14.1</span>
          <span>·</span>
          <span>NVD CVE Feed Synchronized</span>
          <span>·</span>
          <span>Feodo Tracker C2 Feed</span>
        </div>
      </footer> */}
    </div>
  );
}

