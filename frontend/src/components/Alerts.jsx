import { useState, useMemo } from "react";
import { SEV } from "../api";
import { Search, AlertCircle, Shield, Radio } from "lucide-react";

export default function Alerts({ alerts, selectedId, onSelect, newIds }) {
  const [query, setQuery] = useState("");
  const [filterSev, setFilterSev] = useState("all");

  const filtered = useMemo(() => {
    return alerts.filter((a) => {
      const matchSev = filterSev === "all" || a.severity === filterSev;
      const matchQuery =
        !query ||
        a.title.toLowerCase().includes(query.toLowerCase()) ||
        a.indicator.toLowerCase().includes(query.toLowerCase());
      return matchSev && matchQuery;
    });
  }, [alerts, filterSev, query]);

  const counts = useMemo(() => {
    const c = { all: alerts.length, critical: 0, high: 0, medium: 0, low: 0 };
    alerts.forEach((a) => {
      if (c[a.severity] !== undefined) c[a.severity]++;
    });
    return c;
  }, [alerts]);

  return (
    <div className="card space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="card-title !mb-0">
          <Radio className="h-4 w-4 text-sky-400" />
          <span>Active Threat Feed</span>
          <span className="ml-1 rounded-full bg-slate-800/80 px-2 py-0.5 text-[10px] font-bold text-slate-300">
            {alerts.length}
          </span>
        </div>

        
        <div className="flex items-center gap-1 text-[11px]">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSev(s)}
              className={`rounded px-2 py-0.5 font-medium transition ${
                filterSev === s
                  ? "bg-sky-500/20 text-sky-300 ring-1 ring-sky-500/40"
                  : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              }`}
            >
              <span className="capitalize">{s}</span>
              <span className="ml-1 opacity-60">({counts[s] ?? 0})</span>
            </button>
          ))}
        </div>
      </div>

      
      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter alerts by indicator or title…"
          className="w-full rounded-lg border border-slate-700/60 bg-slate-900/60 py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 transition focus:border-sky-500/60 focus:bg-slate-900 focus:outline-none focus:ring-1 focus:ring-sky-500/40"
        />
      </div>

      
      <div className="max-h-[310px] space-y-1.5 overflow-y-auto pr-1">
        {filtered.map((a) => {
          const sevInfo = SEV[a.severity] || SEV.low;
          const isSelected = selectedId === a.id;
          const isNew = newIds?.has(a.id);

          return (
            <button
              key={a.id}
              onClick={() => onSelect(a.id)}
              className={`group flex w-full items-center gap-3 rounded-lg border p-2.5 text-left text-xs transition duration-150 ${
                isSelected
                  ? "border-sky-500/70 bg-sky-950/30 ring-1 ring-sky-500/30"
                  : "border-slate-800/80 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-800/50"
              }`}
            >
              {/* Severity Pill */}
              <span
                className={`flex shrink-0 items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevInfo.badgeCls || sevInfo.cls}`}
              >
                <span
                  className="h-1.5 w-1.5 rounded-full"
                  style={{ backgroundColor: sevInfo.color }}
                />
                {a.severity}
              </span>

              {/* Title & Indicator */}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <span className="truncate font-medium text-slate-200 group-hover:text-sky-300">
                    {a.title}
                  </span>
                  {isNew && (
                    <span className="animate-pulse rounded bg-rose-500 px-1 py-0.2 text-[9px] font-bold text-white shadow-[0_0_8px_rgba(244,63,94,0.6)]">
                      NEW
                    </span>
                  )}
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                  {a.indicator}
                </div>
              </div>

              {/* Risk Score Pill */}
              <div className="flex shrink-0 flex-col items-end">
                <span
                  className="font-mono text-xs font-bold tabular-nums"
                  style={{ color: sevInfo.color }}
                >
                  {a.risk_score}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-slate-500">
                  risk
                </span>
              </div>
            </button>
          );
        })}

        {!filtered.length && (
          <div className="flex flex-col items-center justify-center py-8 text-center text-slate-500">
            <AlertCircle className="mb-1 h-5 w-5 text-slate-600" />
            <p className="text-xs">No threats match current filter criteria.</p>
          </div>
        )}
      </div>
    </div>
  );
}

