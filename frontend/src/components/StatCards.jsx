import { ShieldAlert, AlertTriangle, Bug, Layers } from "lucide-react";

export default function StatCards({ stats }) {
  const items = [
    {
      label: "Total Threats",
      value: stats?.total_threats,
      caption: "Correlated IoC indicators",
      color: "text-sky-400",
      bgIcon: "bg-sky-500/10 text-sky-400 border-sky-500/20",
      accentBorder: "border-sky-500/30",
      Icon: ShieldAlert,
    },
    {
      label: "Critical Threats",
      value: stats?.critical,
      caption: "Urgent response required",
      color: "text-rose-400",
      bgIcon: "bg-rose-500/10 text-rose-400 border-rose-500/20",
      accentBorder: "border-rose-500/30",
      Icon: AlertTriangle,
    },
    {
      label: "Monitored CVEs",
      value: stats?.total_cves,
      caption: "Active vulnerability mappings",
      color: "text-amber-400",
      bgIcon: "bg-amber-500/10 text-amber-400 border-amber-500/20",
      accentBorder: "border-amber-500/30",
      Icon: Bug,
    },
    {
      label: "Active Campaigns",
      value: stats?.campaigns,
      caption: "Identified threat operations",
      color: "text-purple-400",
      bgIcon: "bg-purple-500/10 text-purple-400 border-purple-500/20",
      accentBorder: "border-purple-500/30",
      Icon: Layers,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-3.5 md:grid-cols-4">
      {items.map((i) => {
        const Icon = i.Icon;
        return (
          <div
            key={i.label}
            className="card group relative overflow-hidden transition-all duration-200 hover:-translate-y-0.5"
          >
            <div className="flex items-start justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  {i.label}
                </p>
                <div className={`mt-1.5 text-3xl font-extrabold tracking-tight tabular-nums ${i.color}`}>
                  {i.value ?? "–"}
                </div>
              </div>
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${i.bgIcon} transition group-hover:scale-105`}>
                <Icon className="h-5 w-5" />
              </div>
            </div>
            <div className="mt-2.5 flex items-center justify-between border-t border-slate-700/30 pt-2 text-[11px] text-slate-400">
              <span className="truncate">{i.caption}</span>
              <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
            </div>
          </div>
        );
      })}
    </div>
  );
}

