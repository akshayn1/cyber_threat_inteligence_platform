import { ExternalLink, ArrowRight, ShieldAlert } from "lucide-react";

export default function AttackChain({ chain }) {
  if (!chain?.length) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/40 p-3 text-xs text-slate-400">
        <ShieldAlert className="h-4 w-4 text-slate-500" />
        <span>No MITRE ATT&CK kill-chain techniques correlated for this threat.</span>
      </div>
    );
  }

  return (
    <div className="flex flex-wrap items-stretch gap-2">
      {chain.map((stage, i) => (
        <div key={stage.tactic} className="flex items-center">
          <div className="min-w-[140px] rounded-xl border border-sky-500/30 bg-gradient-to-b from-sky-500/10 to-transparent p-3 shadow-sm transition hover:border-sky-500/60 hover:shadow-sky-500/10">
            <div className="flex items-center justify-between gap-1 text-[10px] font-bold uppercase tracking-wider text-sky-400">
              <span>{stage.label}</span>
              <span className="rounded bg-sky-500/20 px-1 py-0.2 font-mono text-[9px] text-sky-300">
                0{i + 1}
              </span>
            </div>
            <div className="mt-2 space-y-1.5">
              {stage.techniques.map((t) => (
                <a
                  key={t.id}
                  href={t.url}
                  target="_blank"
                  rel="noreferrer"
                  className="group flex items-center justify-between rounded-md bg-slate-900/60 px-2 py-1 text-xs text-slate-200 transition hover:bg-sky-500/15 hover:text-sky-300"
                >
                  <div className="min-w-0 pr-1 truncate">
                    <span className="font-mono font-semibold text-sky-400">{t.id}</span>{" "}
                    <span className="text-slate-300">{t.name}</span>
                  </div>
                  <ExternalLink className="h-3 w-3 shrink-0 opacity-40 group-hover:opacity-100" />
                </a>
              ))}
            </div>
          </div>
          {i < chain.length - 1 && (
            <div className="px-1 text-slate-600">
              <ArrowRight className="h-4 w-4" />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

