import { useEffect, useState } from "react";
import { api, SEV } from "../api";
import AttackChain from "./AttackChain";
import {
  ShieldAlert,
  Copy,
  Check,
  Cpu,
  Sparkles,
  AlertTriangle,
  Bug,
  MapPin,
  Flame,
  CheckCircle2,
  FileText,
  Activity,
  Layers,
  ExternalLink,
  ChevronRight,
} from "lucide-react";

const WEIGHTS = {
  reputation: 30,
  vulnerability: 25,
  confidence: 20,
  frequency: 15,
  asset: 10,
};

function Section({ icon: Icon, title, badge, children }) {
  return (
    <div className="space-y-2.5 rounded-xl border border-slate-800/80 bg-slate-900/40 p-3.5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-300">
          {Icon && <Icon className="h-3.5 w-3.5 text-sky-400" />}
          <span>{title}</span>
        </div>
        {badge && (
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium text-slate-400">
            {badge}
          </span>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
}

export default function ThreatDetail({ id }) {
  const [data, setData] = useState(null);
  const [ai, setAi] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [completedActions, setCompletedActions] = useState(new Set());

  useEffect(() => {
    if (!id) return;
    setData(null);
    setAi(null);
    setError(null);
    setCompletedActions(new Set());
    api.threat(id).then(setData).catch((e) => setError(e.message));
  }, [id]);

  const copyIndicator = () => {
    if (!data?.indicator) return;
    navigator.clipboard.writeText(data.indicator);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const toggleAction = (idx) => {
    setCompletedActions((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const runAi = async () => {
    setAiLoading(true);
    try {
      const res = await api.analyze(id);
      setAi(res.ai);
    } catch (e) {
      setError(e.message);
    } finally {
      setAiLoading(false);
    }
  };

  if (!id) {
    return (
      <div className="card flex flex-col items-center justify-center py-20 text-center">
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-dashed border-slate-700 bg-slate-900/40 text-slate-500">
          <Activity className="h-6 w-6" />
        </div>
        <h3 className="mt-3 text-sm font-semibold text-slate-300">No Threat Selected</h3>
        <p className="mt-1 max-w-xs text-xs text-slate-500">
          Select an indicator from the live threat stream or interactive map to investigate deep telemetry.
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card border-rose-500/40 bg-rose-500/10 text-xs text-rose-300">
        <div className="flex items-center gap-2 font-bold">
          <AlertTriangle className="h-4 w-4" />
          <span>Error Loading Threat</span>
        </div>
        <p className="mt-1">{error}</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="card flex items-center justify-center py-20">
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span>Retrieving threat dossier…</span>
        </div>
      </div>
    );
  }

  const a = data.analysis;
  const sev = SEV[a.severity] || SEV.low;

  // Gauge calculation for circle SVG
  const radius = 32;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (a.risk_score / 100) * circumference;

  return (
    <div className="card space-y-4">
      {/* HUD Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-4">
          {/* Circular SVG Gauge */}
          <div className="relative flex h-20 w-20 shrink-0 items-center justify-center">
            <svg className="h-20 w-20 -rotate-90 transform" viewBox="0 0 80 80">
              <circle
                cx="40"
                cy="40"
                r={radius}
                stroke="currentColor"
                strokeWidth="6"
                className="text-slate-800/80"
                fill="transparent"
              />
              <circle
                cx="40"
                cy="40"
                r={radius}
                stroke={sev.color}
                strokeWidth="6"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="font-mono text-xl font-extrabold leading-none" style={{ color: sev.color }}>
                {a.risk_score}
              </span>
              <span className="mt-0.5 text-[9px] uppercase tracking-wider text-slate-400">
                Score
              </span>
            </div>
          </div>

          {/* Indicator Info */}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="break-all font-mono text-base font-bold text-slate-100 sm:text-lg">
                {data.indicator}
              </span>
              <button
                onClick={copyIndicator}
                title="Copy indicator to clipboard"
                className="rounded-md border border-slate-700/60 bg-slate-800/60 p-1 text-slate-400 transition hover:bg-slate-700 hover:text-slate-100"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </div>

            {/* Badges */}
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className={`rounded-md border px-2 py-0.5 font-bold uppercase ${sev.badgeCls || sev.cls}`}>
                {a.severity}
              </span>
              <span className="rounded-md border border-slate-700/60 bg-slate-800/60 px-2 py-0.5 text-slate-300">
                {data.indicator_type}
              </span>
              {data.malware && (
                <span className="flex items-center gap-1 rounded-md border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 text-rose-300">
                  <Bug className="h-3 w-3" />
                  <span>{data.malware}</span>
                </span>
              )}
              {data.campaign && (
                <span className="flex items-center gap-1 rounded-md border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-purple-300">
                  <Flame className="h-3 w-3" />
                  <span>{data.campaign}</span>
                </span>
              )}
              {data.geo && (
                <span className="flex items-center gap-1 rounded-md border border-slate-700/60 bg-slate-800/60 px-2 py-0.5 text-slate-300">
                  <MapPin className="h-3 w-3 text-sky-400" />
                  <span>{data.geo.country} ({data.geo.country_code})</span>
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Evidence Section */}
      <Section icon={FileText} title="Telemetry Evidence" badge={`${a.evidence?.length || 0} findings`}>
        <div className="space-y-1.5">
          {a.evidence.map((e, i) => (
            <div key={i} className="flex items-start gap-2.5 rounded-lg bg-slate-900/60 p-2 text-xs text-slate-200">
              <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-sky-400" />
              <span className="leading-relaxed">{e}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* Risk Breakdown Matrix */}
      <Section icon={Activity} title="Risk Matrix Breakdown">
        <div className="space-y-2">
          {Object.entries(a.components).map(([k, v]) => (
            <div key={k} className="flex items-center gap-3 text-xs">
              <div className="w-28 shrink-0 flex items-center justify-between">
                <span className="capitalize text-slate-300">{k}</span>
                <span className="font-mono text-[10px] text-slate-500">{WEIGHTS[k]}%</span>
              </div>
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-slate-800">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${v}%`, backgroundColor: sev.color }}
                />
              </div>
              <span className="w-8 text-right font-mono text-xs font-semibold tabular-nums text-slate-300">
                {v}
              </span>
            </div>
          ))}
        </div>

        {a.rules_triggered.length > 0 && (
          <div className="mt-3 rounded-lg border border-amber-500/20 bg-amber-500/10 p-2.5">
            <div className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-amber-400">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>Correlated Rule Triggers</span>
            </div>
            <ul className="mt-1.5 space-y-1 text-xs text-amber-200/90">
              {a.rules_triggered.map((r, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <span className="text-amber-400">▹</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Section>

      {/* Related Vulnerabilities & CVEs */}
      <Section icon={Bug} title="Known Vulnerabilities (CVE)" badge={`${a.related_cves?.length || 0} CVEs`}>
        {a.related_cves.length ? (
          <div className="space-y-2">
            {a.related_cves.map((c) => (
              <div
                key={c.cve_id}
                className="rounded-lg border border-slate-800 bg-slate-900/60 p-2.5 text-xs transition hover:border-slate-700"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-bold text-amber-400">{c.cve_id}</span>
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-mono text-[10px] font-bold text-rose-300">
                      CVSS {c.cvss}
                    </span>
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-400">
                      {c.affected_product}
                    </span>
                  </div>
                </div>
                <p className="mt-1.5 text-slate-400 leading-relaxed">{c.description}</p>
              </div>
            ))}
            {a.exposed_assets.length > 0 && (
              <div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2 text-xs text-rose-300">
                <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                <span>Exposed infrastructure: {a.exposed_assets.map((x) => x.name).join(", ")}</span>
              </div>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-500">No known CVE vulnerabilities directly linked.</p>
        )}
      </Section>

      {/* MITRE ATT&CK Attack Chain */}
      <Section icon={Layers} title="MITRE ATT&CK Attack Chain">
        <AttackChain chain={a.attack_chain} />
      </Section>

      {/* Related Indicators */}
      {a.related_indicator_list?.length > 0 && (
        <Section icon={ShieldAlert} title="Related Indicators" badge={`${a.related_indicator_list.length} indicators`}>
          <div className="flex flex-wrap gap-1.5">
            {a.related_indicator_list.map((r) => (
              <span
                key={r.id}
                className="rounded-md border border-slate-800 bg-slate-900/70 px-2 py-1 font-mono text-xs text-slate-300"
              >
                {r.indicator}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* AI Threat Analysis */}
      <Section icon={Sparkles} title="AI Executive Threat Briefing">
        {ai ? (
          <div className="space-y-2">
            <div className="rounded-lg border border-sky-500/20 bg-slate-950/80 p-3.5">
              <pre className="whitespace-pre-wrap font-sans text-xs leading-relaxed text-slate-200">
                {ai.text}
              </pre>
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-500">
              <span>Model engine: {ai.source}</span>
              <button
                onClick={runAi}
                disabled={aiLoading}
                className="flex items-center gap-1 text-sky-400 hover:text-sky-300 disabled:opacity-50"
              >
                <Sparkles className="h-3 w-3" />
                <span>Regenerate Brief</span>
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={runAi}
            disabled={aiLoading}
            className="flex items-center justify-center gap-2 w-full rounded-lg bg-sky-500 py-2.5 px-4 text-xs font-semibold text-slate-950 shadow-md transition hover:bg-sky-400 disabled:opacity-50"
          >
            {aiLoading ? (
              <>
                <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                <span>Synthesizing Intelligence Dossier…</span>
              </>
            ) : (
              <>
                <Sparkles className="h-4 w-4" />
                <span>Generate AI Intelligence Brief</span>
              </>
            )}
          </button>
        )}
      </Section>

      {/* Incident Response Playbook / Action Checklist */}
      <Section icon={CheckCircle2} title="Recommended Action Plan">
        <div className="space-y-1.5">
          {a.recommendations.map((r, i) => {
            const isDone = completedActions.has(i);
            return (
              <button
                key={i}
                onClick={() => toggleAction(i)}
                className={`flex w-full items-start gap-2.5 rounded-lg border p-2.5 text-left text-xs transition ${
                  isDone
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200 line-through opacity-75"
                    : "border-slate-800 bg-slate-900/40 text-slate-200 hover:border-slate-700 hover:bg-slate-800/40"
                }`}
              >
                <div
                  className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border ${
                    isDone
                      ? "border-emerald-500 bg-emerald-500 text-white"
                      : "border-slate-600 bg-slate-800"
                  }`}
                >
                  {isDone && <Check className="h-3 w-3" />}
                </div>
                <span className="leading-relaxed">{r}</span>
              </button>
            );
          })}
        </div>
      </Section>
    </div>
  );
}

