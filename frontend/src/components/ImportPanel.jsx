import { useRef, useState } from "react";
import { api } from "../api";
import {
  UploadCloud,
  RotateCcw,
  DownloadCloud,
  Radio,
  CheckCircle,
  AlertCircle,
  Loader2,
  Zap,
} from "lucide-react";

export default function ImportPanel({ onImported }) {
  const ref = useRef();
  const [msg, setMsg] = useState(null);
  const [busyAction, setBusyAction] = useState(null);

  const run = async (actionKey, fn, label) => {
    setBusyAction(actionKey);
    setMsg(null);
    try {
      const res = await fn();
      const count =
        res.imported ??
        res.collected ??
        res.seeded ??
        res.techniques_loaded ??
        "Success";
      setMsg({
        ok: true,
        text: `${label}: ${typeof count === "object" ? JSON.stringify(count) : `${count} records processed`}`,
      });
      await onImported(res);
      setTimeout(() => setMsg(null), 5000);
    } catch (e) {
      setMsg({ ok: false, text: `${label} failed: ${e.message}` });
      setTimeout(() => setMsg(null), 6000);
    } finally {
      setBusyAction(null);
    }
  };

  const isBusy = busyAction !== null;

  return (
    <div className="flex flex-wrap items-center gap-2">
      <input
        ref={ref}
        type="file"
        accept=".json"
        hidden
        onChange={(e) =>
          e.target.files[0] &&
          run("import", () => api.importFile(e.target.files[0]), "Imported JSON")
        }
      />

      {/* Import Button */}
      <button
        disabled={isBusy}
        onClick={() => ref.current.click()}
        className="flex items-center gap-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 px-3 py-1.5 text-xs font-semibold text-sky-300 shadow-sm transition hover:bg-sky-500/20 disabled:opacity-50"
      >
        {busyAction === "import" ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <UploadCloud className="h-3.5 w-3.5" />
        )}
        <span>Import IoC JSON</span>
      </button>

      {/* Reset Demo Data */}
      <button
        disabled={isBusy}
        onClick={() => run("seed", api.seed, "Reset Data")}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-300 shadow-sm transition hover:bg-slate-700 hover:text-white disabled:opacity-50"
      >
        {busyAction === "seed" ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <RotateCcw className="h-3.5 w-3.5" />
        )}
        <span>Reset Demo Data</span>
      </button>

      {/* Fetch NVD CVEs */}
      <button
        disabled={isBusy}
        onClick={() => run("cve", () => api.collect("cve"), "NVD Sync")}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-300 shadow-sm transition hover:bg-slate-700 hover:text-white disabled:opacity-50"
      >
        {busyAction === "cve" ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <DownloadCloud className="h-3.5 w-3.5" />
        )}
        <span>Sync NVD CVEs</span>
      </button>

      {/* Fetch CISA KEV */}
      <button
        disabled={isBusy}
        onClick={() => run("cisa", () => api.collect("cisa"), "CISA KEV")}
        className="flex items-center gap-1.5 rounded-lg border border-amber-500/50 bg-amber-500/10 px-3 py-1.5 text-xs font-semibold text-amber-300 shadow-sm transition hover:bg-amber-500/20 disabled:opacity-50"
      >
        {busyAction === "cisa" ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Zap className="h-3.5 w-3.5 text-amber-400" />
        )}
        <span>Sync CISA KEV</span>
      </button>

      {/* Fetch Feodo C2 */}
      <button
        disabled={isBusy}
        onClick={() => run("feodo", () => api.collect("feodo"), "Feodo Sync")}
        className="flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-300 shadow-sm transition hover:bg-slate-700 hover:text-white disabled:opacity-50"
      >
        {busyAction === "feodo" ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Radio className="h-3.5 w-3.5" />
        )}
        <span>Feodo C2 Feed</span>
      </button>

      {/* Notification Toast */}
      {msg && (
        <div
          className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium animate-fadeIn ${
            msg.ok
              ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
              : "border-rose-500/30 bg-rose-500/10 text-rose-300"
          }`}
        >
          {msg.ok ? (
            <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />
          ) : (
            <AlertCircle className="h-3.5 w-3.5 text-rose-400" />
          )}
          <span>{msg.text}</span>
        </div>
      )}
    </div>
  );
}

