import {
  Bar,
  BarChart,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Pie,
  PieChart,
} from "recharts";
import { SEV } from "../api";
import { PieChart as PieIcon, BarChart3 } from "lucide-react";

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0];
    return (
      <div className="rounded-lg border border-slate-700/80 bg-slate-900/95 p-2.5 shadow-xl backdrop-blur-md">
        <p className="text-xs font-semibold text-slate-200">
          {data.payload.name || data.name}
        </p>
        <p className="mt-1 font-mono text-xs text-sky-400">
          Count: <span className="font-bold text-white">{data.value}</span>
        </p>
      </div>
    );
  }
  return null;
};

export default function Charts({ stats }) {
  if (!stats) return null;

  const totalThreats =
    stats.by_severity?.reduce((sum, item) => sum + item.count, 0) || 0;

  return (
    <div className="grid gap-3.5 md:grid-cols-2">
      {/* Severity Donut */}
      <div className="card">
        <div className="card-title">
          <PieIcon className="h-4 w-4 text-sky-400" />
          <span>Severity Distribution</span>
        </div>
        <div className="relative">
          <ResponsiveContainer width="100%" height={175}>
            <PieChart>
              <Pie
                data={stats.by_severity}
                dataKey="count"
                nameKey="severity"
                innerRadius={48}
                outerRadius={72}
                paddingAngle={3}
                stroke="none"
              >
                {stats.by_severity.map((s) => (
                  <Cell
                    key={s.severity}
                    fill={SEV[s.severity]?.color || "#38bdf8"}
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-extrabold tabular-nums text-slate-100">
              {totalThreats}
            </span>
            <span className="text-[10px] uppercase tracking-wider text-slate-400">
              Total
            </span>
          </div>
        </div>

        <div className="mt-2 flex flex-wrap justify-center gap-2 text-[11px]">
          {stats.by_severity.map((s) => {
            const sevInfo = SEV[s.severity] || SEV.low;
            const pct = totalThreats
              ? Math.round((s.count / totalThreats) * 100)
              : 0;
            return (
              <span
                key={s.severity}
                className="flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/60 px-2.5 py-0.5"
              >
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ backgroundColor: sevInfo.color }}
                />
                <span className="capitalize text-slate-300">{s.severity}</span>
                <span className="font-mono text-slate-400 font-semibold">{s.count}</span>
                <span className="text-[10px] text-slate-500">({pct}%)</span>
              </span>
            );
          })}
        </div>
      </div>

      {/* MITRE ATT&CK Bars */}
      <div className="card">
        <div className="card-title">
          <BarChart3 className="h-4 w-4 text-sky-400" />
          <span>Top MITRE ATT&CK Techniques</span>
        </div>
        <ResponsiveContainer width="100%" height={210}>
          <BarChart
            data={stats.top_techniques}
            layout="vertical"
            margin={{ left: 10, right: 10, top: 5, bottom: 5 }}
          >
            <XAxis type="number" hide allowDecimals={false} />
            <YAxis
              type="category"
              dataKey="id"
              width={70}
              tick={{ fill: "#94a3b8", fontSize: 11, fontFamily: "monospace" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(56, 189, 248, 0.08)" }} />
            <Bar
              dataKey="count"
              fill="#0ea5e9"
              radius={[0, 6, 6, 0]}
              barSize={14}
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

