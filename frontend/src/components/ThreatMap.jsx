import { MapContainer, TileLayer, CircleMarker, Polyline, Tooltip, Marker } from "react-leaflet";
import L from "leaflet";
import { SEV } from "../api";
import { Globe, Shield, Radio } from "lucide-react";

// Protected network location (HQ Defense Perimeter)
const TARGET = [20.59, 78.96];

const targetIcon = L.divIcon({
  className: "custom-target-marker",
  html: `
    <div style="position:relative; display:flex; align-items:center; justify-content:center; width:32px; height:32px;">
      <div style="position:absolute; width:100%; height:100%; border-radius:50%; background:rgba(14,165,233,0.3); animation:ping 2s cubic-bezier(0,0,0.2,1) infinite;"></div>
      <div style="position:relative; width:26px; height:26px; border-radius:50%; background:#0284c7; border:2px solid #38bdf8; display:flex; align-items:center; justify-content:center; box-shadow:0 0 14px rgba(56,189,248,0.8); color:white; font-size:13px; font-weight:bold;">
        🛡️
      </div>
    </div>
  `,
  iconSize: [32, 32],
  iconAnchor: [16, 16],
});

export default function ThreatMap({ points, selectedId, onSelect }) {
  return (
    <div className="card space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="card-title !mb-0">
          <Globe className="h-4 w-4 text-sky-400" />
          <span>Global Threat Telemetry Map</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-mono">{points.length} nodes active</span>
          </span>
          <span className="hidden sm:inline text-slate-600">|</span>
          <span className="hidden sm:inline font-mono text-[11px] text-slate-500">
            Target: HQ Defense [20.59°N, 78.96°E]
          </span>
        </div>
      </div>

      <div className="relative overflow-hidden rounded-xl border border-slate-800">
        <MapContainer
          center={[28, 40]}
          zoom={2}
          minZoom={2}
          style={{ height: 330 }}
          worldCopyJump
          className="z-0"
        >
          <TileLayer
            attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?key=cb1_4f1z_1_1bbfcef27c3b2971c7a90bed"
          />
          <Marker position={TARGET} icon={targetIcon}>
            <Tooltip direction="top" offset={[0, -16]}>
              <div className="font-sans font-semibold text-sky-400">
                🛡️ Internal Protected Perimeter
              </div>
              <div className="text-[11px] text-slate-300">
                Monitoring incoming inbound connections
              </div>
            </Tooltip>
          </Marker>
          {points.map((p) => {
            const sevInfo = SEV[p.severity] || SEV.low;
            const c = sevInfo.color;
            const pos = [p.geo.lat, p.geo.lon];
            const sel = p.id === selectedId;

            return (
              <span key={p.id}>
                <Polyline
                  positions={[pos, TARGET]}
                  pathOptions={{
                    color: c,
                    weight: sel ? 2.5 : 1,
                    opacity: sel ? 0.95 : 0.35,
                    dashArray: sel ? undefined : "5 6",
                  }}
                />
                <CircleMarker
                  center={pos}
                  radius={sel ? 12 : 6 + p.risk_score / 25}
                  pathOptions={{
                    color: c,
                    fillColor: c,
                    fillOpacity: sel ? 0.85 : 0.55,
                    weight: sel ? 3 : 1.5,
                  }}
                  eventHandlers={{ click: () => onSelect(p.id) }}
                >
                  <Tooltip direction="top">
                    <div className="font-sans">
                      <div className="font-bold text-slate-100">{p.indicator}</div>
                      <div className="text-xs text-slate-300">
                        {p.geo.country} {p.geo.city ? `· ${p.geo.city}` : ""}
                      </div>
                      <div className="mt-1 flex items-center gap-1.5 text-xs">
                        <span
                          className="font-bold uppercase"
                          style={{ color: c }}
                        >
                          Risk {p.risk_score} ({p.severity})
                        </span>
                        {p.malware && (
                          <span className="text-slate-400">· {p.malware}</span>
                        )}
                      </div>
                      {p.cves.length > 0 && (
                        <div className="mt-0.5 font-mono text-[11px] text-amber-400">
                          {p.cves.join(", ")}
                        </div>
                      )}
                    </div>
                  </Tooltip>
                </CircleMarker>
              </span>
            );
          })}
        </MapContainer>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
        <p>
          Coordinates reflect hostile infrastructure hosting location, not necessarily attacker origin.
        </p>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-rose-500" /> Critical
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-orange-500" /> High
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-amber-500" /> Medium
          </span>
          <span className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-emerald-500" /> Low
          </span>
        </div>
      </div>
    </div>
  );
}

