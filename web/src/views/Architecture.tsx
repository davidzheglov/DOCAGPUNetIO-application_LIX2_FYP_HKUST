import { useState } from "react";
import { ArrowRight, Cpu, Database, Network, Server, Zap } from "lucide-react";
import { tierCopy } from "@/lib/demo";
import { tierName } from "@/lib/format";

const tierIds = [1, 2, 3, 4] as const;

export function Architecture() {
  const [tier, setTier] = useState<(typeof tierIds)[number]>(4);
  const active = tierCopy[tier];

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Architecture</div>
          <h1>Present the benchmark as a packet journey across CPU, NIC, DPU, and GPU memory.</h1>
        </div>
      </section>

      <section className="glass-panel architecture-stage">
        <div className="tier-selector">
          {tierIds.map((id) => (
            <button key={id} className={tier === id ? "is-active" : ""} onClick={() => setTier(id)}>
              {tierName(id)}
            </button>
          ))}
        </div>

        <div className="architecture-visual">
          <div className="chip chip--source">
            <Database size={28} />
            <strong>Tick Source</strong>
            <span>Replay or live Binance</span>
          </div>
          <ArrowRight className="arch-arrow" />
          <div className="chip chip--nic">
            <Network size={28} />
            <strong>BlueField-3</strong>
            <span>{tier >= 4 ? "DOCA Flow steering" : "Network ingress"}</span>
          </div>
          <ArrowRight className="arch-arrow" />
          <div className="chip chip--gpu">
            <Zap size={28} />
            <strong>GPU VRAM</strong>
            <span>{tier >= 3 ? "Direct packet landing" : "cudaMemcpy batch"}</span>
          </div>
          <ArrowRight className="arch-arrow" />
          <div className="chip chip--host">
            <Server size={28} />
            <strong>Harness</strong>
            <span>Latency and drop metrics</span>
          </div>
        </div>

        <div className="architecture-copy">
          <div>
            <Cpu size={22} />
            <strong>{active.name}</strong>
          </div>
          <p>{active.path}</p>
          <span>{active.signal}</span>
        </div>
      </section>

      <section className="glass-panel explain-grid">
        <div>
          <strong>BenchmarkResult</strong>
          <span>48-byte UDP result with T1, T2, T3, T4 timestamps.</span>
        </div>
        <div>
          <strong>SignalResult</strong>
          <span>64-byte trading signal with RSI, spread, fast EMA, and slow EMA.</span>
        </div>
        <div>
          <strong>Ingest Jitter</strong>
          <span>Host-only T2 inter-arrival metric used for the trustworthy latency story.</span>
        </div>
      </section>
    </div>
  );
}
