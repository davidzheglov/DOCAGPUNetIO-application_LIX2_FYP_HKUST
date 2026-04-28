import { Activity, Cpu, Gauge, RadioTower, Timer, Zap } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { compactNumber, fixed, percent, tierName, timeAgo } from "@/lib/format";
import { demoRuns } from "@/lib/demo";
import type { RunSummary } from "@/lib/types";
import { MetricCard } from "@/components/MetricCard";
import { ChartPanel } from "@/components/ChartPanel";
import { TierBadge } from "@/components/TierBadge";

export function Overview() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const summaries: RunSummary[] = runs.data?.runs.map((run) => run.summary).filter(Boolean) ?? [];
  const data = summaries.length ? summaries : demoRuns;
  const latest = data[0];

  const latencyOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: 48, right: 16, top: 36, bottom: 40 },
    xAxis: {
      type: "category",
      data: data.map((item) => tierName(item.tier)),
      axisLabel: { color: "#b7c2cc" },
      axisLine: { lineStyle: { color: "#334155" } },
    },
    yAxis: {
      type: "value",
      name: "p99 us",
      nameTextStyle: { color: "#91a2b1" },
      axisLabel: { color: "#b7c2cc" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,.14)" } },
    },
    series: [
      {
        name: "Compute p99",
        type: "bar",
        data: data.map((item) => item.compute_p99_us ?? 0),
        itemStyle: { color: "#74f0c2", borderRadius: [5, 5, 0, 0] },
      },
      {
        name: "Jitter |p99|",
        type: "line",
        smooth: true,
        data: data.map((item) => item.jitter_abs_p99_us ?? 0),
        lineStyle: { color: "#f6c76d", width: 3 },
        symbolSize: 8,
      },
    ],
  };

  return (
    <div className="view-stack">
      <section className="hero-band">
        <div>
          <div className="eyebrow">DOCAGPUNetIO Benchmark Cockpit</div>
          <h1>GPU packet path, benchmark control, and result intelligence in one surface.</h1>
        </div>
        <div className="hero-status glass-panel">
          <span className={`status-dot status-dot--${health.data?.ok ? "completed" : "failed"}`} />
          <div>
            <strong>{health.data?.platform.system ?? "API offline"}</strong>
            <span>{health.data?.native_pipeline_note ?? "Start the API adapter on port 8000."}</span>
          </div>
        </div>
      </section>

      <div className="metric-grid">
        <MetricCard label="Latest Tier" value={tierName(latest?.tier)} hint={timeAgo(latest?.timestamp)} icon={Cpu} tone="cyan" />
        <MetricCard label="Achieved Throughput" value={compactNumber(latest?.achieved_hz)} hint={`target ${compactNumber(latest?.target_hz ?? latest?.rate_hz)}/s`} icon={Gauge} tone="green" />
        <MetricCard label="Compute p99" value={fixed(latest?.compute_p99_us, 2, " us")} hint="GPU-side timing" icon={Timer} tone="amber" />
        <MetricCard label="Drop Rate" value={percent(latest?.drop_rate)} hint={`${compactNumber(latest?.received)} received`} icon={RadioTower} tone="rose" />
      </div>

      <div className="dashboard-grid dashboard-grid--wide-left">
        <section className="glass-panel pipeline-map">
          <div className="panel-heading">
            <div>
              <h2>Packet Path</h2>
              <p>Native pipeline components exposed through a browser-safe adapter.</p>
            </div>
            <TierBadge tier={latest?.tier ?? 4} />
          </div>
          <div className="packet-flow">
            {["Data Source", "BlueField NIC", "GPU RX Queue", "CUDA Kernel", "Harness"].map((step, index) => (
              <div className="flow-node" key={step}>
                <span>{index + 1}</span>
                <strong>{step}</strong>
              </div>
            ))}
          </div>
          <div className="tool-status-grid">
            {Object.entries(health.data?.tools ?? {}).map(([name, ok]) => (
              <div className="tool-status" key={name}>
                <span className={`status-dot status-dot--${ok ? "completed" : "failed"}`} />
                <span>{name}</span>
              </div>
            ))}
          </div>
        </section>

        <ChartPanel
          title="Latency Signature"
          subtitle={summaries.length ? "From real result summaries" : "Demo data until the first run is captured"}
          option={latencyOption}
        />
      </div>

      <section className="glass-panel tier-strip">
        {[1, 2, 3, 4, 5].map((tier) => (
          <div className="tier-strip__item" key={tier}>
            <Zap size={18} />
            <strong>{tierName(tier)}</strong>
            <span>{tier === 1 ? "CPU copies" : tier === 4 ? "Zero-copy GPUNetIO" : tier === 5 ? "DPU sourced" : "Advanced path"}</span>
          </div>
        ))}
      </section>
    </div>
  );
}
