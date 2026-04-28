import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { demoRuns } from "@/lib/demo";
import { compactNumber, fixed, tierName } from "@/lib/format";
import { ChartPanel } from "@/components/ChartPanel";
import type { RunSummary } from "@/lib/types";

export function Comparison() {
  const comparison = useQuery({ queryKey: ["comparison"], queryFn: api.comparison });
  const summaries: RunSummary[] = comparison.data?.runs.map((run) => run.summary).filter(Boolean) ?? [];
  const data = summaries.length ? summaries : demoRuns;
  const baseline = data.find((item) => item.tier === 1)?.e2e_p99_us ?? data[0]?.e2e_p99_us ?? 1;

  const throughputOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    grid: { left: 56, right: 20, top: 32, bottom: 48 },
    xAxis: {
      type: "value",
      name: "throughput",
      nameTextStyle: { color: "#91a2b1" },
      axisLabel: { color: "#b7c2cc" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,.12)" } },
    },
    yAxis: {
      type: "value",
      name: "p99 us",
      nameTextStyle: { color: "#91a2b1" },
      axisLabel: { color: "#b7c2cc" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,.12)" } },
    },
    series: [
      {
        name: "Runs",
        type: "scatter",
        symbolSize: 16,
        data: data.map((item) => [item.achieved_hz ?? item.rate_hz ?? 0, item.e2e_p99_us ?? 0, tierName(item.tier)]),
        itemStyle: { color: "#7dd3fc" },
      },
    ],
  };

  const speedupOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: 48, right: 20, top: 30, bottom: 42 },
    xAxis: {
      type: "category",
      data: data.map((item) => tierName(item.tier)),
      axisLabel: { color: "#b7c2cc" },
      axisLine: { lineStyle: { color: "#334155" } },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "#b7c2cc" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,.12)" } },
    },
    series: [
      {
        type: "bar",
        data: data.map((item) => baseline / Math.max(item.e2e_p99_us ?? baseline, 0.001)),
        itemStyle: { color: "#74f0c2", borderRadius: [5, 5, 0, 0] },
      },
    ],
  };

  const jitterOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "axis" },
    grid: { left: 50, right: 20, top: 32, bottom: 42 },
    xAxis: {
      type: "category",
      data: data.map((item) => tierName(item.tier)),
      axisLabel: { color: "#b7c2cc" },
      axisLine: { lineStyle: { color: "#334155" } },
    },
    yAxis: {
      type: "value",
      name: "us",
      nameTextStyle: { color: "#91a2b1" },
      axisLabel: { color: "#b7c2cc" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,.12)" } },
    },
    series: [
      {
        name: "Jitter |p99|",
        type: "line",
        smooth: true,
        data: data.map((item) => item.jitter_abs_p99_us ?? 0),
        lineStyle: { color: "#f6c76d", width: 3 },
        areaStyle: { color: "rgba(246,199,109,.12)" },
      },
    ],
  };

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Tier Comparison</div>
          <h1>Turn benchmark captures into the story: fewer CPU copies, tighter jitter, higher throughput.</h1>
        </div>
      </section>

      <div className="comparison-table glass-panel">
        <table>
          <thead>
            <tr>
              <th>Tier</th>
              <th>Rate</th>
              <th>Achieved</th>
              <th>p99 E2E</th>
              <th>p99 Compute</th>
              <th>Jitter |p99|</th>
              <th>Speedup</th>
            </tr>
          </thead>
          <tbody>
            {data.map((item, index) => (
              <tr key={`${item.tier}-${item.rate_hz}-${index}`}>
                <td>{tierName(item.tier)}</td>
                <td>{compactNumber(item.rate_hz)}</td>
                <td>{compactNumber(item.achieved_hz)}</td>
                <td>{fixed(item.e2e_p99_us, 2, " us")}</td>
                <td>{fixed(item.compute_p99_us, 2, " us")}</td>
                <td>{fixed(item.jitter_abs_p99_us, 2, " us")}</td>
                <td>{fixed(baseline / Math.max(item.e2e_p99_us ?? baseline, 0.001), 2, "x")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="dashboard-grid">
        <ChartPanel title="Throughput vs Tail Latency" subtitle="p99 end-to-end latency against achieved rate" option={throughputOption} />
        <ChartPanel title="Speedup vs T1" subtitle="Higher is better" option={speedupOption} />
        <ChartPanel title="Clock-Independent Ingest Jitter" subtitle="Host-side T2 inter-arrival jitter" option={jitterOption} />
      </div>
    </div>
  );
}
