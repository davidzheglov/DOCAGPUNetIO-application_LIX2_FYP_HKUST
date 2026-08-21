import { useCallback, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Play, Radio, SquareActivity } from "lucide-react";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";
import { CommandConsole } from "@/components/CommandConsole";

export function LivePipeline() {
  const [tier, setTier] = useState(1);
  const [symbols, setSymbols] = useState("BTCUSDT,ETHUSDT");
  const [rate, setRate] = useState<number | "">("");
  const [job, setJob] = useState<Job | null>(null);
  const start = useMutation({
    mutationFn: api.startLive,
    onSuccess: (data) => setJob(data.job),
  });
  const stop = useMutation({
    mutationFn: (id: string) => api.stopJob(id),
    onSuccess: (data) => setJob(data.job),
  });
  const updateJob = useCallback((next: Job) => setJob(next), []);

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Live Pipeline</div>
          <h1>Run the Binance-to-DPU relay path and watch the pipeline stay hot.</h1>
        </div>
        <button
          className="primary-button"
          onClick={() => start.mutate({ tier, symbols, rate_hz: rate === "" ? null : Number(rate) })}
        >
          <Play size={17} />
          Start Live
        </button>
      </section>

      <div className="dashboard-grid dashboard-grid--wide-left">
        <section className="glass-panel control-panel">
          <div className="panel-heading">
            <div>
              <h2>Live Controls</h2>
              <p>Launches `scripts/run_live_pipeline.sh` through the API adapter.</p>
            </div>
            <Radio size={20} />
          </div>
          <div className="form-grid">
            <label>
              <span>Tier</span>
              <select value={tier} onChange={(event) => setTier(Number(event.target.value))}>
                <option value={1}>T1 CPU receiver</option>
                <option value={2}>T2 DPDK receiver</option>
                <option value={3}>T3 RDMA receiver</option>
                <option value={4}>T4 GPUNetIO receiver</option>
              </select>
            </label>
            <label>
              <span>Symbols</span>
              <input value={symbols} onChange={(event) => setSymbols(event.target.value)} />
            </label>
            <label>
              <span>Rate Limit</span>
              <input value={rate} onChange={(event) => setRate(event.target.value ? Number(event.target.value) : "")} placeholder="unlimited" />
            </label>
          </div>
        </section>
        <section className="glass-panel live-readout">
          <SquareActivity size={28} />
          <strong>Signal Surface</strong>
          <div className="signal-meter">
            <span>RSI</span>
            <div><i style={{ width: "61%" }} /></div>
          </div>
          <div className="signal-meter">
            <span>EMA spread</span>
            <div><i style={{ width: "42%" }} /></div>
          </div>
          <p>When the receiver emits SignalResult packets, this panel can be extended to show buy/sell/hold, RSI, EMA, spread, and mid price in real time.</p>
        </section>
      </div>

      <CommandConsole job={job} onJobUpdate={updateJob} onStop={() => job?.id && stop.mutate(job.id)} />
    </div>
  );
}
