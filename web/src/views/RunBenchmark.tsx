import { useCallback, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Hammer, Play, Settings, TerminalSquare, Wrench } from "lucide-react";
import { api } from "@/lib/api";
import type { BenchmarkRequest, Job } from "@/lib/types";
import { CommandConsole } from "@/components/CommandConsole";

const defaults: BenchmarkRequest = {
  tier: 4,
  rate_hz: 50000,
  repetition: 1,
  warmup_sec: 5,
  duration_sec: 30,
  gpu_index: 1,
  gpu_pcie: "0000:ac:00.0",
  nic_pcie: "0000:bd:00.1",
  receiver_init_sec: 15,
  ssh: "ubuntu@192.168.100.2",
  dpu_repo: "/home/ubuntu/DOCAGPUNetIO-application_LIX2_FYP_HKUST",
  dpu_bind_ip: "10.10.10.1",
  host_iface: "ens21f1np1",
  manual: false,
  calibrate: true,
  nsys: false,
};

export function RunBenchmark() {
  const [form, setForm] = useState(defaults);
  const [job, setJob] = useState<Job | null>(null);
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const startBenchmark = useMutation({
    mutationFn: api.startBenchmark,
    onSuccess: (data) => setJob(data.job),
  });
  const build = useMutation({
    mutationFn: api.build,
    onSuccess: (data) => setJob(data.job),
  });
  const stopJob = useMutation({
    mutationFn: (id: string) => api.stopJob(id),
    onSuccess: (data) => setJob(data.job),
  });

  const updateJob = useCallback((next: Job) => setJob(next), []);

  function setValue<K extends keyof BenchmarkRequest>(key: K, value: BenchmarkRequest[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Benchmark Launcher</div>
          <h1>Start controlled runs and watch the native pipeline report back.</h1>
        </div>
        <button className="primary-button" onClick={() => startBenchmark.mutate(form)} disabled={startBenchmark.isPending}>
          <Play size={17} />
          Start Benchmark
        </button>
      </section>

      <div className="dashboard-grid dashboard-grid--wide-left">
        <section className="glass-panel control-panel">
          <div className="panel-heading">
            <div>
              <h2>Run Configuration</h2>
              <p>Tiers 1, 4, and 5 are wired through the single-run benchmark driver.</p>
            </div>
            <Settings size={20} />
          </div>

          <div className="form-grid">
            <label>
              <span>Tier</span>
              <select value={form.tier} onChange={(event) => setValue("tier", Number(event.target.value))}>
                <option value={1}>T1 CPU naive</option>
                <option value={4}>T4 GPUNetIO</option>
                <option value={5}>T5 GPUNetIO + DPU</option>
              </select>
            </label>
            <label>
              <span>Rate</span>
              <select value={form.rate_hz} onChange={(event) => setValue("rate_hz", Number(event.target.value))}>
                {[10000, 25000, 50000, 100000, 250000, 500000, 1000000].map((rate) => (
                  <option value={rate} key={rate}>{rate.toLocaleString()} ticks/sec</option>
                ))}
              </select>
            </label>
            <label>
              <span>Warmup</span>
              <input type="number" min={0} value={form.warmup_sec} onChange={(event) => setValue("warmup_sec", Number(event.target.value))} />
            </label>
            <label>
              <span>Duration</span>
              <input type="number" min={1} value={form.duration_sec} onChange={(event) => setValue("duration_sec", Number(event.target.value))} />
            </label>
            <label>
              <span>Repetition</span>
              <input type="number" min={1} value={form.repetition} onChange={(event) => setValue("repetition", Number(event.target.value))} />
            </label>
            <label>
              <span>GPU Index</span>
              <input type="number" min={0} value={form.gpu_index} onChange={(event) => setValue("gpu_index", Number(event.target.value))} />
            </label>
            <label>
              <span>GPU PCIe</span>
              <input value={form.gpu_pcie} onChange={(event) => setValue("gpu_pcie", event.target.value)} />
            </label>
            <label>
              <span>NIC PCIe</span>
              <input value={form.nic_pcie} onChange={(event) => setValue("nic_pcie", event.target.value)} />
            </label>
            <label>
              <span>DPU SSH</span>
              <input value={form.ssh} onChange={(event) => setValue("ssh", event.target.value)} />
            </label>
            <label>
              <span>DPU Bind IP</span>
              <input value={form.dpu_bind_ip} onChange={(event) => setValue("dpu_bind_ip", event.target.value)} />
            </label>
            <label>
              <span>Host Interface</span>
              <input value={form.host_iface} onChange={(event) => setValue("host_iface", event.target.value)} />
            </label>
            <label>
              <span>Receiver Init</span>
              <input type="number" min={1} value={form.receiver_init_sec} onChange={(event) => setValue("receiver_init_sec", Number(event.target.value))} />
            </label>
          </div>

          <div className="toggle-row">
            <button className={form.calibrate ? "toggle is-on" : "toggle"} onClick={() => setValue("calibrate", !form.calibrate)}>Clock calibration</button>
            <button className={form.manual ? "toggle is-on" : "toggle"} onClick={() => setValue("manual", !form.manual)}>Manual sender</button>
            <button className={form.nsys ? "toggle is-on" : "toggle"} onClick={() => setValue("nsys", !form.nsys)}>Nsight capture</button>
          </div>
        </section>

        <section className="glass-panel preflight-panel">
          <div className="panel-heading">
            <div>
              <h2>Preflight</h2>
              <p>{health.data?.native_pipeline_note ?? "API health is loading."}</p>
            </div>
            <TerminalSquare size={20} />
          </div>
          <div className="status-list">
            {Object.entries(health.data?.binaries ?? {}).map(([name, ok]) => (
              <div key={name}>
                <span className={`status-dot status-dot--${ok ? "completed" : "failed"}`} />
                <span>{name}</span>
              </div>
            ))}
          </div>
          <div className="build-buttons">
            {["core", "t1", "t4", "data_source_live"].map((target) => (
              <button key={target} className="secondary-button" onClick={() => build.mutate(target)}>
                <Wrench size={16} />
                make {target}
              </button>
            ))}
          </div>
        </section>
      </div>

      <CommandConsole
        job={job}
        onJobUpdate={updateJob}
        onStop={() => job?.id && stopJob.mutate(job.id)}
      />
    </div>
  );
}
