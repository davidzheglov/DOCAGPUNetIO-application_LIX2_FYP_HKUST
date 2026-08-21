export type Health = {
  ok: boolean;
  repo_root: string;
  platform: {
    system: string;
    release: string;
    machine: string;
    python: string;
    uid: number | null;
  };
  native_pipeline_note: string;
  tools: Record<string, boolean>;
  python_packages?: Record<string, boolean>;
  binaries: Record<string, boolean>;
  results: {
    single_runs: number;
    benchmark_csv: boolean;
  };
};

export type RunSummary = {
  tier?: number | null;
  rate_hz?: number | null;
  timestamp?: string | null;
  duration_sec?: number | null;
  warmup_sec?: number | null;
  target_hz?: number | null;
  achieved_hz?: number | null;
  drop_rate?: number | null;
  received?: number | null;
  expected?: number | null;
  compute_p99_us?: number | null;
  egress_p99_us?: number | null;
  e2e_p99_us?: number | null;
  ingest_p99_us?: number | null;
  jitter_abs_p99_us?: number | null;
  jitter_abs_p95_us?: number | null;
};

export type RunItem = {
  name: string;
  path: string;
  mtime: number;
  updated_at: string;
  summary: RunSummary;
  files: Record<string, boolean>;
  plots: Array<{ name: string; path: string; url: string; kind: string }>;
};

export type DpuArtifact = {
  name: string;
  path: string;
  url: string;
  size_bytes: number;
  updated_at: string;
  mtime: number;
};

export type Job = {
  id: string;
  kind: string;
  status: "queued" | "running" | "stopping" | "completed" | "failed";
  command: string[];
  cwd: string;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  returncode?: number | null;
  log_path?: string | null;
  run_dir?: string | null;
  lines: string[];
};

export type BenchmarkRequest = {
  tier: number;
  rate_hz: number;
  repetition: number;
  warmup_sec: number;
  duration_sec: number;
  gpu_index: number;
  gpu_pcie: string;
  nic_pcie: string;
  receiver_init_sec: number;
  ssh: string;
  dpu_repo: string;
  dpu_bind_ip: string;
  host_iface: string;
  manual: boolean;
  calibrate: boolean;
  nsys: boolean;
};

export type DpuDemoRequest = {
  action: "preflight" | "diagnose" | "datapath" | "benchmark" | "live_sender" | "collect";
  receiver_host: string;
  sender_host: string;
  ssh_password: string;
  remote_repo: string;
  dpu_user: string;
  dpu_ip: string;
  receiver_iface: string;
  receiver_dpu_iface: string;
  sender_dpu_iface: string;
  relay_port: number;
  dpu_relay_path: string;
  live_symbols: string;
  live_rate_hz?: number | null;
  harness_ip: string;
  fillsim_ip: string;
  tiers: string;
  rates: string;
  reps: number;
  warmup_sec: number;
  duration_sec: number;
  csv_rows: number;
  csv_symbols: number;
  csv_path: string;
  regen_csv: boolean;
  local_sender: boolean;
  quick: boolean;
  light_bench: boolean;
  verbose_ssh: boolean;
  timeout_sec: number;
};

export type RemoteTerminalRequest = {
  name: "receiver" | "sender";
  host: string;
  ssh_password: string;
  remote_repo: string;
  dpu_user: string;
  dpu_ip: string;
  context: "host" | "dpu";
  command: string;
  use_repo: boolean;
  verbose_ssh: boolean;
  timeout_sec: number;
};

export type TerminalSession = {
  id: string;
  name: "receiver" | "sender";
  host: string;
  status: "connecting" | "connected" | "closed";
  created_at: string;
  completed_at?: string | null;
  returncode?: number | null;
  chunks: string[];
};

export type TerminalSessionRequest = {
  name: "receiver" | "sender";
  host: string;
  ssh_password: string;
  verbose_ssh: boolean;
};
