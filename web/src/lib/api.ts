import type { BenchmarkRequest, Health, Job, RunItem } from "./types";

const API_URL = import.meta.env.VITE_API_URL ?? "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || response.statusText);
  }
  return response.json() as Promise<T>;
}

export const api = {
  baseUrl: API_URL,
  wsUrl(jobId: string) {
    const url = new URL(API_URL);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = `/api/jobs/${jobId}/logs`;
    return url.toString();
  },
  health: () => request<Health>("/api/health"),
  runs: () => request<{ runs: RunItem[] }>("/api/runs"),
  run: (runName: string) => request<{ run: RunItem; summary_json: unknown; bench_preview: unknown; logs: Record<string, string> }>(`/api/runs/${encodeURIComponent(runName)}`),
  comparison: () => request<{ runs: RunItem[] }>("/api/comparison"),
  jobs: () => request<{ jobs: Job[] }>("/api/jobs"),
  job: (jobId: string) => request<{ job: Job }>(`/api/jobs/${jobId}`),
  startBenchmark: (payload: BenchmarkRequest) =>
    request<{ job: Job }>("/api/benchmark", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  startLive: (payload: { tier: number; symbols: string; rate_hz?: number | null }) =>
    request<{ job: Job }>("/api/live/start", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  build: (target: string) =>
    request<{ job: Job }>("/api/build", {
      method: "POST",
      body: JSON.stringify({ target }),
    }),
  analyze: (runName: string) =>
    request<{ job: Job }>(`/api/runs/${encodeURIComponent(runName)}/analyze`, {
      method: "POST",
    }),
  stopJob: (jobId: string) =>
    request<{ job: Job }>(`/api/jobs/${jobId}/stop`, {
      method: "POST",
    }),
};
