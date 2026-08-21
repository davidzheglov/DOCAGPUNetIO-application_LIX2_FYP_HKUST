import type { BenchmarkRequest, DpuArtifact, DpuDemoRequest, Health, Job, RemoteTerminalRequest, RunItem, TerminalSession, TerminalSessionRequest } from "./types";

const API_CANDIDATES = [
  "http://127.0.0.1:8002",
  import.meta.env.VITE_API_URL,
  "http://127.0.0.1:8001",
  "http://127.0.0.1:8000",
].filter((url, index, urls): url is string => Boolean(url) && urls.indexOf(url) === index);

let activeApiUrl = API_CANDIDATES[0];

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.text();
    if (!body) return response.statusText;
    try {
      const parsed = JSON.parse(body) as { detail?: unknown };
      return typeof parsed.detail === "string" ? parsed.detail : body;
    } catch {
      return body;
    }
  } catch {
    return response.statusText;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const candidates = [activeApiUrl, ...API_CANDIDATES.filter((url) => url !== activeApiUrl)];
  let lastError: unknown = null;

  for (const apiUrl of candidates) {
    try {
      const response = await fetch(`${apiUrl}${path}`, {
        headers: {
          "Content-Type": "application/json",
          ...(init?.headers ?? {}),
        },
        ...init,
      });
      if (response.ok) {
        activeApiUrl = apiUrl;
        return response.json() as Promise<T>;
      }

      const detail = await readError(response);
      lastError = new Error(`${response.status} ${response.statusText}: ${detail}`);

      if (response.status === 404 && API_CANDIDATES.length > 1) {
        continue;
      }
      throw lastError;
    } catch (error) {
      lastError = error;
      if (API_CANDIDATES.length <= 1) break;
    }
  }

  const message = lastError instanceof Error ? lastError.message : String(lastError ?? "API request failed");
  throw new Error(`Backend request failed for ${path}. Tried ${candidates.join(", ")}. Last error: ${message}`);
}

export const api = {
  get baseUrl() {
    return activeApiUrl;
  },
  candidates: API_CANDIDATES,
  wsUrl(jobId: string) {
    const url = new URL(activeApiUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = `/api/jobs/${jobId}/logs`;
    return url.toString();
  },
  terminalWsUrl(sessionId: string) {
    const url = new URL(activeApiUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = `/api/terminal/sessions/${sessionId}/logs`;
    return url.toString();
  },
  artifactUrl(path: string) {
    return `${activeApiUrl}${path}`;
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
  startDpuDemo: (payload: DpuDemoRequest) =>
    request<{ job: Job }>("/api/dpu/demo", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  startRemoteTerminal: (payload: RemoteTerminalRequest) =>
    request<{ job: Job }>("/api/dpu/terminal", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  dpuArtifacts: () => request<{ artifacts: DpuArtifact[] }>("/api/dpu/artifacts"),
  createTerminalSession: (payload: TerminalSessionRequest) =>
    request<{ session: TerminalSession }>("/api/terminal/sessions", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  sendTerminalInput: (sessionId: string, text: string) =>
    request<{ session: TerminalSession }>(`/api/terminal/sessions/${sessionId}/input`, {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  interruptTerminalSession: (sessionId: string) =>
    request<{ session: TerminalSession }>(`/api/terminal/sessions/${sessionId}/interrupt`, {
      method: "POST",
    }),
  closeTerminalSession: (sessionId: string) =>
    request<{ session: TerminalSession }>(`/api/terminal/sessions/${sessionId}/close`, {
      method: "POST",
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
