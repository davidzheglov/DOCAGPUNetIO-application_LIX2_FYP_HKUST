from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_DIR = REPO_ROOT / "results"
SINGLE_RESULTS_DIR = RESULTS_DIR / "single"
WEB_JOBS_DIR = RESULTS_DIR / "web_jobs"
MAX_LOG_LINES = 800


app = FastAPI(
    title="DOCAGPUNetIO Benchmark Cockpit API",
    version="0.1.0",
    description="HTTP/WebSocket adapter for the native GPUNetIO benchmark pipeline.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class BenchmarkRequest(BaseModel):
    tier: int = Field(4, description="Supported by scripts/benchmark.py: 1, 4, or 5")
    rate_hz: int = Field(50000, gt=0)
    repetition: int = Field(1, ge=1)
    warmup_sec: int = Field(5, ge=0)
    duration_sec: int = Field(30, ge=1)
    gpu_index: int = Field(1, ge=0)
    gpu_pcie: str = "0000:ac:00.0"
    nic_pcie: str = "0000:bd:00.1"
    receiver_init_sec: int = Field(15, ge=1)
    ssh: str = "ubuntu@192.168.100.2"
    dpu_repo: str = "/home/ubuntu/DOCAGPUNetIO-application_LIX2_FYP_HKUST"
    dpu_bind_ip: str = "10.10.10.1"
    host_iface: str = "ens21f1np1"
    manual: bool = False
    calibrate: bool = True
    nsys: bool = False


class LiveRequest(BaseModel):
    tier: int = Field(1, ge=1, le=4)
    symbols: str = "BTCUSDT,ETHUSDT"
    rate_hz: int | None = Field(None, gt=0)
    harness_ip: str = "127.0.0.1"
    fillsim_ip: str = "127.0.0.1"
    dpu_user: str = "ubuntu"
    dpu_ip: str = "192.168.100.2"


class BuildRequest(BaseModel):
    target: str = Field("core", pattern="^(core|all|data_source|data_source_live|dpu_relay|dpu_relay_dpu|t1|t2|t3|t4|fill_sim|harness|dashboard|test_flow)$")


class DashboardRequest(BaseModel):
    results_path: str = "results/benchmark.csv"
    out_dir: str = "results/plots"


@dataclass
class Job:
    id: str
    kind: str
    command: list[str]
    cwd: Path
    created_at: str
    status: str = "queued"
    started_at: str | None = None
    completed_at: str | None = None
    returncode: int | None = None
    log_path: Path | None = None
    run_dir: str | None = None
    process: subprocess.Popen[str] | None = field(default=None, repr=False)
    lines: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def append(self, line: str) -> None:
        with self.lock:
            self.lines.append(line.rstrip("\n"))
            if len(self.lines) > MAX_LOG_LINES:
                self.lines = self.lines[-MAX_LOG_LINES:]

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "status": self.status,
                "command": self.command,
                "cwd": str(self.cwd),
                "created_at": self.created_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "returncode": self.returncode,
                "log_path": str(self.log_path) if self.log_path else None,
                "run_dir": self.run_dir,
                "lines": list(self.lines[-120:]),
            }


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def parse_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def flatten_run_summary(summary: dict[str, Any]) -> dict[str, Any]:
    run = summary.get("run", {})
    throughput = summary.get("throughput", {})
    latency = summary.get("latency_us", {})
    jitter = summary.get("ingest_jitter_us", {})

    return {
        "tier": run.get("tier"),
        "rate_hz": run.get("rate_hz"),
        "timestamp": run.get("timestamp"),
        "duration_sec": run.get("duration_sec"),
        "warmup_sec": run.get("warmup_sec"),
        "target_hz": throughput.get("target_hz"),
        "achieved_hz": throughput.get("achieved_hz"),
        "drop_rate": throughput.get("drop_rate"),
        "received": throughput.get("received"),
        "expected": throughput.get("expected"),
        "compute_p99_us": (latency.get("compute") or {}).get("p99"),
        "egress_p99_us": (latency.get("egress") or {}).get("p99"),
        "e2e_p99_us": (latency.get("e2e") or {}).get("p99"),
        "ingest_p99_us": (latency.get("ingest") or {}).get("p99"),
        "jitter_abs_p99_us": jitter.get("abs_p99"),
        "jitter_abs_p95_us": jitter.get("abs_p95"),
    }


def list_plot_files(run_dir: Path) -> list[dict[str, str]]:
    plots_dir = run_dir / "plots"
    if not plots_dir.exists():
        return []
    plots = []
    for path in sorted(plots_dir.glob("*")):
        if path.suffix.lower() not in {".png", ".html", ".svg", ".jpg", ".jpeg"}:
            continue
        rel = path.relative_to(RESULTS_DIR)
        plots.append({
            "name": path.name,
            "path": safe_rel(path),
            "url": f"/artifacts/{rel.as_posix()}",
            "kind": path.suffix.lower().lstrip("."),
        })
    return plots


def summarize_run_dir(run_dir: Path) -> dict[str, Any]:
    summary = parse_json_file(run_dir / "summary.json")
    stat = run_dir.stat()
    files = {
        name: (run_dir / name).exists()
        for name in ["bench.csv", "summary.json", "receiver.log", "sender.log", "cal.log"]
    }
    return {
        "name": run_dir.name,
        "path": safe_rel(run_dir),
        "mtime": stat.st_mtime,
        "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "summary": flatten_run_summary(summary),
        "files": files,
        "plots": list_plot_files(run_dir),
    }


def read_csv_preview(path: Path, limit: int = 250) -> dict[str, Any]:
    if not path.exists():
        return {"columns": [], "rows": [], "row_count": 0}

    rows: list[dict[str, str]] = []
    row_count = 0
    columns: list[str] = []
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        for row in reader:
            row_count += 1
            if len(rows) < limit:
                rows.append(row)
    return {"columns": columns, "rows": rows, "row_count": row_count}


def read_tail(path: Path, max_chars: int = 24000) -> str:
    if not path.exists():
        return ""
    try:
        data = path.read_text(errors="replace")
    except OSError:
        return ""
    return data[-max_chars:]


def run_command_job(job: Job) -> None:
    WEB_JOBS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = WEB_JOBS_DIR / f"{job.id}.log"
    job.log_path = log_path
    job.started_at = utc_now()
    job.status = "running"
    job.append(f"$ {' '.join(job.command)}")

    with log_path.open("w") as log:
        log.write(f"$ {' '.join(job.command)}\n")
        log.flush()
        try:
            job.process = subprocess.Popen(
                job.command,
                cwd=str(job.cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
                env=os.environ.copy(),
            )
        except OSError as exc:
            job.status = "failed"
            job.completed_at = utc_now()
            job.returncode = -1
            msg = f"[web_api] failed to start command: {exc}"
            job.append(msg)
            log.write(msg + "\n")
            return

        assert job.process.stdout is not None
        for line in job.process.stdout:
            job.append(line)
            log.write(line)
            log.flush()

        job.returncode = job.process.wait()
        job.completed_at = utc_now()
        job.status = "completed" if job.returncode == 0 else "failed"
        job.append(f"[web_api] process exited with code {job.returncode}")
        log.write(f"[web_api] process exited with code {job.returncode}\n")


def create_job(kind: str, command: list[str], cwd: Path = REPO_ROOT, run_dir: str | None = None) -> Job:
    job_id = uuid.uuid4().hex[:12]
    job = Job(
        id=job_id,
        kind=kind,
        command=command,
        cwd=cwd,
        created_at=utc_now(),
        run_dir=run_dir,
    )
    with JOBS_LOCK:
        JOBS[job_id] = job
    thread = threading.Thread(target=run_command_job, args=(job,), daemon=True)
    thread.start()
    return job


def benchmark_command(req: BenchmarkRequest) -> list[str]:
    if req.tier not in {1, 4, 5}:
        raise HTTPException(status_code=400, detail="scripts/benchmark.py currently supports tiers 1, 4, and 5.")
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "benchmark.py"),
        "--tier", str(req.tier),
        "--rate", str(req.rate_hz),
        "--repetition", str(req.repetition),
        "--warmup", str(req.warmup_sec),
        "--duration", str(req.duration_sec),
        "--gpu-index", str(req.gpu_index),
        "--gpu-pcie", req.gpu_pcie,
        "--nic-pcie", req.nic_pcie,
        "--receiver-init-sec", str(req.receiver_init_sec),
        "--ssh", req.ssh,
        "--dpu-repo", req.dpu_repo,
        "--dpu-bind-ip", req.dpu_bind_ip,
        "--host-iface", req.host_iface,
    ]
    cmd.append("--calibrate" if req.calibrate else "--no-calibrate")
    if req.manual:
        cmd.append("--manual")
    if req.nsys:
        cmd.append("--nsys")
    return cmd


@app.get("/api/health")
def health() -> dict[str, Any]:
    binaries = {
        "data_source": REPO_ROOT / "bin" / "data_source",
        "data_source_live": REPO_ROOT / "bin" / "data_source_live",
        "cpu_receiver": REPO_ROOT / "bin" / "cpu_receiver",
        "dpdk_receiver": REPO_ROOT / "bin" / "dpdk_receiver",
        "rdma_receiver": REPO_ROOT / "bin" / "rdma_receiver",
        "gpu_receiver": REPO_ROOT / "bin" / "gpu_receiver",
        "fill_simulator": REPO_ROOT / "bin" / "fill_simulator",
        "benchmark_harness": REPO_ROOT / "bin" / "benchmark_harness",
        "dpu_relay_dpu": REPO_ROOT / "bin" / "dpu_relay_dpu",
    }
    tools = {name: command_exists(name) for name in ["make", "cmake", "nvcc", "ssh", "scp", "nsys", "node", "npm"]}
    return {
        "ok": True,
        "repo_root": str(REPO_ROOT),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        },
        "native_pipeline_note": (
            "The web app can run anywhere, but T2-T5 native benchmarks require the Ubuntu/CUDA/DOCA/BlueField host."
            if platform.system() != "Linux"
            else "Linux host detected; native availability depends on CUDA, DOCA, DPDK, and DPU setup."
        ),
        "tools": tools,
        "binaries": {name: path.exists() for name, path in binaries.items()},
        "results": {
            "single_runs": len(list(SINGLE_RESULTS_DIR.glob("T*"))) if SINGLE_RESULTS_DIR.exists() else 0,
            "benchmark_csv": (RESULTS_DIR / "benchmark.csv").exists(),
        },
    }


@app.get("/api/runs")
def list_runs() -> dict[str, Any]:
    if not SINGLE_RESULTS_DIR.exists():
        return {"runs": []}
    runs = [
        summarize_run_dir(path)
        for path in sorted(SINGLE_RESULTS_DIR.glob("T*"), key=lambda item: item.stat().st_mtime, reverse=True)
        if path.is_dir()
    ]
    return {"runs": runs}


@app.get("/api/runs/{run_name}")
def get_run(run_name: str) -> dict[str, Any]:
    run_dir = (SINGLE_RESULTS_DIR / run_name).resolve()
    if not run_dir.exists() or not run_dir.is_dir() or SINGLE_RESULTS_DIR.resolve() not in run_dir.parents:
        raise HTTPException(status_code=404, detail="Run not found")
    summary = parse_json_file(run_dir / "summary.json")
    return {
        "run": summarize_run_dir(run_dir),
        "summary_json": summary,
        "bench_preview": read_csv_preview(run_dir / "bench.csv"),
        "logs": {
            "receiver": read_tail(run_dir / "receiver.log"),
            "sender": read_tail(run_dir / "sender.log"),
            "calibration": read_tail(run_dir / "cal.log"),
        },
    }


@app.get("/api/benchmark-matrix")
def benchmark_matrix() -> dict[str, Any]:
    csv_path = RESULTS_DIR / "benchmark.csv"
    return {
        "path": safe_rel(csv_path),
        "exists": csv_path.exists(),
        "data": read_csv_preview(csv_path, limit=1000),
    }


@app.get("/api/comparison")
def comparison() -> dict[str, Any]:
    runs = []
    if SINGLE_RESULTS_DIR.exists():
        for run_dir in SINGLE_RESULTS_DIR.glob("T*"):
            if (run_dir / "summary.json").exists():
                item = summarize_run_dir(run_dir)
                item["summary_json"] = parse_json_file(run_dir / "summary.json")
                runs.append(item)
    runs.sort(key=lambda item: item["mtime"], reverse=True)
    return {"runs": runs}


@app.post("/api/benchmark")
def start_benchmark(req: BenchmarkRequest) -> dict[str, Any]:
    job = create_job("benchmark", benchmark_command(req))
    return {"job": job.snapshot()}


@app.post("/api/live/start")
def start_live(req: LiveRequest) -> dict[str, Any]:
    script = REPO_ROOT / "scripts" / "run_live_pipeline.sh"
    if not script.exists():
        raise HTTPException(status_code=404, detail="run_live_pipeline.sh not found")
    cmd = [
        str(script),
        "--tier", str(req.tier),
        "--symbols", req.symbols,
        "--harness", req.harness_ip,
        "--fillsim", req.fillsim_ip,
        "--dpu-user", req.dpu_user,
        "--dpu-ip", req.dpu_ip,
    ]
    if req.rate_hz:
        cmd += ["--rate", str(req.rate_hz)]
    job = create_job("live-pipeline", cmd)
    return {"job": job.snapshot()}


@app.post("/api/build")
def start_build(req: BuildRequest) -> dict[str, Any]:
    job = create_job("build", ["make", req.target])
    return {"job": job.snapshot()}


@app.post("/api/dashboard/generate")
def generate_dashboard(req: DashboardRequest) -> dict[str, Any]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "src" / "dashboard" / "dashboard.py"),
        "--results",
        req.results_path,
        "--out",
        req.out_dir,
    ]
    job = create_job("dashboard", cmd)
    return {"job": job.snapshot()}


@app.post("/api/runs/{run_name}/analyze")
def analyze_run(run_name: str) -> dict[str, Any]:
    run_dir = (SINGLE_RESULTS_DIR / run_name).resolve()
    if not run_dir.exists() or SINGLE_RESULTS_DIR.resolve() not in run_dir.parents:
        raise HTTPException(status_code=404, detail="Run not found")
    cmd = [sys.executable, str(REPO_ROOT / "scripts" / "analyze.py"), str(run_dir)]
    job = create_job("analyze", cmd, run_dir=run_name)
    return {"job": job.snapshot()}


@app.get("/api/jobs")
def list_jobs() -> dict[str, Any]:
    with JOBS_LOCK:
        jobs = [job.snapshot() for job in JOBS.values()]
    jobs.sort(key=lambda item: item["created_at"], reverse=True)
    return {"jobs": jobs}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"job": job.snapshot()}


@app.post("/api/jobs/{job_id}/stop")
def stop_job(job_id: str) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.process and job.process.poll() is None:
        try:
            os.killpg(job.process.pid, signal.SIGTERM)
        except OSError:
            job.process.terminate()
        job.status = "stopping"
        job.append("[web_api] stop requested")
    return {"job": job.snapshot()}


@app.websocket("/api/jobs/{job_id}/logs")
async def job_logs(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    last_count = 0
    try:
        while True:
            job = JOBS.get(job_id)
            if not job:
                await websocket.send_json({"type": "error", "message": "Job not found"})
                return
            snapshot = job.snapshot()
            lines = snapshot["lines"]
            if len(lines) != last_count or snapshot["status"] in {"completed", "failed"}:
                await websocket.send_json({"type": "job", "job": snapshot, "lines": lines[last_count:]})
                last_count = len(lines)
            if snapshot["status"] in {"completed", "failed"}:
                return
            await _sleep(0.5)
    except WebSocketDisconnect:
        return


async def _sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)


@app.get("/artifacts/{artifact_path:path}")
def get_artifact(artifact_path: str) -> FileResponse:
    target = (RESULTS_DIR / artifact_path).resolve()
    results_root = RESULTS_DIR.resolve()
    if target != results_root and results_root not in target.parents:
        raise HTTPException(status_code=403, detail="Artifact path escapes results directory")
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target)
