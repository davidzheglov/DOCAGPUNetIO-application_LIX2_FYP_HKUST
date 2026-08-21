#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from typing import Any


PASSWORD_PROMPTS = [
    "password:",
    "Password:",
    "passphrase for key",
    "Are you sure you want to continue connecting",
]


def log(message: str = "") -> None:
    print(message, flush=True)


def quote(value: str) -> str:
    return shlex.quote(value)


def read_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    try:
        path.unlink()
    except OSError:
        pass
    return data


def command_text(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def run_plain(command: list[str], cwd: Path | None = None, timeout: int | None = None) -> int:
    log(f"$ {command_text(command)}")
    proc = subprocess.Popen(
        command,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    started = time.monotonic()
    assert proc.stdout is not None
    for line in proc.stdout:
        log(line.rstrip("\n"))
        if timeout and time.monotonic() - started > timeout:
            proc.terminate()
            log(f"[dpu-demo] timeout after {timeout}s")
            return 124
    return proc.wait()


def run_interactive(command: list[str], password: str, cwd: Path | None = None, timeout: int | None = None) -> int:
    try:
        import pexpect
    except ImportError:
        log("[dpu-demo] Password mode needs the Python package 'pexpect'.")
        log("[dpu-demo] Install it on the machine running the API: python3 -m pip install pexpect")
        return 127

    log(f"$ {command_text(command)}")
    child = pexpect.spawn(command[0], command[1:], cwd=str(cwd) if cwd else None, encoding="utf-8", timeout=timeout)
    child.logfile_read = _PexpectLogger()
    while True:
        index = child.expect(PASSWORD_PROMPTS + [pexpect.EOF, pexpect.TIMEOUT])
        if index in {0, 1, 2}:
            child.sendline(password)
        elif index == 3:
            child.sendline("yes")
        elif index == len(PASSWORD_PROMPTS):
            break
        else:
            child.close(force=True)
            log(f"[dpu-demo] timeout after {timeout}s")
            return 124
    child.close()
    return int(child.exitstatus if child.exitstatus is not None else child.signalstatus or 0)


class _PexpectLogger:
    def write(self, data: str) -> None:
        if data:
            print(data, end="", flush=True)

    def flush(self) -> None:
        sys.stdout.flush()


def run_command(command: list[str], password: str, timeout: int | None = None) -> int:
    if password:
        return run_interactive(command, password=password, timeout=timeout)
    return run_plain(command, timeout=timeout)


def ssh_command(host: str, remote: str, *, password: str, verbose: bool = False, timeout: int | None = None) -> int:
    opts = ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if not password:
        opts += ["-o", "BatchMode=yes"]
    flag = "-vvv" if verbose else "-T"
    return run_command(["ssh", flag, *opts, host, remote], password=password, timeout=timeout)


def scp_from(host: str, remote_path: str, local_dir: Path, *, password: str, timeout: int | None = None) -> int:
    local_dir.mkdir(parents=True, exist_ok=True)
    opts = ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if not password:
        opts += ["-o", "BatchMode=yes"]
    return run_command(["scp", *opts, f"{host}:{remote_path}", str(local_dir)], password=password, timeout=timeout)


def remote_repo_command(repo: str, command: str) -> str:
    return f"cd {quote(repo)} && {command}"


def remote_env(cfg: dict[str, Any], *, sender_iface: bool = True) -> str:
    values = {
        "DPU_USER": cfg["dpu_user"],
        "DPU_IP": cfg["dpu_ip"],
        "DPU_RELAY_PATH": cfg.get("dpu_relay_path", "/home/ubuntu/dpu_relay"),
        "DPU_MCAST_IFACE": cfg.get("sender_dpu_iface" if sender_iface else "receiver_dpu_iface", "10.10.10.3"),
        "RELAY_PORT": str(cfg.get("relay_port", 6005)),
    }
    return " ".join(f"{key}={quote(value)}" for key, value in values.items())


def run_preflight(cfg: dict[str, Any]) -> int:
    receiver = cfg["receiver_host"]
    sender = cfg["sender_host"]
    repo = cfg["remote_repo"]
    password = cfg.get("ssh_password", "")
    dpu_user = cfg["dpu_user"]
    dpu_ip = cfg["dpu_ip"]
    verbose = bool(cfg.get("verbose_ssh", False))

    checks = [
        (
            "receiver host",
            receiver,
            remote_repo_command(
                repo,
                "hostname; pwd; git branch --show-current; git log -1 --oneline; "
                "test -x scripts/run_benchmark.sh && echo run_benchmark=ok; "
                "test -x scripts/diagnose_crosslink.sh && echo diagnose_crosslink=ok; "
                "command -v ssh; command -v scp",
            ),
            False,
        ),
        (
            "sender host",
            sender,
            remote_repo_command(
                repo,
                "hostname; pwd; git branch --show-current; git log -1 --oneline; "
                "test -x bin/data_source && echo data_source=ok || true; "
                "command -v ssh; ip -br -4 addr show tmfifo_net0 || true",
            ),
            False,
        ),
        (
            "receiver DPU from lxcpu1",
            receiver,
            f"ssh {'-vvv' if verbose else '-T'} -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "
            f"{quote(dpu_user + '@' + dpu_ip)} 'hostname; ip -br -4 addr || true; pgrep -a dpu_relay || true'",
            False,
        ),
        (
            "sender DPU from lxcpu2",
            sender,
            f"ssh {'-vvv' if verbose else '-T'} -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "
            f"{quote(dpu_user + '@' + dpu_ip)} 'hostname; ip -br -4 addr || true; pgrep -a dpu_relay || true'",
            False,
        ),
    ]

    rc = 0
    for label, host, command, use_outer_verbose in checks:
        log()
        log(f"[dpu-demo] === {label} ===")
        step_rc = ssh_command(host, command, password=password, verbose=use_outer_verbose, timeout=90)
        if step_rc != 0:
            rc = step_rc
            log(f"[dpu-demo] {label} failed with exit {step_rc}")
    return rc


def run_diagnose(cfg: dict[str, Any]) -> int:
    command = remote_repo_command(cfg["remote_repo"], "bash scripts/diagnose_crosslink.sh")
    return ssh_command(cfg["receiver_host"], command, password=cfg.get("ssh_password", ""), timeout=600)


def run_datapath(cfg: dict[str, Any]) -> int:
    command = remote_repo_command(cfg["remote_repo"], "bash scripts/diagnose_datapath.sh")
    return ssh_command(cfg["receiver_host"], command, password=cfg.get("ssh_password", ""), timeout=900)


def run_live_sender(cfg: dict[str, Any]) -> int:
    repo = cfg["remote_repo"]
    args = [
        remote_env(cfg, sender_iface=True),
        "bash scripts/run_live_sender.sh",
        "--symbols", quote(cfg.get("live_symbols", "BTCUSDT,ETHUSDT")),
        "--dpu-ip", quote(cfg["dpu_ip"]),
        "--dpu-user", quote(cfg["dpu_user"]),
        "--dpu-relay-path", quote(cfg.get("dpu_relay_path", "/home/ubuntu/dpu_relay")),
        "--iface", quote(cfg.get("sender_dpu_iface", "10.10.10.3")),
        "--port", quote(str(cfg.get("relay_port", 6005))),
    ]
    if cfg.get("verbose_ssh", False):
        args.append("--verbose")
    command = remote_repo_command(repo, " ".join(part for part in args if part))
    return ssh_command(cfg["sender_host"], command, password=cfg.get("ssh_password", ""), timeout=int(cfg.get("timeout_sec", 1800)))


def run_benchmark(cfg: dict[str, Any], repo_root: Path) -> int:
    password = cfg.get("ssh_password", "")
    repo = cfg["remote_repo"]
    args = [
        remote_env(cfg, sender_iface=True),
        "bash scripts/run_benchmark.sh",
        "--quick" if cfg.get("quick", True) else "",
        "--tiers", quote(cfg["tiers"]),
        "--rates", quote(cfg["rates"]),
        "--reps", quote(str(cfg["reps"])),
        "--warmup", quote(str(cfg["warmup_sec"])),
        "--duration", quote(str(cfg["duration_sec"])),
        "--csv-rows", quote(str(cfg.get("csv_rows", 1_000_000))),
        "--symbols", quote(str(cfg.get("csv_symbols", 32))),
        "--csv", quote(cfg.get("csv_path", "data/ticks.csv")),
        "--iface", quote(cfg.get("sender_dpu_iface", "10.10.10.3")),
        "--receiver-iface", quote(cfg["receiver_iface"]),
        "--sender-ssh", quote(cfg["sender_host"]),
    ]
    if cfg.get("regen_csv", False):
        args.append("--regen-csv")
    if cfg.get("local_sender", False):
        args.append("--local-sender")
    if cfg.get("light_bench", True):
        args.append("--light-bench")
    if password:
        args.append("--sender-password")
    command = remote_repo_command(repo, " ".join(part for part in args if part))
    rc = ssh_command(cfg["receiver_host"], command, password=password, timeout=int(cfg.get("timeout_sec", 1800)))
    if rc != 0:
        return rc

    log()
    log("[dpu-demo] Collecting newest benchmark artifacts from receiver host...")
    latest_cmd = remote_repo_command(
        repo,
        "latest=$(ls -t results/benchmark_*.csv 2>/dev/null | head -1); "
        "test -n \"$latest\" && printf '%s' \"$latest\"",
    )
    latest_file = capture_remote(cfg["receiver_host"], latest_cmd, password=password)
    if not latest_file:
        log("[dpu-demo] No benchmark CSV found to copy.")
        return 0

    run_id = time.strftime("%Y%m%d_%H%M%S")
    local_dir = repo_root / "results" / "remote_dpu" / run_id
    scp_rc = scp_from(cfg["receiver_host"], f"{repo}/{latest_file}", local_dir, password=password, timeout=240)
    if scp_rc == 0:
        artifact = f"remote_dpu/{run_id}/{Path(latest_file).name}"
        log(f"[dpu-demo] Copied result CSV to results/{artifact}")
        log(f"[dpu-demo] Frontend artifact URL: /artifacts/{artifact}")
    return scp_rc


def safe_extract_tar(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            target = (dest / member.name).resolve()
            if root != target and root not in target.parents:
                raise RuntimeError(f"Refusing to extract unsafe tar member: {member.name}")
        tar.extractall(dest)


def collect_host_artifacts(cfg: dict[str, Any], repo_root: Path, host: str, label: str, run_id: str) -> int:
    password = cfg.get("ssh_password", "")
    repo = cfg["remote_repo"]
    remote_archive = f"/tmp/dpu_demo_{label}_{run_id}.tgz"
    local_dir = repo_root / "results" / "remote_dpu" / run_id
    find_expr = (
        "files=$(find results -maxdepth 3 -type f \\( "
        "-name 'benchmark_*.csv' -o -name '*.log' -o -name '*.json' -o -name '*.png' -o -name '*.txt' "
        "\\) 2>/dev/null | sort | tail -80); "
        "test -n \"$files\" || { echo no-artifacts; exit 3; }; "
        f"tar -czf {quote(remote_archive)} $files && printf '%s' {quote(remote_archive)}"
    )
    log()
    log(f"[dpu-demo] Collecting artifacts from {label} ({host})...")
    remote_path = capture_remote(host, remote_repo_command(repo, find_expr), password=password)
    if not remote_path or "no-artifacts" in remote_path:
        log(f"[dpu-demo] No result/log artifacts found on {label}.")
        return 0
    rc = scp_from(host, remote_archive, local_dir, password=password, timeout=240)
    ssh_command(host, f"rm -f {quote(remote_archive)}", password=password, timeout=30)
    if rc != 0:
        return rc
    local_archive = local_dir / Path(remote_archive).name
    extract_dir = local_dir / label
    try:
        safe_extract_tar(local_archive, extract_dir)
    except Exception as exc:
        log(f"[dpu-demo] Copied archive but extraction failed: {exc}")
        return 1
    log(f"[dpu-demo] Copied archive to {local_archive.relative_to(repo_root)}")
    log(f"[dpu-demo] Extracted files under {extract_dir.relative_to(repo_root)}")
    return 0


def collect_artifacts(cfg: dict[str, Any], repo_root: Path) -> int:
    run_id = time.strftime("%Y%m%d_%H%M%S")
    rc = collect_host_artifacts(cfg, repo_root, cfg["receiver_host"], "receiver", run_id)
    sender_rc = collect_host_artifacts(cfg, repo_root, cfg["sender_host"], "sender", run_id)
    return rc or sender_rc


def capture_remote(host: str, remote: str, *, password: str) -> str:
    try:
        import pexpect
    except ImportError:
        if password:
            return ""
        proc = subprocess.run(
            ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    if password:
        child = pexpect.spawn(
            "ssh",
            ["-T", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new", host, remote],
            encoding="utf-8",
            timeout=60,
        )
        output = []
        while True:
            index = child.expect(PASSWORD_PROMPTS + [pexpect.EOF, pexpect.TIMEOUT])
            output.append(child.before)
            if index in {0, 1, 2}:
                child.sendline(password)
            elif index == 3:
                child.sendline("yes")
            else:
                break
        child.close()
        return "".join(output).strip() if child.exitstatus == 0 else ""

    proc = subprocess.run(
        ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--repo-root", required=True)
    args = parser.parse_args()

    cfg = read_config(Path(args.config))
    repo_root = Path(args.repo_root).resolve()

    action = cfg["action"]
    log("[dpu-demo] Local API runner is active.")
    log(f"[dpu-demo] Action: {action}")
    log(f"[dpu-demo] Receiver host: {cfg['receiver_host']}")
    log(f"[dpu-demo] Sender host: {cfg['sender_host']}")
    log(f"[dpu-demo] Remote repo: {cfg['remote_repo']}")

    if action == "preflight":
        return run_preflight(cfg)
    if action == "diagnose":
        return run_diagnose(cfg)
    if action == "datapath":
        return run_datapath(cfg)
    if action == "live_sender":
        return run_live_sender(cfg)
    if action == "benchmark":
        return run_benchmark(cfg, repo_root)
    if action == "collect":
        return collect_artifacts(cfg, repo_root)
    log(f"[dpu-demo] Unknown action: {action}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
