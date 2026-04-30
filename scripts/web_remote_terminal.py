#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
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


class _PexpectLogger:
    def write(self, data: str) -> None:
        if data:
            print(data, end="", flush=True)

    def flush(self) -> None:
        sys.stdout.flush()


def run_plain(command: list[str], timeout: int) -> int:
    log(f"$ {command_text(command)}")
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    started = time.monotonic()
    assert proc.stdout is not None
    for line in proc.stdout:
        log(line.rstrip("\n"))
        if time.monotonic() - started > timeout:
            proc.terminate()
            log(f"[remote-terminal] timeout after {timeout}s")
            return 124
    return proc.wait()


def run_interactive(command: list[str], password: str, timeout: int) -> int:
    try:
        import pexpect
    except ImportError:
        log("[remote-terminal] Password mode needs pexpect. Install: python3 -m pip install pexpect")
        return 127

    log(f"$ {command_text(command)}")
    child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=timeout)
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
            log(f"[remote-terminal] timeout after {timeout}s")
            return 124
    child.close()
    return int(child.exitstatus if child.exitstatus is not None else child.signalstatus or 0)


def run_command(command: list[str], password: str, timeout: int) -> int:
    if password:
        return run_interactive(command, password, timeout)
    return run_plain(command, timeout)


def remote_repo_command(repo: str, command: str) -> str:
    return f"cd {quote(repo)} && {command}"


def make_ssh_command(host: str, remote_command: str, password: str, verbose: bool) -> list[str]:
    opts = ["-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if not password:
        opts += ["-o", "BatchMode=yes"]
    return ["ssh", "-vvv" if verbose else "-T", *opts, host, remote_command]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    cfg = read_config(Path(args.config))

    host = cfg["host"]
    password = cfg.get("ssh_password", "")
    remote_repo = cfg["remote_repo"]
    context = cfg["context"]
    command = (cfg.get("command") or "").strip()
    timeout = int(cfg.get("timeout_sec", 300))
    verbose = bool(cfg.get("verbose_ssh", False))
    use_repo = bool(cfg.get("use_repo", True))

    if not command:
        command = "hostname; whoami; pwd"

    log("[remote-terminal] Local runner active.")
    log(f"[remote-terminal] Host: {host}")
    log(f"[remote-terminal] Context: {context}")

    if context == "dpu":
        dpu_login = f"{cfg['dpu_user']}@{cfg['dpu_ip']}"
        dpu_flag = "-vvv" if verbose else "-T"
        remote = (
            f"ssh {dpu_flag} -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "
            f"{quote(dpu_login)} {quote(command)}"
        )
    else:
        remote = remote_repo_command(remote_repo, command) if use_repo else command

    return run_command(make_ssh_command(host, remote, password, verbose=False), password, timeout)


if __name__ == "__main__":
    raise SystemExit(main())
