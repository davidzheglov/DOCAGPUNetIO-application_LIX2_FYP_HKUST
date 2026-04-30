# DPU Frontend Testing

This workflow lets the local web cockpit ask the backend API to SSH into the
HKUST receiver/sender servers and run the cross-DPU checks from the repo.

## Local startup

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r src/web_api/requirements.txt
python3 -m fastapi run src/web_api/main.py --host 127.0.0.1 --port 8002
```

In another terminal:

```bash
cd web
npm install
npm run dev
```

Open the Vite URL and select **DPU Demo**. The left **Operator Controls** panel
contains the buttons that actually talk to the servers.

At the top of **DPU Demo** there are two remote terminal panes:

- **Receiver Terminal** for `lix2@lxcpu1.cse.ust.hk`
- **Sender Terminal** for `lix2@lxcpu2.cse.ust.hk`

Each terminal has its own optional SSH password field, a **Host / DPU ARM**
context selector, a **Login to ARM Core DPU** button, quick command buttons, a
**Send Password** button for nested SSH prompts, and a command line with
**Submit**. These terminal panes are persistent SSH sessions: opening a shell
does not create a one-command job, and later commands are written into the same
live terminal until you click **Close**.

The sender pane intentionally opens through `lxcpu1` first. After the receiver
shell connects, the frontend also opens a sender-side shell to `lxcpu1`; then
click **Connect to Sender** in the sender pane to run `ssh -vvv
lix2@lxcpu2.cse.ust.hk` inside that live shell. Use **Send Password** if the
nested SSH prompt asks for it. The DPU login button sends `ssh -vvv
ubuntu@192.168.100.2` into whichever live shell is currently open.

The operator buttons cover the main script regimes:

- **Connect Servers**: SSH preflight for both hosts and both DPU ARM cores.
- **Crosslink Diagnose**: runs `bash scripts/diagnose_crosslink.sh` on
  `lxcpu1`.
- **Datapath Diagnose**: runs `bash scripts/diagnose_datapath.sh` on `lxcpu1`.
- **Live Crypto Sender**: runs `bash scripts/run_live_sender.sh` on `lxcpu2`.
  Change **Live Crypto Symbols** to choose feeds such as
  `BTCUSDT,ETHUSDT,SOLUSDT`.
- **Benchmark Sweep**: runs `bash scripts/run_benchmark.sh` on `lxcpu1` with
  editable tiers, rates, reps, warmup, duration, CSV rows, CSV symbols, DPU
  relay path, relay port, and sender DPU egress IP.
- **Collect Results**: creates archives on both remote hosts and copies recent
  `results/` CSV/log/JSON/PNG/TXT files back into local
  `results/remote_dpu/<timestamp>/`.

The terminal panes also include script-specific buttons. Receiver-side buttons
include datapath diagnostics, `listen_results.py`, `test_link.py recv`, and
live receiver launchers. Sender-side buttons include `run_live_sender.sh`,
`test_link.py send`, relay log tailing, and sender cleanup.

The frontend now prefers `http://127.0.0.1:8002`, then falls back to any
`VITE_API_URL`, `8001`, and `8000`. The **Operator Controls** panel shows the
backend URL it is actually using.

If port `8002` is already in use, find the existing API process:

```bash
lsof -iTCP:8002 -sTCP:LISTEN
```

If you explicitly set Vite's API URL, use `8002`:

```bash
cd web
VITE_API_URL=http://127.0.0.1:8002 npm run dev
```

## Recommended order

1. Turn off the VPN or use the network path that can reach
   `lxcpu1.cse.ust.hk` and `lxcpu2.cse.ust.hk`.
2. In **DPU Demo**, keep these defaults:
   - receiver: `lix2@lxcpu1.cse.ust.hk`
   - sender: `lix2@lxcpu2.cse.ust.hk`
   - DPU login: `ubuntu@192.168.100.2`
3. Enter the SSH password in the receiver terminal password field.
4. Click **Open Receiver Shell**. The sender terminal should also open an
   `lxcpu1` shell automatically.
5. In the sender terminal, click **Connect to Sender** and send the password if
   prompted.
6. Use **Login to ARM Core DPU** in either terminal when you want to enter the
   local DPU ARM shell.
7. Edit **Live Crypto Symbols** if you want a different Binance feed list.
8. In **Operator Controls**, click **Connect Servers**.
9. If connection passes, click **Crosslink Diagnose** or **Datapath Diagnose**.
10. For a live crypto demo, click **Live Crypto Sender** or use the sender
    terminal's **Live Crypto Sender** button.
11. For benchmark data, click **Benchmark Sweep**.
12. Click **Collect Results** whenever you want to SCP recent remote outputs
    back without running a new benchmark.
13. Use **Download latest CSV** in the **Received Data** panel.

The benchmark runs `scripts/run_benchmark.sh` on `lxcpu1`, uses `lxcpu2` as the
sender, and copies the newest `results/benchmark_*.csv` back into:

```text
results/remote_dpu/<timestamp>/
```

The job console prints the copied artifact path and an `/artifacts/...` URL.

## Updating the remote repos

The web UI and API changes only need to run on your local machine. You need to
push to GitHub and pull on `lxcpu1`/`lxcpu2` only when the remote repo is missing
the scripts or branch updates that the UI launches, or when you rebuild binaries
there. A safe remote refresh is:

```bash
cd ~/DOCAGPUNetIO-application_LIX2_FYP_HKUST
git fetch
git checkout dpu-crosslink
git pull
make data_source data_source_live dpu_relay_dpu t1 t2 t3 t4 harness
```

## Passwordless path

Password mode is for initial demos. For repeat runs, set up keys:

```bash
ssh-copy-id lix2@lxcpu1.cse.ust.hk
ssh-copy-id lix2@lxcpu2.cse.ust.hk
```

Then from each server, set up its local DPU ARM:

```bash
ssh lix2@lxcpu1.cse.ust.hk "ssh-copy-id ubuntu@192.168.100.2"
ssh lix2@lxcpu2.cse.ust.hk "ssh-copy-id ubuntu@192.168.100.2"
```

After that, the password field can stay empty.

## Manual DPU SSH checks

From `lxcpu1`:

```bash
ssh -vvv ubuntu@192.168.100.2
```

From `lxcpu2`:

```bash
ssh -vvv ubuntu@192.168.100.2
```

Both servers use the same DPU management IP because `192.168.100.2` is reached
through each server's local `tmfifo_net0` management link.
