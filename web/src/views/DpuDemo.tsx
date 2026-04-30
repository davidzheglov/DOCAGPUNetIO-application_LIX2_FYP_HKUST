import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Activity, Cable, Cpu, Download, Gauge, KeyRound, PlugZap, RefreshCw, Send, Server, SquareTerminal, TerminalSquare } from "lucide-react";
import { api } from "@/lib/api";
import type { DpuDemoRequest, Job, TerminalSession } from "@/lib/types";

const defaults: DpuDemoRequest = {
  action: "preflight",
  receiver_host: "lix2@lxcpu1.cse.ust.hk",
  sender_host: "lix2@lxcpu2.cse.ust.hk",
  ssh_password: "",
  remote_repo: "/home/lix2/DOCAGPUNetIO-application_LIX2_FYP_HKUST",
  dpu_user: "ubuntu",
  dpu_ip: "192.168.100.2",
  receiver_iface: "ens21f0np0",
  receiver_dpu_iface: "10.10.10.1",
  sender_dpu_iface: "10.10.10.3",
  relay_port: 6005,
  dpu_relay_path: "/home/ubuntu/dpu_relay",
  live_symbols: "BTCUSDT,ETHUSDT",
  live_rate_hz: null,
  harness_ip: "127.0.0.1",
  fillsim_ip: "127.0.0.1",
  tiers: "1,2,3,4",
  rates: "50000,500000",
  reps: 1,
  warmup_sec: 2,
  duration_sec: 10,
  csv_rows: 1000000,
  csv_symbols: 32,
  csv_path: "data/ticks.csv",
  regen_csv: false,
  local_sender: false,
  quick: false,
  light_bench: true,
  verbose_ssh: false,
  timeout_sec: 1800,
};

const actions = [
  { id: "preflight", label: "Terminal Preflight", icon: PlugZap, description: "Send host and DPU checks into both live terminals" },
  { id: "diagnose", label: "Crosslink Diagnose", icon: SquareTerminal, description: "Run diagnose_crosslink.sh in the receiver terminal" },
  { id: "datapath", label: "Datapath Diagnose", icon: Activity, description: "Run diagnose_datapath.sh in the receiver terminal" },
  { id: "live_sender", label: "Live Crypto Sender", icon: Send, description: "Run run_live_sender.sh in the sender terminal" },
  { id: "benchmark", label: "Benchmark Sweep", icon: Gauge, description: "Run run_benchmark.sh in the receiver terminal" },
  { id: "collect", label: "Prepare Remote Archives", icon: Download, description: "Create /tmp result archives from both live terminals" },
] as const;

type TerminalAction = typeof actions[number]["id"];

type TerminalPaneHandle = {
  sendCommand: (command: string) => boolean;
};

function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function sh(value: string | number | null | undefined) {
  return `'${String(value ?? "").replace(/'/g, `'\\''`)}'`;
}

function dpuEnv(form: DpuDemoRequest) {
  return [
    `DPU_USER=${sh(form.dpu_user)}`,
    `DPU_IP=${sh(form.dpu_ip)}`,
    `DPU_RELAY_PATH=${sh(form.dpu_relay_path)}`,
    `DPU_MCAST_IFACE=${sh(form.sender_dpu_iface)}`,
    `RELAY_PORT=${sh(form.relay_port)}`,
  ].join(" ");
}

function benchmarkCommand(form: DpuDemoRequest) {
  const parts = [
    "bash scripts/run_benchmark.sh",
    form.quick ? "--quick" : "",
    "--tiers", sh(form.tiers),
    "--rates", sh(form.rates),
    "--reps", sh(form.reps),
    "--warmup", sh(form.warmup_sec),
    "--duration", sh(form.duration_sec),
    "--csv-rows", sh(form.csv_rows),
    "--symbols", sh(form.csv_symbols),
    "--csv", sh(form.csv_path),
    "--iface", sh(form.sender_dpu_iface),
    "--receiver-iface", sh(form.receiver_iface),
    "--sender-ssh", sh(form.sender_host),
    form.regen_csv ? "--regen-csv" : "",
    form.local_sender ? "--local-sender" : "",
    form.light_bench ? "--light-bench" : "",
    "--sender-password",
  ].filter(Boolean).join(" ");
  return `cd ${sh(form.remote_repo)} && ${dpuEnv(form)} ${parts}`;
}

function liveSenderCommand(form: DpuDemoRequest) {
  return [
    `cd ${sh(form.remote_repo)} && bash scripts/run_live_sender.sh`,
    "--symbols", sh(form.live_symbols),
    "--dpu-ip", sh(form.dpu_ip),
    "--dpu-user", sh(form.dpu_user),
    "--dpu-relay-path", sh(form.dpu_relay_path),
    "--iface", sh(form.sender_dpu_iface),
    "--port", sh(form.relay_port),
    form.verbose_ssh ? "--verbose" : "",
  ].filter(Boolean).join(" ");
}

function archiveCommand(form: DpuDemoRequest, label: "receiver" | "sender", host: string) {
  return [
    `cd ${sh(form.remote_repo)} &&`,
    `archive=/tmp/dpu_demo_${label}_results_$(date +%Y%m%d_%H%M%S).tgz &&`,
    "tar -czf \"$archive\" results 2>/dev/null &&",
    "ls -lh \"$archive\" &&",
    "printf 'Prepared %s\\n' \"$archive\" &&",
    `printf 'Remote archive only. Copy locally with: scp %s:%s results/remote_dpu/\\n' ${sh(host)} "$archive"`,
  ].join(" ");
}

function cleanupCommand(form: DpuDemoRequest) {
  return [
    "pkill -f 'data_source_live|data_source' 2>/dev/null || true",
    `ssh ${sh(`${form.dpu_user}@${form.dpu_ip}`)} 'pkill -f dpu_relay 2>/dev/null || true'`,
    `ss -lunp 2>/dev/null | grep ${sh(String(form.relay_port))} || true`,
  ].join("; ");
}

type TerminalPaneProps = {
  role: "receiver" | "sender";
  title: string;
  host: string;
  anchorHost?: string;
  remoteRepo: string;
  dpuUser: string;
  dpuIp: string;
  receiverDpuIface: string;
  senderDpuIface: string;
  liveSymbols: string;
  relayPort: number;
  harnessIp: string;
  fillsimIp: string;
  dpuRelayPath: string;
  autoConnectToken?: number;
  autoPassword?: string;
  onConnected?: (password: string) => void;
};

type QuickCommand = {
  label: string;
  command: string;
  useRepo?: boolean;
  timeoutSec?: number;
};

const hostCommands: QuickCommand[] = [
  { label: "Who am I", command: "hostname; whoami; pwd" },
  { label: "Repo Status", command: "git branch --show-current; git log -1 --oneline; git status --short" },
  { label: "Network", command: "ip -br -4 addr; ip route | head -20", useRepo: false },
  { label: "DPU Reachability", command: "ping -c 2 -W 2 192.168.100.2 || true", useRepo: false },
];

const receiverCommands: QuickCommand[] = [
  { label: "Crosslink Diagnose", command: "bash scripts/diagnose_crosslink.sh", timeoutSec: 900 },
  { label: "Receiver Binaries", command: "ls -lh bin/*receiver bin/benchmark_harness 2>/dev/null || true" },
];

const senderCommands: QuickCommand[] = [
  { label: "Sender Binary", command: "ls -lh bin/data_source bin/data_source_live 2>/dev/null || true" },
  { label: "Sender Route", command: "ip -br -4 addr show tmfifo_net0 || true; ip route | head -20", useRepo: false },
];

const dpuCommands: QuickCommand[] = [
  { label: "DPU Interfaces", command: "hostname; whoami; ip -br -4 addr || true" },
  { label: "DPU Processes", command: "pgrep -a dpu_relay || true; ss -lunp 2>/dev/null | head -30 || true" },
  { label: "OVS Bridge", command: "sudo ovs-vsctl show 2>/dev/null || true" },
];

function PersistentTerminalConsole({ session, output, onClose }: { session: TerminalSession | null; output: string; onClose: () => void }) {
  const status = session?.status ?? "idle";
  const command = useMemo(() => session ? `${session.name} · ${session.host}` : "not connected", [session]);

  return (
    <div className="terminal-console">
      <div className="terminal-console__bar">
        <div>
          <span className={`status-dot status-dot--${status}`} />
          <strong>{status}</strong>
          <small>{command}</small>
        </div>
        {session && status !== "closed" ? <button type="button" className="icon-button icon-button--danger" onClick={onClose}>Close</button> : null}
      </div>
      <pre>{output || "Open a persistent SSH session, then submit commands into this terminal."}</pre>
    </div>
  );
}

const TerminalPane = forwardRef<TerminalPaneHandle, TerminalPaneProps>(function TerminalPane({
  role,
  title,
  host,
  anchorHost,
  remoteRepo,
  dpuUser,
  dpuIp,
  receiverDpuIface,
  senderDpuIface,
  liveSymbols,
  relayPort,
  harnessIp,
  fillsimIp,
  dpuRelayPath,
  autoConnectToken,
  autoPassword,
  onConnected,
}, ref) {
  const [password, setPassword] = useState("");
  const [context, setContext] = useState<"host" | "dpu">("host");
  const [command, setCommand] = useState("hostname; whoami; pwd");
  const [session, setSession] = useState<TerminalSession | null>(null);
  const [output, setOutput] = useState("");
  const [autoBootstrapped, setAutoBootstrapped] = useState(0);
  const openSession = useMutation({
    mutationFn: (payload: { host: string; password: string; verbose?: boolean }) =>
      api.createTerminalSession({
        name: role,
        host: payload.host,
        ssh_password: payload.password,
        verbose_ssh: payload.verbose ?? false,
      }),
    onSuccess: (data, variables) => {
      setSession(data.session);
      setOutput(data.session.chunks.join(""));
      onConnected?.(variables.password);
    },
  });
  const sendInput = useMutation({
    mutationFn: (text: string) => {
      if (!session) throw new Error("Open a terminal session first");
      return api.sendTerminalInput(session.id, text);
    },
    onSuccess: (data) => setSession(data.session),
  });
  const closeSession = useMutation({
    mutationFn: () => {
      if (!session) throw new Error("No terminal session is open");
      return api.closeTerminalSession(session.id);
    },
    onSuccess: (data) => setSession(data.session),
  });
  const interruptSession = useMutation({
    mutationFn: () => {
      if (!session) throw new Error("No terminal session is open");
      return api.interruptTerminalSession(session.id);
    },
    onSuccess: (data) => setSession(data.session),
  });

  useImperativeHandle(ref, () => ({
    sendCommand: (nextCommand: string) => {
      if (!session || session.status === "closed") return false;
      run("host", nextCommand);
      return true;
    },
  }), [session]);

  useEffect(() => {
    if (!session?.id) return;
    const socket = new WebSocket(api.terminalWsUrl(session.id));
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data) as { session?: TerminalSession; chunks?: string[] };
      if (payload.session) setSession(payload.session);
      if (payload.chunks?.length) {
        setOutput((prev) => (prev + payload.chunks!.join("")).slice(-50000));
      }
    };
    return () => socket.close();
  }, [session?.id]);

  useEffect(() => {
    if (!autoConnectToken || autoConnectToken === autoBootstrapped || role !== "sender" || session) return;
    setPassword(autoPassword ?? "");
    setAutoBootstrapped(autoConnectToken);
    openSession.mutate({ host: anchorHost ?? host, password: autoPassword ?? "" });
  }, [anchorHost, autoConnectToken, autoBootstrapped, autoPassword, host, openSession, role, session]);

  function openHostSession(nextHost = host, verbose = false) {
    setOutput("");
    openSession.mutate({ host: nextHost, password, verbose });
  }

  function submitText(text: string) {
    sendInput.mutate(text);
  }

  function sendPassword() {
    if (!password) return;
    submitText(password);
  }

  function run(nextContext: "host" | "dpu", nextCommand: string) {
    setContext(nextContext);
    setCommand(nextCommand);
    submitText(nextCommand);
  }

  function submit() {
    submitText(command);
  }

  const roleCommands = role === "receiver" ? receiverCommands : senderCommands;
  const workflowCommands = role === "receiver"
    ? [
        { label: "Datapath Diagnose", command: `cd ${remoteRepo} && bash scripts/diagnose_datapath.sh` },
        { label: "Listen Results", command: `cd ${remoteRepo} && python3 scripts/listen_results.py` },
        { label: "Link Receiver", command: `cd ${remoteRepo} && python3 scripts/test_link.py recv --bind ${receiverDpuIface === "10.10.10.1" ? "10.10.10.2" : receiverDpuIface}` },
        { label: "Live Receiver T1", command: `cd ${remoteRepo} && bash scripts/run_live_pipeline.sh --tier 1 --symbols ${liveSymbols} --harness ${harnessIp} --fillsim ${fillsimIp} --dpu-user ${dpuUser} --dpu-ip ${dpuIp} --dpu-relay-path ${dpuRelayPath}` },
        { label: "Live Receiver T2", command: `cd ${remoteRepo} && bash scripts/run_live_pipeline.sh --tier 2 --symbols ${liveSymbols} --harness ${harnessIp} --fillsim ${fillsimIp} --dpu-user ${dpuUser} --dpu-ip ${dpuIp} --dpu-relay-path ${dpuRelayPath}` },
        { label: "Live Receiver T3", command: `cd ${remoteRepo} && bash scripts/run_live_pipeline.sh --tier 3 --symbols ${liveSymbols} --harness ${harnessIp} --fillsim ${fillsimIp} --dpu-user ${dpuUser} --dpu-ip ${dpuIp} --dpu-relay-path ${dpuRelayPath}` },
        { label: "Live Receiver T4", command: `cd ${remoteRepo} && bash scripts/run_live_pipeline.sh --tier 4 --symbols ${liveSymbols} --harness ${harnessIp} --fillsim ${fillsimIp} --dpu-user ${dpuUser} --dpu-ip ${dpuIp} --dpu-relay-path ${dpuRelayPath}` },
      ]
    : [
        { label: "Live Crypto Sender", command: `cd ${remoteRepo} && bash scripts/run_live_sender.sh --symbols ${liveSymbols} --dpu-ip ${dpuIp} --dpu-user ${dpuUser} --dpu-relay-path ${dpuRelayPath} --iface ${senderDpuIface} --port ${relayPort}` },
        { label: "Link Sender", command: `cd ${remoteRepo} && python3 scripts/test_link.py send --dest 10.10.10.2 --bind ${senderDpuIface} --count 50 --rate 10` },
        { label: "Relay Log", command: `ssh ${dpuUser}@${dpuIp} 'tail -80 /tmp/dpu_relay.log 2>/dev/null || true'` },
        { label: "Kill Sender", command: `pkill -f 'data_source_live|data_source' 2>/dev/null || true; ssh ${dpuUser}@${dpuIp} 'pkill -f dpu_relay 2>/dev/null || true'` },
      ];

  return (
    <section className="glass-panel terminal-panel">
      <div className="terminal-header">
        <div>
          <div className="eyebrow">{role === "receiver" ? "Receiver Terminal" : "Sender Terminal"}</div>
          <h2>{title}</h2>
          <span>{host}</span>
        </div>
        {role === "receiver" ? <Server size={22} /> : <Send size={22} />}
      </div>

      <div className="terminal-controls">
        <label>
          <span>SSH Password</span>
          <input
            type="password"
            value={password}
            placeholder="optional"
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        <div className="terminal-context">
          <button type="button" className={context === "host" ? "is-active" : ""} onClick={() => setContext("host")}>
            <TerminalSquare size={16} />
            Host
          </button>
          <button type="button" className={context === "dpu" ? "is-active" : ""} onClick={() => setContext("dpu")}>
            <Cpu size={16} />
            DPU ARM
          </button>
        </div>
      </div>

      <div className="terminal-connect-row">
        <button type="button" className="terminal-login" onClick={() => openHostSession(anchorHost ?? host)} disabled={openSession.isPending}>
          <TerminalSquare size={17} />
          {role === "sender" ? "Open via lxcpu1" : "Open Receiver Shell"}
        </button>
        {role === "sender" ? (
          <button type="button" className="terminal-login" onClick={() => submitText(`ssh -vvv ${host}`)} disabled={!session || session.status === "closed"}>
            <Send size={17} />
            Connect to Sender
          </button>
        ) : null}
      </div>

      <div className="terminal-connect-row terminal-connect-row--secondary terminal-connect-row--triple">
        <button
          type="button"
          className="terminal-login"
          onClick={() => {
            setContext("dpu");
            submitText(`ssh -vvv ${dpuUser}@${dpuIp}`);
          }}
          disabled={!session || session.status === "closed"}
        >
          <Cpu size={17} />
          Login to ARM Core DPU
        </button>
        <button type="button" className="terminal-login terminal-login--muted" onClick={sendPassword} disabled={!session || session.status === "closed" || !password}>
          <KeyRound size={17} />
          Send Password
        </button>
        <button type="button" className="terminal-login terminal-login--danger" onClick={() => interruptSession.mutate()} disabled={!session || session.status === "closed" || interruptSession.isPending}>
          <SquareTerminal size={17} />
          Ctrl+C
        </button>
      </div>

      <div className="terminal-command-row">
        <input
          value={command}
          onChange={(event) => setCommand(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") submit();
          }}
          placeholder="Type a command to run on the selected context"
        />
        <button type="button" className="primary-button" onClick={submit} disabled={!session || sendInput.isPending}>
          Submit
        </button>
      </div>

      <div className="quick-command-grid">
        {[...hostCommands, ...roleCommands].map((item) => (
          <button
            type="button"
            key={`${item.label}-${item.command}`}
            onClick={() => run("host", item.useRepo === false ? item.command : `cd ${remoteRepo} && ${item.command}`)}
            disabled={!session || session.status === "closed"}
          >
            {item.label}
          </button>
        ))}
        {dpuCommands.map((item) => (
          <button
            type="button"
            key={`${item.label}-${item.command}`}
            onClick={() => run("dpu", item.command)}
            disabled={!session || session.status === "closed"}
          >
            {item.label}
          </button>
        ))}
        {workflowCommands.map((item) => (
          <button
            type="button"
            key={`${item.label}-${item.command}`}
            onClick={() => run("host", item.command)}
            disabled={!session || session.status === "closed"}
          >
            {item.label}
          </button>
        ))}
      </div>

      {openSession.error ? <div className="operator-error">{openSession.error.message}</div> : null}
      {sendInput.error ? <div className="operator-error">{sendInput.error.message}</div> : null}
      {interruptSession.error ? <div className="operator-error">{interruptSession.error.message}</div> : null}
      <PersistentTerminalConsole session={session} output={output} onClose={() => closeSession.mutate()} />
    </section>
  );
});

export function DpuDemo() {
  const [form, setForm] = useState<DpuDemoRequest>(defaults);
  const [senderBootstrap, setSenderBootstrap] = useState<{ token: number; password: string }>({ token: 0, password: "" });
  const [operatorMessage, setOperatorMessage] = useState("Open both terminals, then use these buttons to send commands into them.");
  const [copyJob, setCopyJob] = useState<Job | null>(null);
  const receiverRef = useRef<TerminalPaneHandle>(null);
  const senderRef = useRef<TerminalPaneHandle>(null);
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const artifacts = useQuery({ queryKey: ["dpu-artifacts"], queryFn: api.dpuArtifacts, refetchInterval: 6000 });
  const copyResults = useMutation({
    mutationFn: () => api.startDpuDemo({ ...form, action: "collect" }),
    onSuccess: (data) => {
      setCopyJob(data.job);
      setOperatorMessage("Local SCP copy-back started. The backend will archive remote results and download them into results/remote_dpu/.");
    },
  });
  const copyJobStatus = useQuery({
    queryKey: ["copy-job", copyJob?.id],
    queryFn: () => api.job(copyJob!.id),
    enabled: Boolean(copyJob?.id && ["queued", "running"].includes(copyJob.status)),
    refetchInterval: 1000,
  });

  useEffect(() => {
    const next = copyJobStatus.data?.job;
    if (!next) return;
    setCopyJob(next);
    if (next.status === "completed") {
      setOperatorMessage("Remote results were copied locally. The Received Data list has been refreshed.");
      artifacts.refetch();
    }
    if (next.status === "failed") {
      setOperatorMessage("Local result copy-back failed. Check the copy log and SSH password/key setup.");
    }
  }, [artifacts, copyJobStatus.data?.job]);

  function setValue<K extends keyof DpuDemoRequest>(key: K, value: DpuDemoRequest[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function sendToReceiver(commandText: string) {
    return receiverRef.current?.sendCommand(commandText) ?? false;
  }

  function sendToSender(commandText: string) {
    return senderRef.current?.sendCommand(commandText) ?? false;
  }

  function runAction(action: TerminalAction) {
    setValue("action", action);
    let ok = false;
    if (action === "preflight") {
      const receiverCheck = `cd ${sh(form.remote_repo)} && hostname; pwd; git branch --show-current; git log -1 --oneline; ip -br -4 addr; ssh -vvv ${sh(`${form.dpu_user}@${form.dpu_ip}`)} 'hostname; whoami; ip -br -4 addr || true'`;
      const senderCheck = `cd ${sh(form.remote_repo)} && hostname; pwd; git branch --show-current; git log -1 --oneline; ip -br -4 addr show tmfifo_net0 || true; ssh -vvv ${sh(`${form.dpu_user}@${form.dpu_ip}`)} 'hostname; whoami; ip -br -4 addr || true'`;
      ok = sendToReceiver(receiverCheck) && sendToSender(senderCheck);
      setOperatorMessage(ok ? "Preflight commands sent to both terminals." : "Open both terminal sessions before running preflight.");
      return;
    }
    if (action === "diagnose") {
      ok = sendToReceiver(`cd ${sh(form.remote_repo)} && bash scripts/diagnose_crosslink.sh`);
      setOperatorMessage(ok ? "Crosslink diagnose sent to the receiver terminal." : "Open the receiver terminal first.");
      return;
    }
    if (action === "datapath") {
      ok = sendToReceiver(`cd ${sh(form.remote_repo)} && bash scripts/diagnose_datapath.sh`);
      setOperatorMessage(ok ? "Datapath diagnose sent to the receiver terminal." : "Open the receiver terminal first.");
      return;
    }
    if (action === "live_sender") {
      ok = sendToSender(liveSenderCommand(form));
      setOperatorMessage(ok ? "Live crypto sender command sent to the sender terminal." : "Open and connect the sender terminal first.");
      return;
    }
    if (action === "benchmark") {
      ok = sendToReceiver(benchmarkCommand(form));
      setOperatorMessage(ok ? "Benchmark sweep command sent to the receiver terminal. Sudo/password prompts will stay interactive there." : "Open the receiver terminal first.");
      return;
    }
    if (action === "collect") {
      const receiverOk = sendToReceiver(archiveCommand(form, "receiver", form.receiver_host));
      const senderOk = sendToSender(archiveCommand(form, "sender", form.sender_host));
      setOperatorMessage(receiverOk && senderOk ? "Remote archive commands sent. This does not copy files to the Mac; use Pull Remote Results below for SCP copy-back." : "Open both terminals before preparing result archives.");
    }
  }

  function runCleanup() {
    const receiverOk = sendToReceiver(cleanupCommand(form));
    const senderOk = sendToSender(cleanupCommand(form));
    setOperatorMessage(receiverOk || senderOk ? "Cleanup commands sent. Use this before Benchmark Sweep if relay port 6005 is already busy." : "Open at least one terminal before cleanup.");
  }

  function setTierPreset(tiers: string) {
    setValue("tiers", tiers);
    setOperatorMessage(`Benchmark tiers set to ${tiers}.`);
  }

  const status = health.data?.ok ? "ready" : "backend";
  const statusDot = health.data?.ok ? "completed" : "failed";
  const newest = artifacts.data?.artifacts?.[0];
  const backendProblem = health.error instanceof Error ? health.error.message : null;

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Cross-DPU Remote Demo</div>
          <h1>Connect, run, and collect data from lxcpu1 and lxcpu2.</h1>
        </div>
        <div className="console-status">
          <span className={`status-dot status-dot--${statusDot}`} />
          <span>{status}</span>
        </div>
      </section>

      <div className="terminal-grid">
        <TerminalPane
          ref={receiverRef}
          role="receiver"
          title="lxcpu1 receiver"
          host={form.receiver_host}
          remoteRepo={form.remote_repo}
          dpuUser={form.dpu_user}
          dpuIp={form.dpu_ip}
          receiverDpuIface={form.receiver_dpu_iface}
          senderDpuIface={form.sender_dpu_iface}
          liveSymbols={form.live_symbols}
          relayPort={form.relay_port}
          harnessIp={form.harness_ip}
          fillsimIp={form.fillsim_ip}
          dpuRelayPath={form.dpu_relay_path}
          onConnected={(password) => {
            setSenderBootstrap((prev) => ({ token: prev.token + 1, password }));
            if (password) setValue("ssh_password", password);
          }}
        />
        <TerminalPane
          ref={senderRef}
          role="sender"
          title="lxcpu2 sender"
          host={form.sender_host}
          anchorHost={form.receiver_host}
          remoteRepo={form.remote_repo}
          dpuUser={form.dpu_user}
          dpuIp={form.dpu_ip}
          receiverDpuIface={form.receiver_dpu_iface}
          senderDpuIface={form.sender_dpu_iface}
          liveSymbols={form.live_symbols}
          relayPort={form.relay_port}
          harnessIp={form.harness_ip}
          fillsimIp={form.fillsim_ip}
          dpuRelayPath={form.dpu_relay_path}
          autoConnectToken={senderBootstrap.token}
          autoPassword={senderBootstrap.password}
        />
      </div>

      <div className="dpu-workbench">
        <section className="glass-panel operator-panel">
          <div className="panel-heading">
            <div>
              <h2>Terminal Controls</h2>
              <p>Buttons below send commands into the live terminals above.</p>
            </div>
            <PlugZap size={20} />
          </div>

          <div className="operator-status">
            <span className={`status-dot status-dot--${statusDot}`} />
            <strong>{status}</strong>
            <span>{operatorMessage}</span>
          </div>

          <div className={health.data?.ok ? "backend-status backend-status--ok" : "backend-status backend-status--bad"}>
            <span className={`status-dot status-dot--${health.data?.ok ? "completed" : "failed"}`} />
            <strong>Backend</strong>
            <span>{health.data?.ok ? api.baseUrl : backendProblem ?? `Trying ${api.candidates.join(", ")}`}</span>
          </div>

          <div className="operator-actions">
            {actions.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  type="button"
                  className={item.id === "benchmark" ? "operator-action operator-action--primary" : "operator-action"}
                  onClick={() => runAction(item.id)}
                >
                  <Icon size={20} />
                  <span>{item.label}</span>
                  <small>{item.description}</small>
                </button>
              );
            })}
          </div>

          <button type="button" className="secondary-button operator-refresh" onClick={runCleanup}>
            <SquareTerminal size={17} />
            Stop Sender/Relay
          </button>

          <button type="button" className="secondary-button operator-refresh" onClick={() => artifacts.refetch()}>
            <RefreshCw size={17} />
            Refresh Downloaded Data
          </button>

          {backendProblem ? <div className="operator-error">{backendProblem}</div> : null}
          <div className="operator-hint">Use the Ctrl+C button on a terminal to stop a running script without closing the SSH session.</div>
        </section>

        <section className="glass-panel control-panel">
          <div className="panel-heading">
            <div>
              <h2>Connection</h2>
              <p>These values are used to build commands for the live receiver and sender terminals.</p>
            </div>
            <Cable size={20} />
          </div>

          <div className="form-grid form-grid--two">
            <label>
              <span>Receiver Host</span>
              <input value={form.receiver_host} onChange={(event) => setValue("receiver_host", event.target.value)} />
            </label>
            <label>
              <span>Sender Host</span>
              <input value={form.sender_host} onChange={(event) => setValue("sender_host", event.target.value)} />
            </label>
            <label className="form-grid__wide">
              <span>Remote Repo</span>
              <input value={form.remote_repo} onChange={(event) => setValue("remote_repo", event.target.value)} />
            </label>
            <label>
              <span>DPU Login</span>
              <input value={`${form.dpu_user}@${form.dpu_ip}`} onChange={(event) => {
                const [user, ip] = event.target.value.split("@");
                setForm((prev) => ({ ...prev, dpu_user: user || prev.dpu_user, dpu_ip: ip || prev.dpu_ip }));
              }} />
            </label>
            <label>
              <span>SSH Password</span>
              <input
                type="password"
                value={form.ssh_password}
                placeholder="nvidia1234 or keyless"
                onChange={(event) => setValue("ssh_password", event.target.value)}
              />
            </label>
            <label>
              <span>Receiver Interface</span>
              <input value={form.receiver_iface} onChange={(event) => setValue("receiver_iface", event.target.value)} />
            </label>
            <label>
              <span>Receiver DPU Egress IP</span>
              <input value={form.receiver_dpu_iface} onChange={(event) => setValue("receiver_dpu_iface", event.target.value)} />
            </label>
            <label>
              <span>Sender DPU Egress IP</span>
              <input value={form.sender_dpu_iface} onChange={(event) => setValue("sender_dpu_iface", event.target.value)} />
            </label>
            <label>
              <span>Relay Port</span>
              <input type="number" min={1} max={65535} value={form.relay_port} onChange={(event) => setValue("relay_port", Number(event.target.value))} />
            </label>
            <label className="form-grid__wide">
              <span>DPU Relay Path</span>
              <input value={form.dpu_relay_path} onChange={(event) => setValue("dpu_relay_path", event.target.value)} />
            </label>
            <label className="form-grid__wide">
              <span>Live Crypto Symbols</span>
              <input value={form.live_symbols} placeholder="BTCUSDT,ETHUSDT,SOLUSDT" onChange={(event) => setValue("live_symbols", event.target.value)} />
            </label>
            <label>
              <span>Harness IP</span>
              <input value={form.harness_ip} onChange={(event) => setValue("harness_ip", event.target.value)} />
            </label>
            <label>
              <span>Fill Simulator IP</span>
              <input value={form.fillsim_ip} onChange={(event) => setValue("fillsim_ip", event.target.value)} />
            </label>
            <label>
              <span>Tiers</span>
              <input value={form.tiers} onChange={(event) => setValue("tiers", event.target.value)} />
            </label>
            <div className="form-grid__wide tier-preset-row">
              {["1", "2", "3", "4", "1,2,3,4"].map((tiers) => (
                <button key={tiers} type="button" className={form.tiers === tiers ? "toggle is-on" : "toggle"} onClick={() => setTierPreset(tiers)}>
                  {tiers === "1,2,3,4" ? "T1-T4" : `T${tiers}`}
                </button>
              ))}
            </div>
            <label>
              <span>Rates</span>
              <input value={form.rates} onChange={(event) => setValue("rates", event.target.value)} />
            </label>
            <label>
              <span>Duration</span>
              <input type="number" min={1} value={form.duration_sec} onChange={(event) => setValue("duration_sec", Number(event.target.value))} />
            </label>
            <label>
              <span>Warmup</span>
              <input type="number" min={0} value={form.warmup_sec} onChange={(event) => setValue("warmup_sec", Number(event.target.value))} />
            </label>
            <label>
              <span>CSV Rows</span>
              <input type="number" min={1} value={form.csv_rows} onChange={(event) => setValue("csv_rows", Number(event.target.value))} />
            </label>
            <label>
              <span>CSV Symbols</span>
              <input type="number" min={1} value={form.csv_symbols} onChange={(event) => setValue("csv_symbols", Number(event.target.value))} />
            </label>
            <label className="form-grid__wide">
              <span>CSV Path</span>
              <input value={form.csv_path} onChange={(event) => setValue("csv_path", event.target.value)} />
            </label>
          </div>

          <div className="toggle-row">
            <button className={form.quick ? "toggle is-on" : "toggle"} onClick={() => setValue("quick", !form.quick)} type="button">Quick sweep</button>
            <button className={form.light_bench ? "toggle is-on" : "toggle"} onClick={() => setValue("light_bench", !form.light_bench)} type="button">Light bench</button>
            <button className={form.regen_csv ? "toggle is-on" : "toggle"} onClick={() => setValue("regen_csv", !form.regen_csv)} type="button">Regenerate CSV</button>
            <button className={form.local_sender ? "toggle is-on" : "toggle"} onClick={() => setValue("local_sender", !form.local_sender)} type="button">Local sender</button>
            <button className={form.verbose_ssh ? "toggle is-on" : "toggle"} onClick={() => setValue("verbose_ssh", !form.verbose_ssh)} type="button">DPU ssh -vvv</button>
          </div>
        </section>

        <section className="glass-panel dpu-topology data-panel">
          <div className="panel-heading">
            <div>
              <h2>Received Data</h2>
              <p>{newest ? newest.name : "Benchmark CSV files will appear here after local copy-back."}</p>
            </div>
            <Download size={20} />
          </div>
          <button type="button" className="primary-button download-action" onClick={() => copyResults.mutate()} disabled={copyResults.isPending || Boolean(copyJob && ["queued", "running"].includes(copyJob.status))}>
            <Download size={17} />
            Pull Remote Results
          </button>
          {newest ? (
            <a className="download-card" href={api.artifactUrl(newest.url)} download>
              <Download size={22} />
              <strong>Download latest CSV</strong>
              <span>{bytes(newest.size_bytes)} · {new Date(newest.updated_at).toLocaleString()}</span>
            </a>
          ) : (
            <div className="download-card download-card--empty">
              <Download size={22} />
              <strong>No copied data yet</strong>
              <span>Use Pull Remote Results to SCP receiver/sender artifacts into results/remote_dpu/.</span>
            </div>
          )}
          {copyJob ? (
            <div className="copyback-status">
              <strong>Copy-back {copyJob.status}</strong>
              <span>{copyJob.run_dir ?? copyJob.id}</span>
              <pre>{copyJob.lines.slice(-10).join("\n")}</pre>
            </div>
          ) : null}
          {copyResults.error ? <div className="operator-error">{copyResults.error.message}</div> : null}
          <div className="artifact-list">
            {(artifacts.data?.artifacts ?? []).slice(0, 6).map((item) => (
              <a key={item.path} href={api.artifactUrl(item.url)} download>
                <span>{item.name}</span>
                <small>{bytes(item.size_bytes)}</small>
              </a>
            ))}
          </div>
        </section>
      </div>

    </div>
  );
}
