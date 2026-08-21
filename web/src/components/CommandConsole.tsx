import { useEffect, useMemo, useState } from "react";
import { Square } from "lucide-react";
import { api } from "@/lib/api";
import type { Job } from "@/lib/types";

type CommandConsoleProps = {
  job?: Job | null;
  onJobUpdate?: (job: Job) => void;
  onStop?: () => void;
};

export function CommandConsole({ job, onJobUpdate, onStop }: CommandConsoleProps) {
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    setLines(job?.lines ?? []);
  }, [job?.id]);

  useEffect(() => {
    if (!job?.id) return;
    const socket = new WebSocket(api.wsUrl(job.id));
    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data) as { job?: Job; lines?: string[] };
      if (payload.job) onJobUpdate?.(payload.job);
      if (payload.lines?.length) {
        setLines((prev) => [...prev, ...payload.lines!].slice(-240));
      }
    };
    return () => socket.close();
  }, [job?.id, onJobUpdate]);

  const status = job?.status ?? "idle";
  const command = useMemo(() => job?.command?.join(" ") ?? "No job running", [job]);

  return (
    <section className="glass-panel command-console">
      <div className="panel-heading">
        <div>
          <h2>Run Console</h2>
          <p>{command}</p>
        </div>
        {job && status === "running" ? (
          <button className="icon-button icon-button--danger" onClick={onStop} title="Stop job">
            <Square size={17} />
          </button>
        ) : null}
      </div>
      <div className="console-status">
        <span className={`status-dot status-dot--${status}`} />
        <span>{status}</span>
        {job?.returncode !== undefined && job?.returncode !== null ? <span>exit {job.returncode}</span> : null}
      </div>
      <pre>
        {lines.length
          ? lines.join("\n")
          : "Start a benchmark, build, analysis, or live pipeline job to stream logs here."}
      </pre>
    </section>
  );
}
