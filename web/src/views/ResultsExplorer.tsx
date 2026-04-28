import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BarChart3, FileText, RefreshCw } from "lucide-react";
import { api } from "@/lib/api";
import { compactNumber, fixed, percent, tierName, timeAgo } from "@/lib/format";
import { TierBadge } from "@/components/TierBadge";

export function ResultsExplorer() {
  const queryClient = useQueryClient();
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });
  const [selected, setSelected] = useState<string | null>(null);
  const active = selected ?? runs.data?.runs[0]?.name ?? null;
  const details = useQuery({
    queryKey: ["run", active],
    queryFn: () => api.run(active!),
    enabled: Boolean(active),
  });
  const analyze = useMutation({
    mutationFn: api.analyze,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["runs"] }),
  });

  return (
    <div className="view-stack">
      <section className="section-heading">
        <div>
          <div className="eyebrow">Results Explorer</div>
          <h1>Open each run’s summary, raw capture preview, logs, and generated plots.</h1>
        </div>
        <button className="secondary-button" onClick={() => runs.refetch()}>
          <RefreshCw size={17} />
          Refresh
        </button>
      </section>

      <div className="results-layout">
        <section className="glass-panel run-list">
          <div className="panel-heading">
            <div>
              <h2>Runs</h2>
              <p>{runs.data?.runs.length ?? 0} captured</p>
            </div>
          </div>
          {runs.data?.runs.length ? (
            runs.data.runs.map((run) => (
              <button
                key={run.name}
                className={active === run.name ? "run-row is-active" : "run-row"}
                onClick={() => setSelected(run.name)}
              >
                <TierBadge tier={run.summary.tier} />
                <strong>{run.name}</strong>
                <span>{compactNumber(run.summary.rate_hz)} Hz · {timeAgo(run.updated_at)}</span>
              </button>
            ))
          ) : (
            <div className="empty-state">
              <BarChart3 size={34} />
              <strong>No runs yet</strong>
              <span>Start a benchmark to populate `results/single`.</span>
            </div>
          )}
        </section>

        <section className="glass-panel run-detail">
          {details.data ? (
            <>
              <div className="panel-heading">
                <div>
                  <h2>{details.data.run.name}</h2>
                  <p>{tierName(details.data.run.summary.tier)} at {compactNumber(details.data.run.summary.rate_hz)} ticks/sec</p>
                </div>
                <button className="secondary-button" onClick={() => analyze.mutate(details.data!.run.name)}>
                  <FileText size={16} />
                  Analyze
                </button>
              </div>

              <div className="summary-mosaic">
                <div><span>Throughput</span><strong>{compactNumber(details.data.run.summary.achieved_hz)}</strong></div>
                <div><span>Drop Rate</span><strong>{percent(details.data.run.summary.drop_rate)}</strong></div>
                <div><span>Compute p99</span><strong>{fixed(details.data.run.summary.compute_p99_us, 2, " us")}</strong></div>
                <div><span>Jitter |p99|</span><strong>{fixed(details.data.run.summary.jitter_abs_p99_us, 2, " us")}</strong></div>
              </div>

              {details.data.run.plots.length ? (
                <div className="plot-grid">
                  {details.data.run.plots.map((plot) => (
                    <a key={plot.url} className="plot-tile" href={`${api.baseUrl}${plot.url}`} target="_blank" rel="noreferrer">
                      {plot.kind === "png" || plot.kind === "jpg" || plot.kind === "jpeg" ? (
                        <img src={`${api.baseUrl}${plot.url}`} alt={plot.name} />
                      ) : (
                        <div className="plot-file"><FileText size={28} /><span>{plot.kind}</span></div>
                      )}
                      <strong>{plot.name}</strong>
                    </a>
                  ))}
                </div>
              ) : (
                <div className="empty-state empty-state--wide">
                  <FileText size={32} />
                  <strong>No plots generated for this run</strong>
                  <span>Use Analyze to create run-local PNG plots.</span>
                </div>
              )}

              <div className="log-grid">
                {Object.entries(details.data.logs).map(([name, value]) => (
                  <details key={name}>
                    <summary>{name}.log</summary>
                    <pre>{value || "No log file found."}</pre>
                  </details>
                ))}
              </div>
            </>
          ) : (
            <div className="empty-state empty-state--wide">
              <FileText size={34} />
              <strong>Select a run</strong>
              <span>Run artifacts will appear here.</span>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
