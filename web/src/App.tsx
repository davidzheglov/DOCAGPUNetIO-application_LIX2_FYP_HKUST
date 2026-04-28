import { useMemo, useState } from "react";
import { Activity, BarChart3, CircuitBoard, Gauge, Layers3, PlayCircle, Radio } from "lucide-react";
import { motion, AnimatePresence } from "motion/react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { HighTechBackground } from "@/components/HighTechBackground";
import { Overview } from "@/views/Overview";
import { RunBenchmark } from "@/views/RunBenchmark";
import { ResultsExplorer } from "@/views/ResultsExplorer";
import { Comparison } from "@/views/Comparison";
import { Architecture } from "@/views/Architecture";
import { LivePipeline } from "@/views/LivePipeline";

const nav = [
  { id: "overview", label: "Overview", icon: Gauge },
  { id: "run", label: "Run", icon: PlayCircle },
  { id: "results", label: "Results", icon: BarChart3 },
  { id: "compare", label: "Compare", icon: Layers3 },
  { id: "architecture", label: "Architecture", icon: CircuitBoard },
  { id: "live", label: "Live", icon: Radio },
] as const;

type ViewId = (typeof nav)[number]["id"];

export default function App() {
  const [active, setActive] = useState<ViewId>("overview");
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 10000 });

  const view = useMemo(() => {
    switch (active) {
      case "run":
        return <RunBenchmark />;
      case "results":
        return <ResultsExplorer />;
      case "compare":
        return <Comparison />;
      case "architecture":
        return <Architecture />;
      case "live":
        return <LivePipeline />;
      default:
        return <Overview />;
    }
  }, [active]);

  return (
    <div className="app-shell">
      <HighTechBackground />
      <div className="topbar">
        <div className="brand-mark">
          <Activity size={24} />
          <div>
            <strong>DOCAGPUNetIO</strong>
            <span>HKUST FYP Control Surface</span>
          </div>
        </div>
        <nav className="nav-tabs" aria-label="Primary">
          {nav.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={active === item.id ? "is-active" : ""}
                onClick={() => setActive(item.id)}
              >
                <Icon size={17} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <div className="api-pill">
          <span className={`status-dot status-dot--${health.data?.ok ? "completed" : "failed"}`} />
          <span>{health.data?.ok ? "API online" : "API offline"}</span>
        </div>
      </div>

      <main>
        <AnimatePresence mode="wait">
          <motion.div
            key={active}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.28, ease: "easeOut" }}
          >
            {view}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
