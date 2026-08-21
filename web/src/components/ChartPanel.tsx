import { useEffect, useRef } from "react";
import * as echarts from "echarts";

type ChartPanelProps = {
  title: string;
  subtitle?: string;
  option: Record<string, unknown>;
  height?: number;
};

export function ChartPanel({ title, subtitle, option, height = 310 }: ChartPanelProps) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: "canvas" });
    chart.setOption(option);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(ref.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [option]);

  return (
    <section className="glass-panel chart-panel">
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
      </div>
      <div ref={ref} className="chart-surface" style={{ height }} />
    </section>
  );
}
