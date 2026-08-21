import type { LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string;
  value: string;
  hint?: string;
  icon: LucideIcon;
  tone?: "cyan" | "green" | "amber" | "rose";
};

export function MetricCard({ label, value, hint, icon: Icon, tone = "cyan" }: MetricCardProps) {
  return (
    <section className={`metric-card metric-card--${tone}`}>
      <div className="metric-card__icon">
        <Icon size={20} strokeWidth={1.8} />
      </div>
      <div>
        <p className="metric-card__label">{label}</p>
        <strong>{value}</strong>
        {hint ? <span>{hint}</span> : null}
      </div>
    </section>
  );
}
