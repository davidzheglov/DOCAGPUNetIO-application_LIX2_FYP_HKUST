export function compactNumber(value?: number | null, digits = 1): string {
  if (value === undefined || value === null || Number.isNaN(value)) return "n/a";
  return Intl.NumberFormat("en", {
    notation: "compact",
    maximumFractionDigits: digits,
  }).format(value);
}

export function fixed(value?: number | null, digits = 2, suffix = ""): string {
  if (value === undefined || value === null || Number.isNaN(value)) return "n/a";
  return `${value.toFixed(digits)}${suffix}`;
}

export function percent(value?: number | null): string {
  if (value === undefined || value === null || Number.isNaN(value)) return "n/a";
  return `${(value * 100).toFixed(3)}%`;
}

export function tierName(tier?: number | null): string {
  switch (tier) {
    case 1:
      return "T1 CPU";
    case 2:
      return "T2 DPDK";
    case 3:
      return "T3 RDMA";
    case 4:
      return "T4 GPUNetIO";
    case 5:
      return "T5 GPUNetIO+DPU";
    default:
      return "Tier n/a";
  }
}

export function timeAgo(iso?: string | null): string {
  if (!iso) return "n/a";
  const date = new Date(iso);
  const diff = Date.now() - date.getTime();
  if (!Number.isFinite(diff)) return "n/a";
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}
