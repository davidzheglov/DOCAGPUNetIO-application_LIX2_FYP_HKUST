import { tierName } from "@/lib/format";

export function TierBadge({ tier }: { tier?: number | null }) {
  return <span className={`tier-badge tier-badge--${tier ?? "x"}`}>{tierName(tier)}</span>;
}
