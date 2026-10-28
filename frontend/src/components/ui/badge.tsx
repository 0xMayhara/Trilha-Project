import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export type BadgeTone = "critical" | "high" | "medium" | "low" | "progress" | "ok" | "warn" | "muted" | "plain";

const TONES: Record<BadgeTone, string> = {
  critical: "border-danger bg-danger text-on-brand",
  high: "border-danger-border bg-danger-tint text-danger",
  medium: "border-caution-border bg-caution-tint text-caution",
  low: "border-info-border bg-info-tint text-info",
  progress: "border-info-border bg-info-tint text-info",
  ok: "border-success-border bg-success-tint text-success",
  warn: "border-warning-border bg-warning-tint text-warning",
  muted: "border-border bg-surface-sunken text-ink-muted",
  plain: "border-border-strong bg-surface text-ink",
};

/** Short word for a level or state. The word always shows: color only reinforces it. */
export function Badge({ tone = "plain", className, ...props }: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) {
  return (
    <span
      className={cn(
        "inline-block rounded-sm border px-1.5 py-px text-caption font-semibold whitespace-nowrap",
        TONES[tone],
        className,
      )}
      {...props}
    />
  );
}
