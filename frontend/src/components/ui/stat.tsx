import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Row of counters of the admin overview. Only real totals: no deltas, no sparklines. */
export function StatGrid({ className, children }: { className?: string; children: ReactNode }) {
  return <dl className={cn("m-0 grid grid-cols-2 gap-3 sm:grid-cols-5", className)}>{children}</dl>;
}

export function Stat({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="border border-t-2 border-border border-t-brand bg-surface px-4 py-3">
      <dt className="text-small text-ink-muted">{label}</dt>
      <dd className="m-0 text-stat text-brand">{value}</dd>
    </div>
  );
}
