import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Bordered block with a sunken title bar. Panels do not nest. */
export function Panel({ title, className, children }: { title?: ReactNode; className?: string; children: ReactNode }) {
  return (
    <section className={cn("border border-border bg-surface", className)}>
      {title ? (
        <h2 className="m-0 border-b border-border bg-surface-sunken px-4 py-2 text-subheading text-brand">{title}</h2>
      ) : null}
      <div className="flex flex-col gap-3 p-4">{children}</div>
    </section>
  );
}
