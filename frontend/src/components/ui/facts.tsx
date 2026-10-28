import { Fragment, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Term and value pairs of a detail page. A missing value spells the domain word: None, Unspecified, Unknown. */
export function Facts({ items, className }: { items: [term: string, value: ReactNode][]; className?: string }) {
  return (
    <dl className={cn("m-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1.5 text-ui", className)}>
      {items.map(([term, value]) => (
        <Fragment key={term}>
          <dt className="font-semibold text-ink-muted">{term}</dt>
          <dd className="m-0 whitespace-pre-wrap">{value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
