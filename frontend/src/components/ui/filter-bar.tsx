import type { FormHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/** The strip of filters above a list. Filters apply on submit, never on each keystroke. */
export function FilterBar({ label, className, ...props }: FormHTMLAttributes<HTMLFormElement> & { label: string }) {
  return (
    <form
      role="search"
      aria-label={label}
      className={cn("flex flex-wrap items-end gap-3 border border-border bg-surface-sunken px-4 py-3", className)}
      {...props}
    />
  );
}
