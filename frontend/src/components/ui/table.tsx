import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

/** List table: sunken header with a brand rule, zebra rows, brand-tint on hover. Scrolls sideways, never hides columns. */
export function Table({ caption, className, children }: { caption: string; className?: string; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table
        className={cn(
          "w-full border-collapse border border-border bg-surface text-left text-ui [&_tbody_tr:hover]:bg-brand-tint [&_tbody_tr:nth-child(even)]:bg-stripe",
          className,
        )}
      >
        <caption className="sr-only">{caption}</caption>
        {children}
      </table>
    </div>
  );
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      scope="col"
      className={cn(
        "border-b-2 border-brand bg-surface-sunken px-3 py-2 text-label whitespace-nowrap",
        className,
      )}
      {...props}
    />
  );
}

export function TableHead({ columns }: { columns: ReactNode[] }) {
  return (
    <thead>
      <tr>
        {columns.map((column, index) => (
          <Th key={index}>{column}</Th>
        ))}
      </tr>
    </thead>
  );
}

export function TableBody(props: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody {...props} />;
}

export function Tr(props: HTMLAttributes<HTMLTableRowElement>) {
  return <tr {...props} />;
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("border-b border-border px-3 py-2 align-top", className)} {...props} />;
}

/** Secondary line inside a cell, such as an ID under a name. */
export function Sub({ className, ...props }: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("block text-caption text-ink-muted", className)} {...props} />;
}
