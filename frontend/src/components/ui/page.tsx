import type { HTMLAttributes, ReactNode } from "react";

import { cn } from "@/lib/utils";

const WIDTHS = {
  wide: "max-w-6xl pt-6",
  medium: "max-w-3xl pt-6",
  narrow: "max-w-md pt-12",
} as const;

/** Centered column of a screen: `wide` 1152px (lists, details), `medium` 768px (forms, account), `narrow` 448px (login). */
export function Page({ width = "wide", children }: { width?: keyof typeof WIDTHS; children: ReactNode }) {
  return <main className={cn("mx-auto flex w-full flex-col gap-6 px-8 pb-12", WIDTHS[width])}>{children}</main>;
}

/** The single h1 of a screen, ruled in brand. */
export function PageTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h1 className={cn("m-0 border-b-2 border-brand pb-2 text-title", className)} {...props} />;
}

export function SectionTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h2 className={cn("m-0 text-heading", className)} {...props} />;
}
