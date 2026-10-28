import type { HTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export type NoticeTone = "error" | "success" | "confirm" | "info";

const TONES: Record<NoticeTone, string> = {
  error: "border-danger-border bg-danger-tint text-danger",
  success: "border-success-border bg-success-tint text-success",
  confirm: "border-warning-border bg-warning-tint text-ink",
  info: "border-info-border bg-info-tint text-info",
};

const ROLES: Partial<Record<NoticeTone, string>> = { error: "alert", success: "status" };

/** Inline message. `error` is an alert, `success` a status, `confirm` is the explicit second step before a destructive action. */
export function Notice({ tone = "info", className, ...props }: HTMLAttributes<HTMLDivElement> & { tone?: NoticeTone }) {
  const confirm = tone === "confirm";
  return (
    <div
      role={ROLES[tone] ?? (confirm ? "group" : undefined)}
      aria-label={confirm ? "Confirm action" : undefined}
      className={cn("flex flex-col gap-2 rounded-sm border px-4 py-3 text-ui", TONES[tone], className)}
      {...props}
    />
  );
}
