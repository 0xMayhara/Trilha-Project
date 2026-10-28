import { Badge, type BadgeTone } from "./badge";

/** Severity of a finding and criticality of an asset share one scale. `null` is Unassessed, never a guess. */
const LEVELS = { critical: ["critical", "Critical"], high: ["high", "High"], medium: ["medium", "Medium"], low: ["low", "Low"] } as const;

export function LevelBadge({ level }: { level: keyof typeof LEVELS | null }) {
  if (!level) return <Badge tone="muted">Unassessed</Badge>;
  const [tone, label] = LEVELS[level];
  return <Badge tone={tone}>{label}</Badge>;
}

export function FindingStatusBadge({ status }: { status: "open" | "in_progress" }) {
  return status === "open" ? <Badge tone="warn">Open</Badge> : <Badge tone="progress">In progress</Badge>;
}

export function AssetStatusBadge({ status }: { status: "active" | "retired" }) {
  return status === "active" ? <Badge tone="ok">Active</Badge> : <Badge tone="muted">Retired</Badge>;
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return enabled ? <Badge tone="ok">Enabled</Badge> : <Badge tone="muted">Disabled</Badge>;
}

export function TeamStateBadge({ active }: { active: boolean }) {
  return active ? <Badge tone="ok">Active</Badge> : <Badge tone="muted">Inactive</Badge>;
}

export type { BadgeTone };
