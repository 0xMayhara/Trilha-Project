import type { QueryClient } from "@tanstack/react-query";
import { z } from "zod";

import { ApiError, apiFetch } from "@/lib/api-client";
import {
  CRITICALITIES,
  ENVIRONMENTS,
  handleAssetError,
  HARDENING_STATUSES,
  INTERNET_EXPOSURES,
  ASSET_KINDS,
  STATUSES,
} from "@/lib/assets";

/** Findings client (SPEC-0007 slice B). Capabilities and permissions here only shape the UI; every
 * request is authorized again by the API. */

export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export const CATEGORIES = ["vulnerability", "misconfiguration", "hardening_gap", "end_of_life", "other"] as const;
export const FINDING_STATUSES = ["open", "in_progress"] as const;

export const SEVERITY_LABELS: Record<(typeof SEVERITIES)[number], string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};
export const CATEGORY_LABELS: Record<(typeof CATEGORIES)[number], string> = {
  vulnerability: "Vulnerability",
  misconfiguration: "Misconfiguration",
  hardening_gap: "Hardening gap",
  end_of_life: "End of life",
  other: "Other",
};
export const FINDING_STATUS_LABELS: Record<(typeof FINDING_STATUSES)[number], string> = {
  open: "Open",
  in_progress: "In progress",
};

const teamSchema = z.object({ id: z.uuid(), code: z.string(), name: z.string() });
const userRefSchema = z.object({ id: z.uuid(), username: z.string(), display_name: z.string() });
export type UserRef = z.infer<typeof userRefSchema>;

export const findingSummarySchema = z.object({
  id: z.uuid(),
  title: z.string(),
  severity: z.enum(SEVERITIES),
  category: z.enum(CATEGORIES),
  status: z.enum(FINDING_STATUSES),
  created_at: z.string(),
  asset: z.object({ id: z.uuid(), name: z.string(), status: z.enum(STATUSES) }),
  team: teamSchema,
  assignee: userRefSchema.nullable(),
});
export type FindingSummary = z.infer<typeof findingSummarySchema>;

export const findingSchema = findingSummarySchema.extend({
  version: z.number().int().positive(),
  description: z.string(),
  cve_ids: z.array(z.string()),
  updated_at: z.string(),
  reported_by: userRefSchema,
  asset: z.object({
    id: z.uuid(),
    name: z.string(),
    status: z.enum(STATUSES),
    kind: z.enum(ASSET_KINDS),
    environment: z.enum(ENVIRONMENTS).nullable(),
    criticality: z.enum(CRITICALITIES).nullable(),
    hardening_status: z.enum(HARDENING_STATUSES).nullable(),
    internet_exposure: z.enum(INTERNET_EXPOSURES).nullable(),
    os_label: z.string().nullable(),
    os_version: z.string(),
  }),
  capabilities: z.object({ edit: z.boolean() }),
});
export type Finding = z.infer<typeof findingSchema>;

export const findingPageSchema = z.object({
  count: z.number().int().nonnegative(),
  next: z.string().nullable(),
  previous: z.string().nullable(),
  results: z.array(findingSummarySchema),
});
export type FindingPage = z.infer<typeof findingPageSchema>;

export const entrySchema = z.object({
  id: z.uuid(),
  sequence: z.number().int().positive(),
  kind: z.enum(["comment", "system"]),
  event: z.string().nullable(),
  actor: userRefSchema.nullable(),
  body: z.string().nullable(),
  metadata: z.record(z.string(), z.unknown()),
  created_at: z.string(),
  redacted: z.boolean(),
  redacted_at: z.string().nullable(),
  redaction_reason: z.enum(["secret", "personal_data"]).nullable(),
});
export type Entry = z.infer<typeof entrySchema>;

export const logbookPageSchema = z.object({
  results: z.array(entrySchema),
  has_more_before: z.boolean(),
  last_sequence: z.number().int().nonnegative(),
});
export type LogbookPage = z.infer<typeof logbookPageSchema>;

export const FINDING_FILTER_KEYS = ["status", "severity", "category", "team", "asset", "assignee", "q"] as const;
export type FindingFilters = Partial<Record<(typeof FINDING_FILTER_KEYS)[number], string>>;

/** Every finding query is keyed by the signed-in user, so one user's data never serves another. */
export const FINDINGS_QUERY_KEY = ["findings"] as const;

export function findingListKey(userId: string, filters: FindingFilters, page: number) {
  return [...FINDINGS_QUERY_KEY, userId, "list", filters, page] as const;
}

export function findingKey(userId: string, id: string) {
  return [...FINDINGS_QUERY_KEY, userId, "detail", id] as const;
}

export function logbookKey(userId: string, id: string) {
  return [...FINDINGS_QUERY_KEY, userId, "logbook", id] as const;
}

/** Only allowlisted keys reach the URL; values are sent as typed and validated by the server. */
export function findingListPath(filters: FindingFilters, page: number): string {
  if (!Number.isSafeInteger(page) || page < 1) throw new Error("Invalid page.");
  const params = new URLSearchParams({ page: String(page) });
  for (const key of FINDING_FILTER_KEYS) {
    const value = filters[key];
    if (value) params.set(key, value);
  }
  return `/api/v1/findings/?${params.toString()}`;
}

/** A UUID is the only way to address a finding; anything else never becomes part of a path. */
export function findingPath(id: string, action = ""): string {
  return `/api/v1/findings/${z.uuid().parse(id)}/${action}`;
}

export function fetchFindings(filters: FindingFilters, page: number, signal?: AbortSignal) {
  return apiFetch(findingListPath(filters, page), findingPageSchema, { signal });
}

export function fetchFinding(id: string, signal?: AbortSignal) {
  return apiFetch(findingPath(id), findingSchema, { signal });
}

/** The latest entries, or those before a sequence ("Load earlier"). */
export function fetchLogbook(id: string, before?: number, signal?: AbortSignal) {
  if (before !== undefined && (!Number.isSafeInteger(before) || before < 1)) throw new Error("Invalid cursor.");
  const query = before === undefined ? "" : `?before=${before}`;
  return apiFetch(findingPath(id, `logbook/${query}`), logbookPageSchema, { signal });
}

export type FindingInput = {
  title: string;
  description: string;
  category: string;
  severity: string;
  cve_ids: string[];
};

export function createFinding(assetId: string, input: FindingInput) {
  return apiFetch("/api/v1/findings/", findingSchema, { method: "POST", body: { asset_id: assetId, ...input } });
}

export function updateFinding(finding: Finding, input: FindingInput) {
  return apiFetch(findingPath(finding.id), findingSchema, {
    method: "PATCH",
    body: { version: finding.version, ...input },
  });
}

/** One CVE ID per line (commas and spaces also separate); the server canonicalizes and validates. */
export function parseCveIds(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean);
}

export function readFindingForm(form: FormData): FindingInput {
  const text = (key: string) => String(form.get(key) ?? "");
  return {
    title: text("title"),
    description: text("description"),
    category: text("category"),
    severity: text("severity"),
    cve_ids: parseCveIds(text("cve_ids")),
  };
}

export async function clearFindingQueries(client: QueryClient) {
  await client.cancelQueries({ queryKey: FINDINGS_QUERY_KEY });
  client.removeQueries({ queryKey: FINDINGS_QUERY_KEY });
}

/** True when the error means this finding is no longer visible to the user. */
export function lostAccess(error: unknown) {
  return error instanceof ApiError && (error.status === 403 || error.status === 404);
}

/** 401 ends the session: no finding, asset or access data stays cached. 403/404 on one finding
 * removes that finding's cached detail and logbook (SPEC-0007 SEC-44). */
export async function handleFindingError(client: QueryClient, error: unknown, finding?: { userId: string; id: string }) {
  if (error instanceof ApiError && error.status === 401) {
    await clearFindingQueries(client);
    await handleAssetError(client, error);
  } else if (finding && lostAccess(error)) {
    for (const key of [findingKey(finding.userId, finding.id), logbookKey(finding.userId, finding.id)]) {
      await client.cancelQueries({ queryKey: key });
      client.removeQueries({ queryKey: key });
    }
  }
}

export function findingErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return "Check the highlighted fields.";
      case 401:
        return "Your session has ended. Log in again.";
      case 403:
      case 404:
        return "You no longer have access to this finding.";
      case 409:
        // The server's 409 messages are fixed strings; rendered as text like everything else.
        return `${error.message} Reload to see the current version.`;
      case 429:
        return "Too many changes. Wait a moment and try again.";
      case 503:
        return "Service temporarily unavailable. Try again.";
    }
  }
  return "Something went wrong. Try again.";
}

const REDACTION_LABELS = { secret: "secret", personal_data: "personal data" } as const;

/** Fixed text per system event; codes from later releases fall back to a neutral notice. */
export function systemEventText(entry: Entry): string {
  const meta = entry.metadata;
  const text = (key: string) => (typeof meta[key] === "string" ? (meta[key] as string) : "?");
  switch (entry.event) {
    case "finding_created":
      return "Finding reported";
    case "finding_updated": {
      const fields = Array.isArray(meta.fields) ? meta.fields.filter((f) => typeof f === "string") : [];
      const change = (key: "severity" | "category") => {
        const value = meta[key];
        if (!value || typeof value !== "object") return null;
        const { before, after } = value as { before?: unknown; after?: unknown };
        return `${key} ${String(before)} → ${String(after)}`;
      };
      const details = [change("severity"), change("category")].filter(Boolean).join(", ");
      return `Finding edited: ${fields.join(", ") || "fields"}${details ? ` (${details})` : ""}`;
    }
    case "asset_transferred":
      return `Asset moved from team ${text("from_team")} to team ${text("to_team")}`;
    case "entry_redacted":
      return `An entry was removed by the platform owner (entry ${String(meta.sequence ?? "?")})`;
    default:
      return "System event";
  }
}

export function redactedText(entry: Entry): string {
  const date = entry.redacted_at ? entry.redacted_at.slice(0, 10) : "an unknown date";
  const reason = entry.redaction_reason ? REDACTION_LABELS[entry.redaction_reason] : "unspecified";
  return `Content removed by the platform owner on ${date} (reason: ${reason})`;
}

export function userLabel(user: UserRef | null): string {
  if (!user) return "System";
  return user.display_name ? `${user.display_name} (${user.username})` : user.username;
}
