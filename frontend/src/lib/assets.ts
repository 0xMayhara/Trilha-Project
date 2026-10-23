import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { z } from "zod";

import { ACCESS_QUERY_KEY, accessPageSchema, clearOwnAccess, type AccessPage, type PermissionCode } from "@/lib/access";
import { ApiError, apiFetch } from "@/lib/api-client";
import { SESSION_QUERY_KEY } from "@/lib/auth";

/** Asset inventory client (SPEC-0005). Permission checks here only shape the UI; the API decides. */

export const ASSET_KINDS = ["server", "workstation", "network_device", "cloud_resource", "other"] as const;
export const ENVIRONMENTS = ["production", "staging", "development", "testing", "other"] as const;
export const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
export const STATUSES = ["active", "retired"] as const;
/** Declared posture (SPEC-0007 BR-25). There is no "not assessed" or "unknown" code: that is null. */
export const HARDENING_STATUSES = ["hardened", "partially_hardened", "not_hardened"] as const;
export const INTERNET_EXPOSURES = ["exposed", "not_exposed"] as const;

export const KIND_LABELS: Record<(typeof ASSET_KINDS)[number], string> = {
  server: "Server",
  workstation: "Workstation",
  network_device: "Network device",
  cloud_resource: "Cloud resource",
  other: "Other",
};
export const ENVIRONMENT_LABELS: Record<(typeof ENVIRONMENTS)[number], string> = {
  production: "Production",
  staging: "Staging",
  development: "Development",
  testing: "Testing",
  other: "Other",
};
export const CRITICALITY_LABELS: Record<(typeof CRITICALITIES)[number], string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
export const HARDENING_LABELS: Record<(typeof HARDENING_STATUSES)[number], string> = {
  hardened: "Hardened",
  partially_hardened: "Partially hardened",
  not_hardened: "Not hardened",
};
export const EXPOSURE_LABELS: Record<(typeof INTERNET_EXPOSURES)[number], string> = {
  exposed: "Exposed",
  not_exposed: "Not exposed",
};

const teamSchema = z.object({ id: z.uuid(), code: z.string(), name: z.string() });
export const assetSchema = z.object({
  id: z.uuid(),
  team: teamSchema,
  name: z.string(),
  kind: z.enum(ASSET_KINDS),
  hostname: z.string(),
  ip_addresses: z.array(z.string()),
  operating_system: z.string(), // legacy free text, read-only (SPEC-0011)
  os_product: z.string().nullable(),
  os_version: z.string(),
  os_label: z.string().nullable(),
  environment: z.enum(ENVIRONMENTS).nullable(),
  criticality: z.enum(CRITICALITIES).nullable(),
  hardening_status: z.enum(HARDENING_STATUSES).nullable(),
  internet_exposure: z.enum(INTERNET_EXPOSURES).nullable(),
  status: z.enum(STATUSES),
  version: z.number().int().positive(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type Asset = z.infer<typeof assetSchema>;
export const assetPageSchema = z.object({
  count: z.number().int().nonnegative(),
  next: z.string().nullable(),
  previous: z.string().nullable(),
  results: z.array(assetSchema),
});
export type AssetPage = z.infer<typeof assetPageSchema>;

export const FILTER_KEYS = ["status", "team", "kind", "environment", "criticality", "ip", "q"] as const;
export type AssetFilters = Partial<Record<(typeof FILTER_KEYS)[number], string>>;

export const ASSET_QUERY_KEY = ["assets"] as const;

const catalogCode = z.string().regex(/^[a-z0-9_]{1,32}$/);
const osCatalogEntrySchema = z.object({
  code: catalogCode,
  label: z.string().min(1),
  family: catalogCode,
  family_label: z.string().min(1),
});
export type OsCatalogEntry = z.infer<typeof osCatalogEntrySchema>;
/** `next` must be null: a catalog larger than one page fails closed instead of losing options. */
export const osCatalogPageSchema = z.object({
  count: z.number().int().nonnegative(),
  next: z.null(),
  previous: z.null(),
  results: z.array(osCatalogEntrySchema),
});

/** The backend's OS catalog (SPEC-0011). The same for every user; cleared with asset queries. */
export const osCatalogQuery = queryOptions({
  queryKey: [...ASSET_QUERY_KEY, "os-catalog"],
  queryFn: async ({ signal }) =>
    (await apiFetch("/api/v1/assets/os-catalog/?page_size=100", osCatalogPageSchema, { signal })).results,
  staleTime: Infinity,
});

/** Null means the team has not assessed it: never shown as "Not hardened" (SPEC-0007 BR-25). */
export function hardeningSummary(value: Asset["hardening_status"]): string {
  return value ? HARDENING_LABELS[value] : "Not assessed";
}

/** Null means unknown: never shown as "Not exposed" (SPEC-0007 BR-25). */
export function exposureSummary(value: Asset["internet_exposure"]): string {
  return value ? EXPOSURE_LABELS[value] : "Unknown";
}

/** OS text for tables and details. Reads only the asset, never the catalog (SPEC-0011 NFR-03). */
export function osSummary(asset: Pick<Asset, "os_product" | "os_version" | "os_label" | "operating_system">) {
  if (asset.os_product) return [asset.os_label ?? asset.os_product, asset.os_version].filter(Boolean).join(" ");
  return asset.operating_system ? "Not classified" : "Unspecified";
}

export function assetListKey(userId: string, filters: AssetFilters, page: number) {
  return [...ASSET_QUERY_KEY, userId, "list", filters, page] as const;
}

export function assetKey(userId: string, id: string) {
  return [...ASSET_QUERY_KEY, userId, "detail", id] as const;
}

/** Under the own-access prefix, so the existing logout/401 clearing removes it too. */
export function accessTeamsKey(userId: string) {
  return [...ACCESS_QUERY_KEY, userId, "asset-teams"] as const;
}

/** Only allowlisted keys reach the URL. `ip` and `q` are sent as typed; the server canonicalizes. */
export function assetListPath(filters: AssetFilters, page: number): string {
  if (!Number.isSafeInteger(page) || page < 1) throw new Error("Invalid page.");
  const params = new URLSearchParams({ page: String(page) });
  for (const key of FILTER_KEYS) {
    const value = filters[key];
    if (value) params.set(key, value);
  }
  return `/api/v1/assets/?${params.toString()}`;
}

/** A UUID is the only way to address an asset; anything else never becomes part of a path. */
export function assetPath(id: string, action = ""): string {
  return `/api/v1/assets/${z.uuid().parse(id)}/${action}`;
}

export function fetchAssets(filters: AssetFilters, page: number, signal?: AbortSignal) {
  return apiFetch(assetListPath(filters, page), assetPageSchema, { signal });
}

export function fetchAsset(id: string, signal?: AbortSignal) {
  return apiFetch(assetPath(id), assetSchema, { signal });
}

/** The caller's memberships with their permission codes: enough for one form's team options. */
export function fetchAccessTeams(signal?: AbortSignal) {
  // shortcut: one page of 100 memberships; paginate if an actor ever has more teams than that.
  return apiFetch("/api/v1/rbac/me/?page=1&page_size=100", accessPageSchema, { signal });
}

export type AssetInput = {
  name: string;
  kind: string;
  hostname: string;
  ip_addresses: string[];
  os_product: string | null;
  os_version: string;
  environment: string | null;
  criticality: string | null;
  hardening_status: string | null;
  internet_exposure: string | null;
};

export function createAsset(teamId: string, input: AssetInput) {
  return apiFetch("/api/v1/assets/", assetSchema, { method: "POST", body: { team_id: teamId, ...input } });
}

export function updateAsset(asset: Asset, input: AssetInput) {
  return apiFetch(assetPath(asset.id), assetSchema, { method: "PATCH", body: { version: asset.version, ...input } });
}

export function retireAsset(asset: Asset) {
  return apiFetch(assetPath(asset.id, "retire/"), assetSchema, { method: "POST", body: { version: asset.version } });
}

export function restoreAsset(asset: Asset) {
  return apiFetch(assetPath(asset.id, "restore/"), assetSchema, { method: "POST", body: { version: asset.version } });
}

export function transferAsset(asset: Asset, teamId: string) {
  return apiFetch(assetPath(asset.id, "transfer/"), assetSchema, {
    method: "POST",
    body: { version: asset.version, team_id: teamId },
  });
}

/** Teams whose own-access entry lists every given code. Advisory: the server rechecks. */
export function teamsWith(access: AccessPage | undefined, ...codes: PermissionCode[]) {
  return (access?.results ?? [])
    .filter((entry) => codes.every((code) => entry.permissions.includes(code)))
    .map((entry) => entry.team);
}

export function can(access: AccessPage | undefined, teamId: string, ...codes: PermissionCode[]) {
  return teamsWith(access, ...codes).some((team) => team.id === teamId);
}

/** Lines or commas separate addresses; the server canonicalizes and validates each one. */
export function parseAddresses(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean);
}

export function readAssetForm(form: FormData): AssetInput {
  const text = (key: string) => String(form.get(key) ?? "");
  return {
    name: text("name"),
    kind: text("kind"),
    hostname: text("hostname").trim(),
    ip_addresses: parseAddresses(text("ip_addresses")),
    os_product: text("os_product") || null,
    os_version: text("os_version"),
    environment: text("environment") || null,
    criticality: text("criticality") || null,
    // The first option ("Not assessed" / "Unknown") submits "", which is null, never a negative value.
    hardening_status: text("hardening_status") || null,
    internet_exposure: text("internet_exposure") || null,
  };
}

export async function clearAssetQueries(client: QueryClient) {
  await client.cancelQueries({ queryKey: ASSET_QUERY_KEY });
  client.removeQueries({ queryKey: ASSET_QUERY_KEY });
}

/** A 401 ends the session: no asset data may stay cached for the next user of this browser. */
export async function handleAssetError(client: QueryClient, error: unknown) {
  if (error instanceof ApiError && error.status === 401) {
    await clearAssetQueries(client);
    await clearOwnAccess(client);
    client.setQueryData(SESSION_QUERY_KEY, null);
  }
}

const fieldErrorsSchema = z.record(z.string(), z.array(z.string()));

export function fieldErrors(error: unknown): Record<string, string[]> {
  if (!(error instanceof ApiError) || error.status !== 400) return {};
  const parsed = fieldErrorsSchema.safeParse(error.details);
  return parsed.success ? parsed.data : {};
}

export function assetErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    switch (error.status) {
      case 400:
        return "Check the highlighted fields.";
      case 401:
        return "Your session has ended. Log in again.";
      case 403:
        return "Access denied. Your session is still active.";
      case 404:
        return "Asset not found.";
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
