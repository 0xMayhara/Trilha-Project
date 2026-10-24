import type { QueryClient } from "@tanstack/react-query";
import { z } from "zod";

import { ApiError, apiFetch } from "@/lib/api-client";
import { SESSION_QUERY_KEY } from "@/lib/auth";

/** The server's supported permission catalog. Unknown codes are rejected, never displayed. */
export const PERMISSION_CODES = [
  "teams.view_team",
  "assets.view_asset",
  "assets.add_asset",
  "assets.change_asset",
  "assets.retire_asset",
  "assets.transfer_asset",
  "findings.view_finding",
  "findings.add_finding",
  "findings.change_finding",
  "findings.comment_finding",
  "findings.work_finding",
  "findings.override_priority",
] as const;
export type PermissionCode = (typeof PERMISSION_CODES)[number];
export const PERMISSION_LABELS: Record<PermissionCode, string> = {
  "teams.view_team": "View team summary",
  "assets.view_asset": "View assets",
  "assets.add_asset": "Register assets",
  "assets.change_asset": "Edit assets",
  "assets.retire_asset": "Retire and restore assets",
  "assets.transfer_asset": "Transfer assets",
  "findings.view_finding": "View findings",
  "findings.add_finding": "Report findings",
  "findings.change_finding": "Edit findings",
  "findings.comment_finding": "Comment on findings",
  "findings.work_finding": "Work on assigned findings",
  "findings.override_priority": "Override finding priority",
};

const teamSchema = z.object({ id: z.uuid(), code: z.string(), name: z.string() });
export const accessPageSchema = z.object({
  count: z.number().int().nonnegative(),
  next: z.string().nullable(),
  previous: z.string().nullable(),
  results: z.array(z.object({
    membership_id: z.uuid(),
    team: teamSchema,
    roles: z.array(teamSchema),
    permissions: z.array(z.enum(PERMISSION_CODES)),
  })),
});
export type AccessPage = z.infer<typeof accessPageSchema>;
export const ACCESS_QUERY_KEY = ["rbac", "me"] as const;

export function accessQueryKey(userId: string, page: number) {
  return [...ACCESS_QUERY_KEY, userId, page] as const;
}

export function fetchOwnAccess(page: number, signal?: AbortSignal) {
  if (!Number.isSafeInteger(page) || page < 1) throw new Error("Invalid page.");
  // Navigation uses local page numbers, never server-returned URLs.
  return apiFetch(`/api/v1/rbac/me/?page=${page}`, accessPageSchema, { signal });
}

export async function clearOwnAccess(client: QueryClient) {
  await client.cancelQueries({ queryKey: ACCESS_QUERY_KEY });
  client.removeQueries({ queryKey: ACCESS_QUERY_KEY });
}

export async function handleAccessError(client: QueryClient, error: unknown) {
  if (error instanceof ApiError && error.status === 401) {
    await clearOwnAccess(client);
    client.setQueryData(SESSION_QUERY_KEY, null);
  }
}

export function accessErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 403) return "Access denied. Your authentication session may still be valid.";
    if (error.status === 401) return "Your session has ended. Log in again.";
    if (error.status === 503) return "Service temporarily unavailable. Try again.";
  }
  return "Unable to load access. Try again.";
}
