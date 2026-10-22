import type { QueryClient } from "@tanstack/react-query";
import { z } from "zod";

import { clearOwnAccess, PERMISSION_CODES } from "@/lib/access";
import { ApiError, apiFetch } from "@/lib/api-client";
import { clearAssetQueries } from "@/lib/assets";
import { SESSION_QUERY_KEY } from "@/lib/auth";

/** Platform administration client (SPEC-0010). Everything here only shapes the UI: the server
 * decides every Admin check, step-up and guard. Password links live only in component state. */

export const POSITIONS = ["analyst", "engineer"] as const;
export type Position = (typeof POSITIONS)[number];
export const POSITION_LABELS: Record<Position, string> = { analyst: "Analyst", engineer: "Engineer" };

const position = z.enum(POSITIONS).nullable();

/** The caller's own platform state. Strict: an unexpected field fails closed (no admin UI). */
export const platformSelfSchema = z.strictObject({
  is_admin: z.boolean(),
  position,
  reauthenticated_until: z.string().nullable(),
});
export type PlatformSelf = z.infer<typeof platformSelfSchema>;

const roleSummary = z.object({ id: z.uuid(), code: z.string(), name: z.string() });
export const teamAdminSchema = z.object({
  id: z.uuid(),
  code: z.string(),
  name: z.string(),
  is_active: z.boolean(),
  member_count: z.number().int().nonnegative(),
});
export type TeamAdmin = z.infer<typeof teamAdminSchema>;

export const userAdminSchema = z.object({
  id: z.uuid(),
  username: z.string(),
  first_name: z.string(),
  last_name: z.string(),
  email: z.string(),
  is_active: z.boolean(),
  password_set: z.boolean(),
  is_admin: z.boolean(),
  position,
  date_joined: z.string(),
  last_login: z.string().nullable(),
});
export type UserAdmin = z.infer<typeof userAdminSchema>;

export const userDetailSchema = userAdminSchema.extend({
  memberships: z.array(
    z.object({ membership_id: z.uuid(), team: teamAdminSchema, roles: z.array(roleSummary) }),
  ),
});
export type UserDetail = z.infer<typeof userDetailSchema>;

export const passwordLinkSchema = z.object({
  url: z.string().startsWith("http"),
  expires_in_seconds: z.number().int().positive(),
});
export type IssuedLink = z.infer<typeof passwordLinkSchema>;
export const userCreatedSchema = z.object({ user: userAdminSchema, password_link: passwordLinkSchema });

export const memberSchema = z.object({
  membership_id: z.uuid(),
  user: z.object({
    id: z.uuid(),
    username: z.string(),
    first_name: z.string(),
    last_name: z.string(),
    is_active: z.boolean(),
    position,
  }),
  roles: z.array(roleSummary),
});
export type Member = z.infer<typeof memberSchema>;

export const roleAdminSchema = z.object({
  id: z.uuid(),
  code: z.string(),
  name: z.string(),
  permissions: z.array(z.enum(PERMISSION_CODES)),
});
export type RoleAdmin = z.infer<typeof roleAdminSchema>;

export const catalogEntrySchema = z.object({ code: z.enum(PERMISSION_CODES), action: z.string() });

export const activationPreviewSchema = z.object({
  team: teamAdminSchema,
  membership_count: z.number().int().nonnegative(),
  role_assignment_count: z.number().int().nonnegative(),
  revision: z.string().regex(/^[0-9a-f]{64}$/),
});
export type ActivationPreview = z.infer<typeof activationPreviewSchema>;

export const auditEntrySchema = z.object({
  event_id: z.uuid(),
  occurred_at: z.string(),
  actor: z.object({ type: z.string(), id: z.uuid().nullable(), label: z.string() }),
  action: z.string(),
  outcome: z.string(),
  resource: z.object({ type: z.string(), id: z.string() }),
  source: z.string(),
  request_id: z.uuid().nullable(),
  client_ip: z.string().nullable(),
  changes: z.record(z.string(), z.unknown()),
  metadata: z.record(z.string(), z.unknown()),
});
export type AuditEntry = z.infer<typeof auditEntrySchema>;

export function pageOf<T extends z.ZodType>(item: T) {
  return z.object({
    count: z.number().int().nonnegative(),
    next: z.string().nullable(),
    previous: z.string().nullable(),
    results: z.array(item),
  });
}

// Query keys: always under the signed-in user's ID, so another user of this browser never sees them.

export const PLATFORM_QUERY_KEY = ["platform"] as const;
export const ADMIN_QUERY_KEY = ["admin"] as const;

export function platformKey(userId: string) {
  return [...PLATFORM_QUERY_KEY, userId] as const;
}

export function adminKey(userId: string, ...parts: readonly unknown[]) {
  return [...ADMIN_QUERY_KEY, userId, ...parts] as const;
}

export function fetchPlatformSelf(signal?: AbortSignal) {
  return apiFetch("/api/v1/rbac/me/platform/", platformSelfSchema, { signal });
}

// Paths: only allowlisted query keys and UUIDs ever reach a URL.

const ADMIN = "/api/v1/admin/";
export const USER_FILTER_KEYS = ["q", "is_active", "is_admin", "position"] as const;
export const TEAM_FILTER_KEYS = ["q", "is_active"] as const;
export const AUDIT_FILTER_KEYS = [
  "action",
  "actor_id",
  "resource_type",
  "resource_id",
  "outcome",
  "source",
  "occurred_after",
  "occurred_before",
] as const;
export type Filters<K extends string> = Partial<Record<K, string>>;

export function adminPath(...segments: string[]): string {
  return ADMIN + segments.map((segment) => `${segment}/`).join("");
}

export function uuidSegment(id: string): string {
  return z.uuid().parse(id);
}

export function listPath<K extends string>(
  resource: string,
  keys: readonly K[],
  filters: Filters<K>,
  page: number,
  pageSize?: number,
): string {
  if (!Number.isSafeInteger(page) || page < 1) throw new Error("Invalid page.");
  const params = new URLSearchParams({ page: String(page) });
  if (pageSize !== undefined) params.set("page_size", String(pageSize));
  for (const key of keys) {
    const value = filters[key];
    if (value) params.set(key, value);
  }
  return `${ADMIN}${resource}/?${params.toString()}`;
}

const noContent = z.undefined();
const usersPage = pageOf(userAdminSchema);
const teamsPage = pageOf(teamAdminSchema);
const membersPage = pageOf(memberSchema);
const rolesPage = pageOf(roleAdminSchema);
const catalogPage = pageOf(catalogEntrySchema);
const auditPage = pageOf(auditEntrySchema);

export const fetchUsers = (filters: Filters<(typeof USER_FILTER_KEYS)[number]>, page: number, signal?: AbortSignal, pageSize?: number) =>
  apiFetch(listPath("users", USER_FILTER_KEYS, filters, page, pageSize), usersPage, { signal });
export const fetchUser = (id: string, signal?: AbortSignal) =>
  apiFetch(adminPath("users", uuidSegment(id)), userDetailSchema, { signal });
export const fetchTeams = (filters: Filters<(typeof TEAM_FILTER_KEYS)[number]>, page: number, signal?: AbortSignal, pageSize?: number) =>
  apiFetch(listPath("teams", TEAM_FILTER_KEYS, filters, page, pageSize), teamsPage, { signal });
export const fetchTeam = (id: string, signal?: AbortSignal) =>
  apiFetch(adminPath("teams", uuidSegment(id)), teamAdminSchema, { signal });
export const fetchMembers = (teamId: string, page: number, signal?: AbortSignal) =>
  apiFetch(listPath(`teams/${uuidSegment(teamId)}/members`, [], {}, page), membersPage, { signal });
export const fetchActivationPreview = (teamId: string, signal?: AbortSignal) =>
  apiFetch(adminPath("teams", uuidSegment(teamId), "activation-preview"), activationPreviewSchema, { signal });
export const fetchRoles = (filters: Filters<"q">, page: number, signal?: AbortSignal, pageSize?: number) =>
  apiFetch(listPath("roles", ["q"], filters, page, pageSize), rolesPage, { signal });
export const fetchRole = (id: string, signal?: AbortSignal) =>
  apiFetch(adminPath("roles", uuidSegment(id)), roleAdminSchema, { signal });
export const fetchCatalog = (signal?: AbortSignal) =>
  apiFetch(listPath("permissions", [], {}, 1, 100), catalogPage, { signal });
export const fetchAudit = (filters: Filters<(typeof AUDIT_FILTER_KEYS)[number]>, page: number, signal?: AbortSignal) =>
  apiFetch(listPath("audit-events", AUDIT_FILTER_KEYS, filters, page), auditPage, { signal });

const post = <T>(path: string, schema: z.ZodType<T>, body: unknown = {}) =>
  apiFetch(path, schema, { method: "POST", body });
const patch = <T>(path: string, schema: z.ZodType<T>, body: unknown) =>
  apiFetch(path, schema, { method: "PATCH", body });
const user = (id: string, action?: string) =>
  action ? adminPath("users", uuidSegment(id), action) : adminPath("users", uuidSegment(id));

export type ProfileInput = { first_name?: string; last_name?: string; email?: string };

export const createUser = (input: { username: string } & ProfileInput) =>
  post(adminPath("users"), userCreatedSchema, input);
export const updateUser = (id: string, changes: ProfileInput) => patch(user(id), userAdminSchema, changes);
export const disableUser = (id: string) => post(user(id, "disable"), userAdminSchema);
export const enableUser = (id: string) => post(user(id, "enable"), userCreatedSchema);
export const issuePasswordLink = (id: string) => post(user(id, "password-link"), passwordLinkSchema);
export const setPosition = (id: string, value: Position | null) =>
  post(user(id, "position"), userAdminSchema, { position: value });
export const grantAdmin = (id: string) => post(user(id, "grant-admin"), userAdminSchema);
export const revokeAdmin = (id: string) => post(user(id, "revoke-admin"), userAdminSchema);

const team = (id: string, ...rest: string[]) => adminPath("teams", uuidSegment(id), ...rest);
export const createTeam = (code: string, name: string) => post(adminPath("teams"), teamAdminSchema, { code, name });
export const renameTeam = (id: string, name: string) => patch(team(id), teamAdminSchema, { name });
export const deactivateTeam = (id: string) => post(team(id, "deactivate"), teamAdminSchema);
export const activateTeam = (id: string, revision: string, confirmationCode: string) =>
  post(team(id, "activate"), teamAdminSchema, { revision, confirmation_code: confirmationCode });
export const addMember = (teamId: string, userId: string) =>
  post(team(teamId, "members"), memberSchema, { user_id: uuidSegment(userId) });
export const removeMember = (teamId: string, userId: string) =>
  post(team(teamId, "members", uuidSegment(userId), "remove"), noContent);
export const assignRole = (membershipId: string, roleId: string) =>
  post(adminPath("memberships", uuidSegment(membershipId), "roles"), memberSchema, { role_id: uuidSegment(roleId) });
export const revokeRole = (membershipId: string, roleId: string) =>
  post(adminPath("memberships", uuidSegment(membershipId), "roles", uuidSegment(roleId), "revoke"), memberSchema);

const role = (id: string, ...rest: string[]) => adminPath("roles", uuidSegment(id), ...rest);
export const createRole = (code: string, name: string) => post(adminPath("roles"), roleAdminSchema, { code, name });
export const renameRole = (id: string, name: string) => patch(role(id), roleAdminSchema, { name });
export const grantPermission = (id: string, permission: string) =>
  post(role(id, "grant-permission"), roleAdminSchema, { permission });
export const revokePermission = (id: string, permission: string) =>
  post(role(id, "revoke-permission"), roleAdminSchema, { permission });

export function reauthenticate(password: string) {
  return apiFetch("/api/v1/auth/reauthenticate/", noContent, { method: "POST", body: { password } });
}

// Step-up: one prompt, then exactly one retry of the original request (SPEC-0010 BR-07, F-08).

export class StepUpCancelled extends Error {
  constructor() {
    super("Password confirmation was cancelled.");
    this.name = "StepUpCancelled";
  }
}

export function isStepUpRequired(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403 && error.code === "reauthentication_required";
}

export async function withStepUp<T>(run: () => Promise<T>, confirm: () => Promise<void>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (!isStepUpRequired(error)) throw error;
    await confirm(); // rejects with StepUpCancelled when the person cancels
    return run(); // a second refusal propagates: no loop of prompts
  }
}

/** Re-authentication rotated the session key and CSRF token: read the session and platform state
 * again before the original request is retried (design review F-08). */
export async function afterReauthentication(client: QueryClient) {
  await client.refetchQueries({ queryKey: SESSION_QUERY_KEY });
  await client.invalidateQueries({ queryKey: PLATFORM_QUERY_KEY });
}

// Cache hygiene (SEC-32).

export async function clearAdminQueries(client: QueryClient) {
  await client.cancelQueries({ queryKey: ADMIN_QUERY_KEY });
  await client.cancelQueries({ queryKey: PLATFORM_QUERY_KEY });
  client.removeQueries({ queryKey: ADMIN_QUERY_KEY });
  client.removeQueries({ queryKey: PLATFORM_QUERY_KEY });
}

/** 401 ends the session and clears every private query. An Admin-route 403 means the grant is
 * gone: admin data is dropped and the platform state is read again. */
export async function handleAdminError(client: QueryClient, error: unknown) {
  if (!(error instanceof ApiError)) return;
  if (error.status === 401) {
    await clearAdminQueries(client);
    await clearAssetQueries(client);
    await clearOwnAccess(client);
    client.setQueryData(SESSION_QUERY_KEY, null);
  } else if (error.status === 403 && error.code === "permission_denied") {
    await client.cancelQueries({ queryKey: ADMIN_QUERY_KEY });
    client.removeQueries({ queryKey: ADMIN_QUERY_KEY });
    await client.invalidateQueries({ queryKey: PLATFORM_QUERY_KEY });
  }
}

const fieldErrorsSchema = z.record(z.string(), z.array(z.string()));

export function adminErrorMessage(error: unknown): string {
  if (error instanceof StepUpCancelled) return "Password confirmation was cancelled. Nothing changed.";
  if (!(error instanceof ApiError)) return "Something went wrong. Try again.";
  switch (error.status) {
    case 400: {
      const details = fieldErrorsSchema.safeParse(error.details);
      const messages = details.success ? Object.values(details.data).flat() : [];
      return messages.length > 0 ? messages.join(" ") : "Check the form and try again.";
    }
    case 401:
      return "Your session has ended. Log in again.";
    case 403:
      return error.code === "reauthentication_required"
        ? "Confirm your password to continue."
        : "Administration access is no longer available.";
    case 404:
      return "Not found. It may have been changed by someone else; reload the page.";
    case 409:
      // Fixed server-side text (guards and conflicts); never exception details.
      return error.message;
    case 429:
      return "Too many changes in a short time. Wait a moment and try again.";
    case 503:
      return "Service temporarily unavailable. Try again.";
    default:
      return "Something went wrong. Try again.";
  }
}
