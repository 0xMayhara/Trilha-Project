import { MutationObserver, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuditTable, readAuditFilters, toIsoWithOffset } from "@/components/admin/audit";
import { OneTimeLink } from "@/components/admin/shared";
import { StepUpProvider } from "@/components/admin/step-up";
import { MemberTable, TeamTable } from "@/components/admin/teams";
import { RoleTable } from "@/components/admin/roles";
import { UserFacts, UserTable } from "@/components/admin/users";
import { AdministrationLink } from "@/components/auth-nav";
import { ACCESS_QUERY_KEY, accessQueryKey } from "@/lib/access";
import {
  ADMIN_QUERY_KEY,
  adminErrorMessage,
  adminKey,
  afterReauthentication,
  auditEntrySchema,
  createUser,
  fetchUsers,
  handleAdminError,
  isStepUpRequired,
  listPath,
  memberSchema,
  PLATFORM_QUERY_KEY,
  platformKey,
  platformSelfSchema,
  roleAdminSchema,
  activationPreviewSchema,
  StepUpCancelled,
  userAdminSchema,
  uuidSegment,
  withStepUp,
} from "@/lib/admin";
import { ApiError } from "@/lib/api-client";
import { ASSET_QUERY_KEY } from "@/lib/assets";
import { SESSION_QUERY_KEY } from "@/lib/auth";

const id = "11111111-1111-4111-8111-111111111111";
const other = "22222222-2222-4222-8222-222222222222";
const user = {
  id,
  username: "alice",
  first_name: "Alice",
  last_name: "Doe",
  email: "alice@example.com",
  is_active: true,
  password_set: true,
  is_admin: false,
  position: "analyst" as const,
  date_joined: "2026-10-22T10:00:00Z",
  last_login: null,
};
const team = { id: other, code: "alpha", name: "Alpha", is_active: true, member_count: 1 };
const link = { url: "https://trilha.example/set-password#uid=AAA&token=canary-token-77", expires_in_seconds: 3600 };
const stepUp = () => new ApiError(403, "reauthentication_required", "Confirm your password to continue.");
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
afterEach(() => vi.unstubAllGlobals());

describe("SPEC-0010 administration client", () => {
  it("test_platform_and_admin_schemas_are_strict", () => {
    const self = { is_admin: true, position: "engineer", reauthenticated_until: null };
    expect(platformSelfSchema.parse(self)).toEqual(self);
    for (const forged of [
      { ...self, is_admin: "true" },
      { ...self, position: "admin" },
      { ...self, is_superuser: true },
      { is_admin: true },
    ]) {
      expect(() => platformSelfSchema.parse(forged)).toThrow();
    }
    expect(() => userAdminSchema.parse({ ...user, position: "both" })).toThrow();
    expect(() => userAdminSchema.parse({ ...user, is_admin: 1 })).toThrow();
    expect(() => roleAdminSchema.parse({ id, code: "r", name: "R", permissions: ["assets.*"] })).toThrow();
    expect(() =>
      memberSchema.parse({ membership_id: id, user: { ...user, position: "lead" }, roles: [] }),
    ).toThrow();
    const preview = { team, membership_count: 1, role_assignment_count: 0, revision: "a".repeat(64) };
    expect(activationPreviewSchema.parse(preview).revision).toHaveLength(64);
    expect(() => activationPreviewSchema.parse({ ...preview, revision: "A".repeat(64) })).toThrow();
    expect(() => auditEntrySchema.parse({ event_id: "x" })).toThrow();
  });

  it("test_step_up_dialog_retries_once_after_success", async () => {
    const run = vi.fn().mockRejectedValueOnce(stepUp()).mockResolvedValueOnce("done");
    const confirm = vi.fn().mockResolvedValue(undefined);
    await expect(withStepUp(run, confirm)).resolves.toBe("done");
    expect(run).toHaveBeenCalledTimes(2);
    expect(confirm).toHaveBeenCalledTimes(1);

    // A second refusal is not retried again: no loop of prompts.
    const stubborn = vi.fn().mockRejectedValue(stepUp());
    const once = vi.fn().mockResolvedValue(undefined);
    await expect(withStepUp(stubborn, once)).rejects.toMatchObject({ code: "reauthentication_required" });
    expect(stubborn).toHaveBeenCalledTimes(2);
    expect(once).toHaveBeenCalledTimes(1);

    // Cancelling sends nothing more; other errors never prompt.
    const cancelled = vi.fn().mockRejectedValue(stepUp());
    await expect(withStepUp(cancelled, () => Promise.reject(new StepUpCancelled()))).rejects.toBeInstanceOf(StepUpCancelled);
    expect(cancelled).toHaveBeenCalledTimes(1);
    const denied = vi.fn().mockRejectedValue(new ApiError(403, "permission_denied", "No"));
    const never = vi.fn();
    await expect(withStepUp(denied, never)).rejects.toMatchObject({ code: "permission_denied" });
    expect(never).not.toHaveBeenCalled();
    expect(isStepUpRequired(new ApiError(400, "reauthentication_required", "x"))).toBe(false);

    // After the key rotation, the session is read again before the retry (design review F-08).
    const client = new QueryClient();
    const order: string[] = [];
    client.setQueryDefaults(SESSION_QUERY_KEY, {
      queryFn: async () => {
        order.push("session");
        return { id };
      },
    });
    client.setQueryData(SESSION_QUERY_KEY, { id });
    client.setQueryData(platformKey(id), { is_admin: true, position: null, reauthenticated_until: null });
    await afterReauthentication(client);
    expect(order).toEqual(["session"]);
    expect(client.getQueryState(platformKey(id))?.isInvalidated).toBe(true);
  });

  it("test_admin_queries_are_user_scoped_and_cleared_cwe_524", async () => {
    expect(adminKey("first", "users")).not.toEqual(adminKey("second", "users"));
    expect(platformKey("first")).not.toEqual(platformKey("second"));
    const fill = (client: QueryClient) => {
      client.setQueryData(SESSION_QUERY_KEY, { id });
      client.setQueryData(platformKey(id), { is_admin: true });
      client.setQueryData(adminKey(id, "users", {}, 1), { results: [user] });
      client.setQueryData(adminKey("previous-user", "audit"), { results: [] });
      client.setQueryData(accessQueryKey(id, 1), { results: [] });
      client.setQueryData([...ASSET_QUERY_KEY, id, "list"], { results: [] });
    };
    const signedOut = new QueryClient();
    fill(signedOut);
    await handleAdminError(signedOut, new ApiError(401, "not_authenticated", "Gone"));
    expect(signedOut.getQueriesData({ queryKey: ADMIN_QUERY_KEY })).toEqual([]);
    expect(signedOut.getQueriesData({ queryKey: PLATFORM_QUERY_KEY })).toEqual([]);
    expect(signedOut.getQueriesData({ queryKey: ACCESS_QUERY_KEY })).toEqual([]);
    expect(signedOut.getQueriesData({ queryKey: ASSET_QUERY_KEY })).toEqual([]);
    expect(signedOut.getQueryData(SESSION_QUERY_KEY)).toBeNull();

    const revoked = new QueryClient();
    fill(revoked);
    await handleAdminError(revoked, new ApiError(403, "permission_denied", "Denied"));
    expect(revoked.getQueriesData({ queryKey: ADMIN_QUERY_KEY })).toEqual([]);
    expect(revoked.getQueryState(platformKey(id))?.isInvalidated).toBe(true);
    expect(revoked.getQueryData(SESSION_QUERY_KEY)).toEqual({ id }); // still signed in

    const prompted = new QueryClient();
    fill(prompted);
    await handleAdminError(prompted, stepUp());
    expect(prompted.getQueriesData({ queryKey: ADMIN_QUERY_KEY })).toHaveLength(2);
  });

  it("test_password_link_is_never_persisted", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(json(201, { user, password_link: link })));
    const client = new QueryClient();
    // The same options the admin mutation hook uses: no key, results dropped at once.
    const observer = new MutationObserver(client, { mutationFn: createUser, gcTime: 0 });
    const result = await observer.mutate({ username: "alice" });
    expect(result.password_link.url).toBe(link.url);
    observer.reset();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(client.getMutationCache().getAll()).toEqual([]);
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state.data))).not.toContain("canary-token");
    // The panel shows it as a read-only field, with the delivery warning, and nothing else keeps it.
    const panel = renderToStaticMarkup(<OneTimeLink link={link} onDone={() => undefined} />);
    expect(panel).toMatch(/<input readOnly=""[^>]*value="https:\/\/trilha\.example/);
    expect(panel).toContain("authorized internal channel");
    expect(panel).toContain("60 minutes");
    const sources = readdirSync(join(process.cwd(), "src/components/admin")).map((file) =>
      readFileSync(join(process.cwd(), "src/components/admin", file), "utf8"),
    );
    for (const source of sources) {
      expect(source).not.toMatch(/router\.(push|replace)\([^)]*link/i);
      expect(source).not.toMatch(/href=\{[^}]*\.url/);
      expect(source).not.toMatch(/console\./);
    }
  });

  it("test_admin_views_render_untrusted_text_cwe_79", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const markup = [
      renderToStaticMarkup(<UserTable users={[{ ...user, first_name: hostile, email: hostile }]} />),
      renderToStaticMarkup(<UserFacts user={{ ...user, username: hostile }} />),
      renderToStaticMarkup(<TeamTable teams={[{ ...team, name: hostile, code: hostile }]} />),
      renderToStaticMarkup(<RoleTable roles={[{ id, code: hostile, name: hostile, permissions: [] }]} />),
      renderToStaticMarkup(
        <AuditTable
          entries={[
            {
              event_id: id,
              occurred_at: "2026-10-22T10:00:00Z",
              actor: { type: "user", id, label: hostile },
              action: "rbac.admin_granted",
              outcome: "success",
              resource: { type: "rbac.platformaccess", id: hostile },
              source: "http",
              request_id: null,
              client_ip: null,
              changes: { name: { before: hostile, after: "<script>alert(1)</script>" } },
              metadata: {},
            },
          ]}
        />,
      ),
      renderToStaticMarkup(
        <QueryClientProvider client={new QueryClient()}>
          <StepUpProvider>
            <MemberTable
              teamId={other}
              members={[{ membership_id: id, user: { ...user, last_name: hostile }, roles: [{ id, code: "r", name: hostile }] }]}
              roles={[{ id: other, code: "x", name: hostile }]}
            />
          </StepUpProvider>
        </QueryClientProvider>,
      ),
    ];
    for (const html of markup) {
      expect(html).not.toContain("<img");
      expect(html).not.toContain("<script");
      expect(html).toContain("&lt;");
    }
    const sources = readdirSync(join(process.cwd(), "src/components/admin")).map((file) =>
      readFileSync(join(process.cwd(), "src/components/admin", file), "utf8"),
    );
    for (const source of sources) expect(source).not.toContain("innerHTML");
  });

  it("test_admin_nav_shown_only_from_platform_state", () => {
    expect(renderToStaticMarkup(<AdministrationLink platform={{ is_admin: true, position: null, reauthenticated_until: null }} />)).toContain('href="/admin"');
    for (const platform of [undefined, { is_admin: false, position: "engineer" as const, reauthenticated_until: null }]) {
      expect(renderToStaticMarkup(<AdministrationLink platform={platform} />)).toBe("");
    }
  });

  it("builds only allowlisted, UUID-addressed admin URLs", async () => {
    expect(() => uuidSegment("../../auth/logout")).toThrow();
    expect(() => uuidSegment(`${id}/../x`)).toThrow();
    expect(listPath("users", ["q", "position"] as const, { q: "a&is_admin=true", position: "none" }, 2)).toBe(
      "/api/v1/admin/users/?page=2&q=a%26is_admin%3Dtrue&position=none",
    );
    expect(() => listPath("users", [], {}, 0)).toThrow();
    const fetch = vi.fn().mockResolvedValue(json(200, { count: 0, next: null, previous: null, results: [] }));
    vi.stubGlobal("fetch", fetch);
    // @ts-expect-error: keys outside the allowlist never reach the URL
    await fetchUsers({ q: "x", ordering: "-username" }, 1);
    expect(fetch).toHaveBeenCalledWith("/api/v1/admin/users/?page=1&q=x", expect.objectContaining({ credentials: "same-origin" }));
  });

  it("maps errors to fixed text and converts local dates to offsets", () => {
    expect(adminErrorMessage(new ApiError(409, "conflict", "At least one other enabled Admin must remain."))).toBe(
      "At least one other enabled Admin must remain.",
    );
    expect(adminErrorMessage(new ApiError(403, "permission_denied", "internal"))).toBe("Administration access is no longer available.");
    expect(adminErrorMessage(stepUp())).toBe("Confirm your password to continue.");
    expect(adminErrorMessage(new ApiError(400, "validation_error", "x", { position: ["Choose analyst, engineer or null."] }))).toBe(
      "Choose analyst, engineer or null.",
    );
    expect(adminErrorMessage(new StepUpCancelled())).toContain("Nothing changed");
    expect(adminErrorMessage(new ApiError(500, "server_error", "Traceback"))).not.toContain("Traceback");
    expect(toIsoWithOffset("")).toBeUndefined();
    expect(toIsoWithOffset("2026-10-22T10:00")).toMatch(/Z$/);
    const form = new FormData();
    form.set("action", " rbac.admin_granted ");
    form.set("occurred_after", "2026-10-01T00:00");
    form.set("unexpected", "x");
    const filters = readAuditFilters(form);
    expect(filters.action).toBe("rbac.admin_granted");
    expect(filters.occurred_after).toMatch(/Z$/);
    expect(Object.keys(filters).sort()).toEqual(["action", "occurred_after"]);
  });
});
