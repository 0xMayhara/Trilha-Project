import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AccessEntries } from "@/components/access-entries";
import { ACCESS_QUERY_KEY, accessErrorMessage, accessPageSchema, accessQueryKey, clearOwnAccess, fetchOwnAccess, handleAccessError } from "@/lib/access";
import { ApiError } from "@/lib/api-client";
import { SESSION_QUERY_KEY } from "@/lib/auth";

const id = "11111111-1111-4111-8111-111111111111";
const entry = { membership_id: id, team: { id, code: "alpha", name: "Alpha" }, roles: [{ id, code: "reader", name: "Reader" }], permissions: ["teams.view_team"] };
const page = { count: 1, next: null, previous: null, results: [entry] };
afterEach(() => vi.unstubAllGlobals());

describe("own-access contracts", () => {
  it("groups grants by team without inventing global permissions", () => {
    const parsed = accessPageSchema.parse(page);
    expect(parsed.results[0]?.permissions).toEqual(["teams.view_team"]);
    expect(() => accessPageSchema.parse({ ...page, results: [{ ...entry, permissions: ["*"] }] })).toThrow();
    expect(accessQueryKey("first", 1)).not.toEqual(accessQueryKey("second", 1));
  });
  it("requests local numbered pages with credentials and abort support", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(page)));
    vi.stubGlobal("fetch", fetch);
    const signal = new AbortController().signal;
    expect(await fetchOwnAccess(2, signal)).toEqual(page);
    expect(fetch).toHaveBeenCalledWith("/api/v1/rbac/me/?page=2", expect.objectContaining({ credentials: "same-origin", signal }));
    expect(() => fetchOwnAccess(0)).toThrow();
    expect(() => fetchOwnAccess(Number.NaN)).toThrow();
  });
  it("clears all own-access pages on logout and 401", async () => {
    const client = new QueryClient();
    client.setQueryData(SESSION_QUERY_KEY, { id });
    client.setQueryData(accessQueryKey(id, 1), page);
    client.setQueryData(accessQueryKey("another", 2), page);
    await handleAccessError(client, new ApiError(401, "not_authenticated", "Denied"));
    expect(client.getQueriesData({ queryKey: ACCESS_QUERY_KEY })).toEqual([]);
    expect(client.getQueryData(SESSION_QUERY_KEY)).toBeNull();
    client.setQueryData(accessQueryKey(id, 1), page);
    await clearOwnAccess(client);
    expect(client.getQueriesData({ queryKey: ACCESS_QUERY_KEY })).toEqual([]);
  });
  it("preserves authentication for 403 and shows dependency failures safely", async () => {
    const client = new QueryClient();
    const user = { id };
    client.setQueryData(SESSION_QUERY_KEY, user);
    await handleAccessError(client, new ApiError(403, "permission_denied", "Forbidden"));
    expect(client.getQueryData(SESSION_QUERY_KEY)).toEqual(user);
    expect(accessErrorMessage(new ApiError(403, "permission_denied", "internal"))).toContain("Access denied");
    expect(accessErrorMessage(new ApiError(503, "service_unavailable", "internal"))).toContain("temporarily unavailable");
  });
  it("test_access_schema_accepts_asset_catalog_codes", () => {
    const codes = ["teams.view_team", "assets.view_asset", "assets.add_asset", "assets.change_asset", "assets.retire_asset", "assets.transfer_asset"];
    const parsed = accessPageSchema.parse({ ...page, results: [{ ...entry, permissions: codes }] });
    expect(parsed.results[0]?.permissions).toEqual(codes);
    for (const unknown of ["*", "assets.delete_asset", "assets.*"]) {
      expect(() => accessPageSchema.parse({ ...page, results: [{ ...entry, permissions: [unknown] }] })).toThrow();
    }
    const markup = renderToStaticMarkup(<AccessEntries entries={parsed.results} />);
    expect(markup).toContain("Register assets, Edit assets");
    expect(markup).toContain("Transfer assets");
  });
  it("test_access_labels_render_as_text", () => {
    const parsed = accessPageSchema.parse({ ...page, results: [{ ...entry,
      team: { ...entry.team, name: '<img src=x onerror="alert(1)">' },
      roles: [{ ...entry.roles[0], name: "<script>alert(1)</script>" }],
    }] });
    const markup = renderToStaticMarkup(<AccessEntries entries={parsed.results} />);
    expect(markup).toContain("&lt;img");
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
    expect(renderToStaticMarkup(<AccessEntries entries={[]} />)).toContain("no memberships");
  });
});
