import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FindingForm } from "@/components/finding-form";
import { canReport } from "@/components/finding-report";
import { FindingAsset, FindingFacts, FindingTable } from "@/components/finding-table";
import { LogbookEntries } from "@/components/logbook";
import { accessPageSchema, accessQueryKey, PERMISSION_CODES } from "@/lib/access";
import { ApiError } from "@/lib/api-client";
import { ASSET_QUERY_KEY, assetKey, assetSchema, transferAsset } from "@/lib/assets";
import { SESSION_QUERY_KEY } from "@/lib/auth";
import {
  entrySchema,
  fetchLogbook,
  findingErrorMessage,
  findingKey,
  findingListKey,
  findingListPath,
  findingPageSchema,
  findingPath,
  FINDINGS_QUERY_KEY,
  findingSchema,
  handleFindingError,
  logbookKey,
  logbookPageSchema,
  readFindingForm,
  redactedText,
  systemEventText,
  type Entry,
  type FindingFilters,
} from "@/lib/findings";

const id = "11111111-1111-4111-8111-111111111111";
const other = "33333333-3333-4333-8333-333333333333";
const team = { id: "22222222-2222-4222-8222-222222222222", code: "alpha", name: "Alpha" };
const user = { id: "44444444-4444-4444-8444-444444444444", username: "reporter", display_name: "Rita Reporter" };
const asset = {
  id: "55555555-5555-4555-8555-555555555555",
  name: "Web 01",
  status: "active",
  kind: "server",
  environment: "production",
  criticality: null,
  hardening_status: null,
  internet_exposure: "exposed",
  os_label: "Debian",
  os_version: "12",
};
const finding = {
  id,
  title: "Outdated TLS",
  severity: "high",
  category: "vulnerability",
  status: "open",
  created_at: "2026-10-24T10:00:00Z",
  asset,
  team,
  assignee: null,
  version: 1,
  description: "Seen on 443.",
  cve_ids: ["CVE-2024-3094"],
  updated_at: "2026-10-24T10:00:00Z",
  reported_by: user,
  capabilities: { edit: true },
};
const summary = { ...finding, asset: { id: asset.id, name: asset.name, status: asset.status } };
const entry = (fields: Partial<Entry>): Entry =>
  entrySchema.parse({
    id: "66666666-6666-4666-8666-666666666666",
    sequence: 1,
    kind: "system",
    event: "finding_created",
    actor: user,
    body: null,
    metadata: {},
    created_at: "2026-10-24T10:00:00Z",
    redacted: false,
    redacted_at: null,
    redaction_reason: null,
    ...fields,
  });
afterEach(() => vi.unstubAllGlobals());

describe("findings client contracts", () => {
  it("test_finding_and_logbook_text_render_as_text_cwe_79", () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const parsed = findingSchema.parse({
      ...finding,
      title: hostile,
      description: "<script>alert(1)</script>\nline 2",
      cve_ids: ["<b>CVE</b>"],
      team: { ...team, name: "<svg onload=alert(1)>" },
      asset: { ...asset, name: "<iframe src=javascript:alert(1)>" },
      reported_by: { ...user, display_name: "<u>Mallory</u>" },
    });
    const listed = findingPageSchema.parse({ count: 1, next: null, previous: null, results: [{ ...summary, title: hostile }] });
    const entries = [
      entry({ kind: "comment", event: null, body: "<script>steal()</script>", actor: { ...user, username: "<i>x</i>" } }),
      entry({ sequence: 2, event: "asset_transferred", metadata: { from_team: "<b>a</b>", to_team: "<b>b</b>" } }),
      entry({ sequence: 3, event: "finding_updated", metadata: { fields: ["<title>"], severity: { before: "<x>", after: "<y>" } } }),
    ];
    const markup = [
      renderToStaticMarkup(<FindingTable findings={listed.results} />),
      renderToStaticMarkup(<FindingFacts finding={parsed} />),
      renderToStaticMarkup(<FindingAsset finding={parsed} />),
      renderToStaticMarkup(<LogbookEntries entries={entries} />),
    ].join("\n");
    for (const tag of ["<img", "<script", "<svg", "<iframe", "<b>", "<u>", "<i>", "<title>", "<x>"]) {
      expect(markup).not.toContain(tag);
    }
    expect(markup).toContain("&lt;img src=x");
    expect(markup).toContain("&lt;script&gt;steal()&lt;/script&gt;");
    expect(markup).toContain(`href="/findings/${id}"`);
    expect(markup).toContain(`href="/assets/${asset.id}"`);
    expect(markup).toContain("whitespace-pre-wrap"); // multi-line text keeps its line breaks
  });

  it("clears finding cache on 401, 403 and 404", async () => {
    const client = new QueryClient();
    client.setQueryData(SESSION_QUERY_KEY, { id: "user-1" });
    client.setQueryData(findingKey("user-1", id), finding);
    client.setQueryData(logbookKey("user-1", id), { pages: [], pageParams: [] });
    client.setQueryData(findingKey("user-1", other), finding);
    client.setQueryData(findingListKey("user-1", {}, 1), { count: 0, next: null, previous: null, results: [] });
    client.setQueryData(assetKey("user-1", asset.id), assetSchema.parse({ ...asset, team, hostname: "", ip_addresses: [],
      operating_system: "", os_product: null, version: 1, created_at: "x", updated_at: "x" }));
    client.setQueryData(accessQueryKey("user-1", 1), { count: 0, next: null, previous: null, results: [] });

    for (const status of [403, 404]) {
      client.setQueryData(findingKey("user-1", id), finding);
      client.setQueryData(logbookKey("user-1", id), { pages: [], pageParams: [] });
      await handleFindingError(client, new ApiError(status, "denied", "Denied"), { userId: "user-1", id });
      expect(client.getQueryData(findingKey("user-1", id))).toBeUndefined();
      expect(client.getQueryData(logbookKey("user-1", id))).toBeUndefined();
      expect(client.getQueryData(findingKey("user-1", other))).toEqual(finding); // only that finding
      expect(client.getQueryData(SESSION_QUERY_KEY)).toEqual({ id: "user-1" });
    }
    await handleFindingError(client, new ApiError(500, "server_error", "Boom"), { userId: "user-1", id: other });
    expect(client.getQueryData(findingKey("user-1", other))).toEqual(finding);

    await handleFindingError(client, new ApiError(401, "not_authenticated", "Ended"));
    expect(client.getQueriesData({ queryKey: FINDINGS_QUERY_KEY })).toEqual([]);
    expect(client.getQueriesData({ queryKey: ASSET_QUERY_KEY })).toEqual([]);
    expect(client.getQueryData(accessQueryKey("user-1", 1))).toBeUndefined();
    expect(client.getQueryData(SESSION_QUERY_KEY)).toBeNull();
    expect(findingKey("first", id)).not.toEqual(findingKey("second", id)); // keyed by user
  });

  it("parses only the documented shapes", () => {
    expect(findingSchema.parse(finding).capabilities).toEqual({ edit: true });
    expect(() => findingSchema.parse({ ...finding, severity: "unknown" })).toThrow();
    expect(() => findingSchema.parse({ ...finding, id: "not-a-uuid" })).toThrow();
    expect(() => findingSchema.parse({ ...finding, status: "resolved" })).toThrow();
    expect(logbookPageSchema.parse({ results: [entry({})], has_more_before: false, last_sequence: 1 }).results).toHaveLength(1);
    expect(() => entrySchema.parse({ ...entry({}), kind: "html" })).toThrow();
    for (const code of ["findings.view_finding", "findings.add_finding", "findings.change_finding",
      "findings.comment_finding", "findings.work_finding", "findings.override_priority"] as const) {
      expect(PERMISSION_CODES).toContain(code);
    }
    const access = accessPageSchema.parse({
      count: 1, next: null, previous: null,
      results: [{ membership_id: id, team, roles: [], permissions: ["findings.view_finding"] }],
    });
    expect(access.results[0]?.permissions).toEqual(["findings.view_finding"]);
  });

  it("builds only allowlisted, UUID-addressed requests", async () => {
    const filters = { status: "open", q: "tls", team: team.id, priority: "p1", ordering: "-score" };
    const params = new URL(findingListPath(filters as FindingFilters, 2), "https://trilha.invalid").searchParams;
    expect([...params.keys()].sort()).toEqual(["page", "q", "status", "team"]);
    expect(() => findingListPath({}, 0)).toThrow();
    expect(findingPath(id, "logbook/")).toBe(`/api/v1/findings/${id}/logbook/`);
    expect(() => findingPath("../assets")).toThrow();
    expect(() => fetchLogbook(id, 0)).toThrow();
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ results: [], has_more_before: false, last_sequence: 0 })));
    vi.stubGlobal("fetch", fetch);
    await fetchLogbook(id, 7);
    expect(fetch).toHaveBeenCalledWith(`/api/v1/findings/${id}/logbook/?before=7`, expect.objectContaining({ credentials: "same-origin" }));
  });

  it("reads the native form and lists CVE IDs one per line", () => {
    const form = new FormData();
    form.set("title", "T");
    form.set("description", "a\nb");
    form.set("category", "other");
    form.set("severity", "low");
    form.set("cve_ids", "CVE-2024-3094\n cve-2021-44228, CVE-2023-1\n\n");
    expect(readFindingForm(form)).toEqual({
      title: "T",
      description: "a\nb",
      category: "other",
      severity: "low",
      cve_ids: ["CVE-2024-3094", "cve-2021-44228", "CVE-2023-1"],
    });
    const markup = renderToStaticMarkup(
      <FindingForm finding={findingSchema.parse(finding)} errors={{ title: ["Too long."] }} pending={false} submitLabel="Save" onSubmit={() => {}} />,
    );
    expect(markup).toContain("Too long.");
    // The title input is described by the element that holds its error.
    const titleError = /<input[^>]*aria-describedby="([^"]+)"[^>]*name="title"|<input[^>]*name="title"[^>]*aria-describedby="([^"]+)"/.exec(markup);
    const errorId = titleError?.[1] ?? titleError?.[2];
    expect(errorId).toBeTruthy();
    expect(markup).toMatch(new RegExp(`id="${errorId}"[^>]*>Too long.`));
    expect(markup).toContain("CVE-2024-3094");
    expect(markup).toContain("Never paste passwords, keys or personal data");
  });

  it("renders system events from fixed templates and redacted entries as placeholders", () => {
    expect(systemEventText(entry({ event: "finding_created" }))).toBe("Finding reported");
    expect(systemEventText(entry({ event: "finding_updated", metadata: { fields: ["severity", "title"], severity: { before: "high", after: "critical" } } })))
      .toBe("Finding edited: severity, title (severity high → critical)");
    expect(systemEventText(entry({ event: "asset_transferred", metadata: { from_team: "alpha", to_team: "beta" } })))
      .toBe("Asset moved from team alpha to team beta");
    expect(systemEventText(entry({ event: "work_started" }))).toBe("System event"); // later releases
    expect(systemEventText(entry({ event: "entry_redacted", metadata: { sequence: 4 } }))).toContain("entry 4");
    const redacted = entry({ kind: "comment", event: null, body: null, redacted: true, redacted_at: "2026-10-25T08:00:00Z", redaction_reason: "personal_data" });
    expect(redactedText(redacted)).toBe("Content removed by the platform owner on 2026-10-25 (reason: personal data)");
    const markup = renderToStaticMarkup(<LogbookEntries entries={[redacted]} />);
    expect(markup).toContain("Content removed by the platform owner");
    expect(renderToStaticMarkup(<LogbookEntries entries={[]} />)).toContain("No entries yet.");
  });

  it("offers reporting only for active assets with add, view and asset view in the asset's team", () => {
    const parsed = assetSchema.parse({ ...asset, team, hostname: "", ip_addresses: [], operating_system: "",
      os_product: null, version: 1, created_at: "x", updated_at: "x" });
    const page = (permissions: string[], teamId = team.id) =>
      accessPageSchema.parse({ count: 1, next: null, previous: null,
        results: [{ membership_id: id, team: { ...team, id: teamId }, roles: [], permissions }] });
    const all = ["assets.view_asset", "findings.view_finding", "findings.add_finding"];
    expect(canReport(parsed, page(all))).toBe(true);
    for (const missing of all) expect(canReport(parsed, page(all.filter((code) => code !== missing)))).toBe(false);
    expect(canReport(parsed, page(all, other))).toBe(false); // grants in another team
    expect(canReport({ ...parsed, status: "retired" }, page(all))).toBe(false);
    expect(canReport(parsed, undefined)).toBe(false);
  });

  it("confirms the finding count when transferring an asset", async () => {
    const parsed = assetSchema.parse({ ...asset, team, hostname: "", ip_addresses: [], operating_system: "",
      os_product: null, version: 3, created_at: "x", updated_at: "x" });
    const fetch = vi.fn().mockImplementation(async () => new Response(JSON.stringify(parsed)));
    vi.stubGlobal("fetch", fetch);
    await transferAsset(parsed, other, 2);
    await transferAsset(parsed, other);
    const bodies = fetch.mock.calls.map(([, init]) => JSON.parse(String((init as RequestInit).body)));
    expect(bodies).toEqual([
      { version: 3, team_id: other, finding_count: 2 },
      { version: 3, team_id: other }, // unchanged SPEC-0005 body when no count is known
    ]);
  });

  it("maps errors to fixed messages", () => {
    expect(findingErrorMessage(new ApiError(404, "not_found", "<b>x</b>"))).toBe("You no longer have access to this finding.");
    expect(findingErrorMessage(new ApiError(403, "permission_denied", "x"))).toBe("You no longer have access to this finding.");
    expect(findingErrorMessage(new ApiError(409, "conflict", "The finding changed. Reload and try again.")))
      .toBe("The finding changed. Reload and try again. Reload to see the current version.");
    expect(findingErrorMessage(new Error("internal detail"))).toBe("Something went wrong. Try again.");
  });
});
