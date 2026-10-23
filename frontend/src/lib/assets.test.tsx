import { readFileSync } from "node:fs";

import { QueryClient } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AssetForm } from "@/components/asset-form";
import { AssetFacts, AssetTable } from "@/components/asset-table";
import { accessQueryKey } from "@/lib/access";
import { ApiError } from "@/lib/api-client";
import {
  ASSET_QUERY_KEY,
  accessTeamsKey,
  assetErrorMessage,
  assetKey,
  assetListKey,
  assetListPath,
  assetPageSchema,
  assetPath,
  assetSchema,
  can,
  clearAssetQueries,
  fetchAssets,
  fieldErrors,
  handleAssetError,
  osCatalogPageSchema,
  osSummary,
  readAssetForm,
  teamsWith,
  type Asset,
  type AssetFilters,
} from "@/lib/assets";
import { SESSION_QUERY_KEY } from "@/lib/auth";

const id = "11111111-1111-4111-8111-111111111111";
const team = { id: "22222222-2222-4222-8222-222222222222", code: "alpha", name: "Alpha" };
const asset = {
  id,
  team,
  name: "Web 01",
  kind: "server",
  hostname: "web-01.example.com",
  ip_addresses: ["10.0.0.5"],
  operating_system: "Debian",
  os_product: null,
  os_version: "",
  os_label: null,
  environment: "production",
  criticality: null,
  status: "active",
  version: 1,
  created_at: "2026-10-22T10:00:00Z",
  updated_at: "2026-10-22T10:00:00Z",
};
const page = { count: 1, next: null, previous: null, results: [asset] };
afterEach(() => vi.unstubAllGlobals());

describe("asset client contracts", () => {
  it("test_asset_labels_render_as_text", () => {
    const hostile = assetSchema.parse({
      ...asset,
      name: '<img src=x onerror="alert(1)">',
      hostname: "<script>alert(1)</script>",
      operating_system: "<b>bold</b>",
      team: { ...team, name: "<svg onload=alert(1)>" },
    });
    const table = renderToStaticMarkup(<AssetTable assets={[hostile]} />);
    expect(table).toContain("&lt;img"); // the name; the detail page shows it in its heading
    for (const markup of [table, renderToStaticMarkup(<AssetFacts asset={hostile} />)]) {
      expect(markup).toContain("&lt;script&gt;");
      expect(markup).toContain("&lt;svg");
      expect(markup).not.toContain("<img");
      expect(markup).not.toContain("<script");
      expect(markup).not.toContain("<svg");
      expect(markup).not.toContain("<b>");
    }
    expect(renderToStaticMarkup(<AssetTable assets={[hostile]} />)).toContain(`href="/assets/${id}"`);
  });

  it("test_asset_queries_cleared_on_logout_and_401", async () => {
    const client = new QueryClient();
    client.setQueryData(SESSION_QUERY_KEY, { id: "user-1" });
    client.setQueryData(assetListKey("user-1", {}, 1), page);
    client.setQueryData(assetKey("user-1", id), asset);
    client.setQueryData(assetListKey("user-2", { q: "x" }, 2), page);
    client.setQueryData(accessTeamsKey("user-1"), { count: 0, next: null, previous: null, results: [] });
    client.setQueryData(accessQueryKey("user-1", 1), { count: 0, next: null, previous: null, results: [] });

    await handleAssetError(client, new ApiError(403, "permission_denied", "Forbidden"));
    expect(client.getQueriesData({ queryKey: ASSET_QUERY_KEY })).toHaveLength(3);
    expect(client.getQueryData(SESSION_QUERY_KEY)).toEqual({ id: "user-1" });

    await handleAssetError(client, new ApiError(401, "not_authenticated", "Ended"));
    expect(client.getQueriesData({ queryKey: ASSET_QUERY_KEY })).toEqual([]);
    expect(client.getQueryData(accessTeamsKey("user-1"))).toBeUndefined();
    expect(client.getQueryData(accessQueryKey("user-1", 1))).toBeUndefined();
    expect(client.getQueryData(SESSION_QUERY_KEY)).toBeNull();

    client.setQueryData(assetKey("user-3", id), asset);
    await clearAssetQueries(client); // the logout path
    expect(client.getQueriesData({ queryKey: ASSET_QUERY_KEY })).toEqual([]);
  });

  it("test_asset_list_query_includes_exact_ip_filter", async () => {
    const filters = { ip: "::ffff:10.0.0.5", q: "web 01", status: "active", user_id: "x", ordering: "name" };
    const path = assetListPath(filters as AssetFilters, 2);
    const params = new URL(path, "https://trilha.invalid").searchParams;
    expect([...params.keys()].sort()).toEqual(["ip", "page", "q", "status"]);
    expect(params.get("ip")).toBe("::ffff:10.0.0.5"); // sent as typed; the server canonicalizes
    expect(params.getAll("ip")).toHaveLength(1);
    expect(assetListPath({ ip: "" }, 1)).toBe("/api/v1/assets/?page=1");
    expect(() => assetListPath({}, 0)).toThrow();

    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(page)));
    vi.stubGlobal("fetch", fetch);
    await fetchAssets({ ip: "10.0.0.5" }, 1);
    expect(fetch).toHaveBeenCalledWith("/api/v1/assets/?page=1&ip=10.0.0.5", expect.objectContaining({ credentials: "same-origin" }));

    const invalid = new ApiError(400, "validation_error", "Invalid input.", { ip: ["Enter a valid IPv4 or IPv6 address."] });
    expect(fieldErrors(invalid)).toEqual({ ip: ["Enter a valid IPv4 or IPv6 address."] });
    expect(fieldErrors(new ApiError(403, "permission_denied", "x", { ip: ["y"] }))).toEqual({});
  });

  it("parses only the documented schema and addresses assets by UUID", () => {
    expect(assetPageSchema.parse(page).results[0]?.name).toBe("Web 01");
    for (const bad of [{ kind: "router" }, { status: "deleted" }, { criticality: "urgent" }, { version: 0 }, { id: "1" }]) {
      expect(() => assetSchema.parse({ ...asset, ...bad })).toThrow();
    }
    expect(assetPath(id, "retire/")).toBe(`/api/v1/assets/${id}/retire/`);
    for (const bad of ["../teams", "web-01", `${id}/../x`, ""]) {
      expect(() => assetPath(bad)).toThrow();
    }
  });

  it("derives advisory actions from same-team own-access codes", () => {
    const access = {
      count: 2,
      next: null,
      previous: null,
      results: [
        { membership_id: id, team, roles: [], permissions: ["assets.view_asset", "assets.change_asset"] as const },
        { membership_id: id, team: { ...team, id: "33333333-3333-4333-8333-333333333333", code: "beta" }, roles: [], permissions: ["assets.change_asset"] as const },
      ],
    };
    const typed = access as unknown as Parameters<typeof teamsWith>[0];
    expect(teamsWith(typed, "assets.view_asset").map((t) => t.code)).toEqual(["alpha"]);
    expect(can(typed, team.id, "assets.view_asset", "assets.change_asset")).toBe(true);
    // A grant in one team never lights up an action in another.
    expect(can(typed, "33333333-3333-4333-8333-333333333333", "assets.view_asset", "assets.change_asset")).toBe(false);
  });

  it("reads the native form and explains errors without server details", () => {
    const form = new FormData();
    form.set("name", "  Web 01 ");
    form.set("kind", "server");
    form.set("hostname", " web.example.com ");
    form.set("ip_addresses", "10.0.0.5\n10.0.0.6, 2001:db8::1\n\n");
    form.set("environment", "");
    expect(readAssetForm(form)).toEqual({
      name: "  Web 01 ",
      kind: "server",
      hostname: "web.example.com",
      ip_addresses: ["10.0.0.5", "10.0.0.6", "2001:db8::1"],
      os_product: null,
      os_version: "",
      environment: null,
      criticality: null,
    });
    const conflict = new ApiError(409, "conflict", "An active asset with this name already exists in the team.");
    expect(assetErrorMessage(conflict)).toContain("already exists");
    expect(assetErrorMessage(conflict)).toContain("Reload");
    expect(assetErrorMessage(new ApiError(500, "server_error", "Internal server error."))).toBe("Something went wrong. Try again.");
    expect(assetErrorMessage(new ApiError(403, "permission_denied", "internal detail"))).not.toContain("internal");
  });
});

const debian = { code: "debian", label: "Debian", family: "linux", family_label: "Linux" };
const catalog = [
  debian,
  { code: "fixture_os", label: "Fixture OS", family: "linux", family_label: "Linux" },
  { code: "windows_11", label: "Windows 11", family: "windows", family_label: "Microsoft Windows" },
];
const loaded = { data: catalog, isError: false, refetch: () => undefined };
const classified = assetSchema.parse({ ...asset, os_product: "debian", os_version: "12", os_label: "Debian" });

function form(state: Parameters<typeof AssetForm>[0]["catalog"], current?: Asset) {
  return renderToStaticMarkup(
    <AssetForm asset={current} catalog={state} errors={{}} pending={false} submitLabel="Save" onSubmit={() => undefined} />,
  );
}

describe("operating-system catalog (SPEC-0011)", () => {
  it("test_os_catalog_schema_rejects_malformed_or_partial_catalog_cwe_754", () => {
    const page = { count: 3, next: null, previous: null, results: catalog };
    expect(osCatalogPageSchema.parse(page).results).toEqual(catalog);
    for (const bad of [
      { ...page, next: "/api/v1/assets/os-catalog/?page=2" },
      { ...page, results: [{ ...debian, code: "Debian" }] },
      { ...page, results: [{ ...debian, label: "" }] },
      { ...page, results: [{ code: "debian", label: "Debian" }] },
    ]) {
      expect(osCatalogPageSchema.safeParse(bad).success).toBe(false);
    }
  });

  it("test_asset_form_requires_loaded_catalog_cwe_754", () => {
    const pending = form({ isError: false, refetch: () => undefined }, classified);
    expect(pending).toContain('role="status"');
    expect(pending).not.toContain("<form");
    const failed = form({ isError: true, refetch: () => undefined }, classified);
    expect(failed).toContain('role="alert"');
    expect(failed).toContain("Retry");
    expect(failed).not.toContain("<form");
  });

  it("test_asset_form_lists_catalog_labels_grouped_by_family", () => {
    const html = form(loaded);
    expect(html).toContain('<optgroup label="Linux"><option value="debian">Debian</option><option value="fixture_os">Fixture OS</option></optgroup>');
    expect(html).toContain('<optgroup label="Microsoft Windows"><option value="windows_11">Windows 11</option></optgroup>');
    expect(html).toContain('<option value="" selected="">Unspecified</option>');
    expect(html).toContain('name="os_version"');
    expect(html).not.toContain("operating_system");
    // Labels come from the backend: no catalog copy exists in the frontend sources.
    const sources = ["./assets.ts", "../components/asset-form.tsx", "../components/asset-table.tsx"]
      .map((path) => readFileSync(new URL(path, import.meta.url), "utf8"))
      .join("\n");
    for (const label of ["Ubuntu", "Windows Server", "Red Hat", "macOS", "CentOS"]) {
      expect(sources).not.toContain(label);
    }
  });

  it("test_asset_form_shows_saved_os_and_legacy_text", () => {
    const html = form(loaded, classified);
    expect(html).toContain('<option value="debian" selected="">Debian</option>');
    expect(html).toMatch(/name="os_version"[^>]*value="12"/);
    expect(html).toContain("Legacy OS text: &quot;Debian&quot; (kept as recorded)");
    expect(html).toMatch(/<select[^>]*name="os_product"[^>]*aria-describedby="os-legacy"/);
    expect(form(loaded, assetSchema.parse(asset))).toContain('<option value="" selected="">Not classified</option>');
  });

  it("test_form_preserves_unrecognized_current_code_cwe_754", () => {
    const newer = assetSchema.parse({ ...classified, os_product: "vmware_esxi", os_label: "VMware ESXi" });
    expect(form(loaded, newer)).toContain('<option value="vmware_esxi" selected="">vmware_esxi (unrecognized)</option>');
  });

  it("test_read_asset_form_maps_os_fields", () => {
    const data = new FormData();
    data.set("os_product", "debian");
    data.set("os_version", " 12 ");
    expect(readAssetForm(data)).toMatchObject({ os_product: "debian", os_version: " 12 " });
    data.set("os_product", "");
    const input = readAssetForm(data);
    expect(input.os_product).toBeNull();
    expect(input).not.toHaveProperty("operating_system");
  });

  it("test_os_summary_distinguishes_os_states", () => {
    const base = { os_product: null, os_version: "", os_label: null, operating_system: "" };
    expect(osSummary(base)).toBe("Unspecified");
    expect(osSummary({ ...base, operating_system: "CentOS 7" })).toBe("Not classified");
    expect(osSummary({ ...base, os_product: "centos", os_label: "CentOS", os_version: "7" })).toBe("CentOS 7");
    expect(osSummary({ ...base, os_product: "centos", os_label: "CentOS" })).toBe("CentOS");
    expect(osSummary({ ...base, os_product: "vmware_esxi" })).toBe("vmware_esxi");
  });

  it("test_os_text_renders_as_text_cwe_79", () => {
    const hostile = assetSchema.parse({
      ...asset,
      operating_system: '<img src=x onerror="alert(1)">',
      os_product: "debian",
      os_label: "<script>alert(1)</script>",
    });
    const hostileCatalog = { ...loaded, data: [{ ...debian, label: "<b>Debian</b>", family_label: "<i>Linux</i>" }] };
    for (const markup of [
      renderToStaticMarkup(<AssetTable assets={[hostile]} />),
      renderToStaticMarkup(<AssetFacts asset={hostile} />),
      form(hostileCatalog, hostile),
    ]) {
      expect(markup).not.toContain("<img");
      expect(markup).not.toContain("<script");
      expect(markup).not.toContain("<b>");
    }
    expect(renderToStaticMarkup(<AssetFacts asset={hostile} />)).toContain("&lt;img");
    expect(form(hostileCatalog, hostile)).toContain("&lt;b&gt;Debian&lt;/b&gt;");
  });
});
