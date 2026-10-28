"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";

import { AssetTable } from "@/components/asset-table";
import { buttonClasses, Button, Field, FilterBar, Input, Notice, Pager, Select } from "@/components/ui";
import { adminKey, fetchPlatformSelf, fetchTeams, platformKey } from "@/lib/admin";
import {
  accessTeamsKey,
  ASSET_KINDS,
  assetErrorMessage,
  assetListKey,
  fetchAccessTeams,
  fetchAssets,
  fieldErrors,
  FILTER_KEYS,
  handleAssetError,
  KIND_LABELS,
  teamsWith,
  type AssetFilters,
} from "@/lib/assets";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

function readFilters(form: FormData): AssetFilters {
  const filters: AssetFilters = {};
  for (const key of FILTER_KEYS) {
    const value = String(form.get(key) ?? "").trim();
    if (value) filters[key] = value;
  }
  return filters;
}

export function AssetInventory() {
  const client = useQueryClient();
  const [filters, setFilters] = useState<AssetFilters>({ status: "active" });
  const [page, setPage] = useState(1);
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const access = useQuery({
    queryKey: accessTeamsKey(user?.id ?? ""),
    queryFn: ({ signal }) => fetchAccessTeams(signal),
    enabled: Boolean(user),
  });
  // Admins read every team's assets (SPEC-0010 BR-12), so their team filter lists every team.
  const platform = useQuery({
    queryKey: platformKey(user?.id ?? ""),
    queryFn: ({ signal }) => fetchPlatformSelf(signal),
    enabled: Boolean(user),
  });
  const isAdmin = platform.data?.is_admin === true;
  const allTeams = useQuery({
    queryKey: adminKey(user?.id ?? "", "teams", "asset-filter"),
    // shortcut: the first 100 teams; add a search box if a deployment ever has more.
    queryFn: ({ signal }) => fetchTeams({}, 1, signal, 100),
    enabled: Boolean(user) && isAdmin,
  });
  const assets = useQuery({
    queryKey: assetListKey(user?.id ?? "", filters, page),
    queryFn: ({ signal }) => fetchAssets(filters, page, signal),
    enabled: Boolean(user),
    staleTime: 0,
  });
  useEffect(() => {
    if (assets.error) void handleAssetError(client, assets.error);
    if (access.error) void handleAssetError(client, access.error);
  }, [assets.error, access.error, client]);

  if (!user) return null;
  const viewable = isAdmin ? (allTeams.data?.results ?? []) : teamsWith(access.data, "assets.view_asset");
  const canRegister = teamsWith(access.data, "assets.add_asset", "assets.view_asset").length > 0;
  const errors = fieldErrors(assets.error);
  const filtered = Object.keys(filters).some((key) => key !== "status") || filters.status === "retired";

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters(readFilters(new FormData(event.currentTarget)));
    setPage(1);
  }

  const FIELD_LABELS: Record<string, string> = { q: "Search", ip: "IP address" };
  const fieldError = (key: string) => (errors[key] ? `${FIELD_LABELS[key]}: ${errors[key].join(" ")}` : undefined);
  const otherErrors = Object.entries(errors).filter(([field]) => !(field in FIELD_LABELS));

  return (
    <section className="flex flex-col gap-6" aria-label="Asset inventory">
      {canRegister && (
        <div>
          <Link href="/assets/new" className={buttonClasses("primary")}>
            Register asset
          </Link>
        </div>
      )}
      <FilterBar label="Filter assets" onSubmit={apply}>
        <Field label="Name or hostname" error={fieldError("q")}>
          <Input name="q" maxLength={100} defaultValue={filters.q} className="w-50" />
        </Field>
        <Field label="Exact IP address" error={fieldError("ip")}>
          <Input name="ip" maxLength={45} defaultValue={filters.ip} className="w-38" />
        </Field>
        <Field label="Status">
          <Select name="status" defaultValue={filters.status ?? "active"}>
            <option value="active">Active</option>
            <option value="retired">Retired</option>
          </Select>
        </Field>
        <Field label="Team">
          <Select name="team" defaultValue={filters.team ?? ""}>
            <option value="">{isAdmin ? "All teams" : "All my teams"}</option>
            {viewable.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Kind">
          <Select name="kind" defaultValue={filters.kind ?? ""}>
            <option value="">Any kind</option>
            {ASSET_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {KIND_LABELS[kind]}
              </option>
            ))}
          </Select>
        </Field>
        <Button type="submit">Apply filters</Button>
      </FilterBar>
      {otherErrors.map(([field, messages]) => (
        <Notice key={field} tone="error">
          {field}: {messages.join(" ")}
        </Notice>
      ))}
      {assets.isPending && (
        <p role="status" className="m-0 text-ink-muted">
          Loading assets...
        </p>
      )}
      {assets.isError && Object.keys(errors).length === 0 && <Notice tone="error">{assetErrorMessage(assets.error)}</Notice>}
      {assets.data &&
        (assets.data.results.length === 0 ? (
          <p className="m-0">{filtered ? "No assets match these filters." : "No assets yet."}</p>
        ) : (
          <>
            <AssetTable assets={assets.data.results} />
            <Pager
              label="assets"
              page={page}
              count={assets.data.count}
              hasPrevious={Boolean(assets.data.previous)}
              hasNext={Boolean(assets.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}
