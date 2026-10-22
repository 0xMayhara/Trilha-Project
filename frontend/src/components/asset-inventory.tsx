"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";

import { AssetTable } from "@/components/asset-table";
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

const INPUT = "rounded border border-neutral-300 px-2 py-1";

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
  const viewable = teamsWith(access.data, "assets.view_asset");
  const canRegister = teamsWith(access.data, "assets.add_asset", "assets.view_asset").length > 0;
  const errors = fieldErrors(assets.error);
  const filtered = Object.keys(filters).some((key) => key !== "status") || filters.status === "retired";

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters(readFilters(new FormData(event.currentTarget)));
    setPage(1);
  }

  return (
    <section className="space-y-4" aria-label="Asset inventory">
      {canRegister && (
        <Link href="/assets/new" className="inline-block rounded bg-neutral-900 px-3 py-2 text-sm text-white">
          Register asset
        </Link>
      )}
      <form role="search" aria-label="Filter assets" onSubmit={apply} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          Name or hostname
          <input name="q" maxLength={100} defaultValue={filters.q} className={INPUT} aria-invalid={Boolean(errors.q)} />
        </label>
        <label className="flex flex-col gap-1">
          Exact IP address
          <input name="ip" maxLength={45} defaultValue={filters.ip} className={INPUT} aria-invalid={Boolean(errors.ip)} />
        </label>
        <label className="flex flex-col gap-1">
          Status
          <select name="status" defaultValue={filters.status ?? "active"} className={INPUT}>
            <option value="active">Active</option>
            <option value="retired">Retired</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Team
          <select name="team" defaultValue={filters.team ?? ""} className={INPUT}>
            <option value="">All my teams</option>
            {viewable.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Kind
          <select name="kind" defaultValue={filters.kind ?? ""} className={INPUT}>
            <option value="">Any kind</option>
            {ASSET_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {KIND_LABELS[kind]}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" className="rounded border border-neutral-400 px-3 py-1">
          Apply filters
        </button>
      </form>
      {Object.entries(errors).map(([field, messages]) => (
        <p key={field} role="alert" className="text-sm text-red-700">
          {field === "ip" ? "IP address" : field === "q" ? "Search" : field}: {messages.join(" ")}
        </p>
      ))}
      {assets.isPending && <p role="status">Loading assets...</p>}
      {assets.isError && Object.keys(errors).length === 0 && <p role="alert">{assetErrorMessage(assets.error)}</p>}
      {assets.data &&
        (assets.data.results.length === 0 ? (
          <p>{filtered ? "No assets match these filters." : "No assets yet."}</p>
        ) : (
          <>
            <AssetTable assets={assets.data.results} />
            <nav className="flex gap-4 text-sm" aria-label="Asset pages">
              <button type="button" disabled={!assets.data.previous} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <span>
                Page {page} ({assets.data.count} assets)
              </span>
              <button type="button" disabled={!assets.data.next} onClick={() => setPage(page + 1)}>
                Next
              </button>
            </nav>
          </>
        ))}
    </section>
  );
}
