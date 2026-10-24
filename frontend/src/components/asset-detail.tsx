"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { AssetForm } from "@/components/asset-form";
import { AssetFacts } from "@/components/asset-table";
import { ReportFinding } from "@/components/finding-report";
import { ApiError } from "@/lib/api-client";
import {
  accessTeamsKey,
  ASSET_QUERY_KEY,
  assetErrorMessage,
  assetKey,
  can,
  fetchAccessTeams,
  fetchAsset,
  fieldErrors,
  handleAssetError,
  osCatalogQuery,
  restoreAsset,
  retireAsset,
  teamsWith,
  transferAsset,
  updateAsset,
  type Asset,
  type AssetInput,
} from "@/lib/assets";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

type Pending = { kind: "retire" } | { kind: "restore" } | { kind: "transfer"; teamId: string; label: string };

const BUTTON = "rounded border border-neutral-400 px-3 py-1 text-sm disabled:opacity-60";

export function AssetDetail({ id }: { id: string }) {
  const client = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [confirming, setConfirming] = useState<Pending | null>(null);
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const userId = user?.id ?? "";
  const asset = useQuery({
    queryKey: assetKey(userId, id),
    queryFn: ({ signal }) => fetchAsset(id, signal),
    enabled: Boolean(user),
    staleTime: 0,
  });
  const access = useQuery({
    queryKey: accessTeamsKey(userId),
    queryFn: ({ signal }) => fetchAccessTeams(signal),
    enabled: Boolean(user),
  });
  // Only editing needs the catalog; reading the asset never does (SPEC-0011 NFR-03).
  const catalog = useQuery({ ...osCatalogQuery, enabled: Boolean(user) && editing });
  // Every write sends the version shown on screen; the server rejects stale ones with 409.
  const mutation = useMutation({
    mutationFn: (run: () => Promise<Asset>) => run(),
    onSuccess: async (updated) => {
      client.setQueryData(assetKey(userId, id), updated);
      await client.invalidateQueries({ queryKey: [...ASSET_QUERY_KEY, userId, "list"] });
      setEditing(false);
      setConfirming(null);
    },
    onError: (error) => handleAssetError(client, error),
  });
  useEffect(() => {
    for (const error of [asset.error, catalog.error]) if (error) void handleAssetError(client, error);
  }, [asset.error, catalog.error, client]);

  if (!user) return null;
  if (asset.isPending) return <p role="status">Loading asset...</p>;
  if (asset.isError) return <p role="alert">{assetErrorMessage(asset.error)}</p>;
  const current = asset.data;
  const teamId = current.team.id;
  const canEdit = current.status === "active" && can(access.data, teamId, "assets.view_asset", "assets.change_asset");
  const canRetire = can(access.data, teamId, "assets.view_asset", "assets.retire_asset");
  const destinations =
    current.status === "active" && can(access.data, teamId, "assets.view_asset", "assets.transfer_asset")
      ? teamsWith(access.data, "assets.view_asset", "assets.transfer_asset").filter((team) => team.id !== teamId)
      : [];
  const conflict = mutation.error instanceof ApiError && mutation.error.status === 409;

  function confirm(pending: Pending) {
    mutation.reset();
    setConfirming(pending);
  }

  function run() {
    if (!confirming) return;
    if (confirming.kind === "retire") mutation.mutate(() => retireAsset(current));
    else if (confirming.kind === "restore") mutation.mutate(() => restoreAsset(current));
    else mutation.mutate(() => transferAsset(current, confirming.teamId));
  }

  return (
    <section className="space-y-4" aria-label="Asset">
      <h1 className="text-2xl font-semibold">{current.name}</h1>
      <AssetFacts asset={current} />
      {mutation.isError && (
        <div role="alert" className="space-y-2 text-sm text-red-700">
          <p>{assetErrorMessage(mutation.error)}</p>
          {conflict && (
            <button
              type="button"
              className={BUTTON}
              onClick={() => {
                mutation.reset();
                setConfirming(null);
                void asset.refetch();
              }}
            >
              Reload asset
            </button>
          )}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {canEdit && !editing && (
          <button type="button" className={BUTTON} onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
        {canRetire && current.status === "active" && (
          <button type="button" className={BUTTON} onClick={() => confirm({ kind: "retire" })}>
            Retire
          </button>
        )}
        {canRetire && current.status === "retired" && (
          <button type="button" className={BUTTON} onClick={() => confirm({ kind: "restore" })}>
            Restore
          </button>
        )}
      </div>
      <ReportFinding asset={current} access={access.data} />
      {destinations.length > 0 && (
        <form
          className="flex items-end gap-2 text-sm"
          onSubmit={(event) => {
            event.preventDefault();
            const teamId = String(new FormData(event.currentTarget).get("team_id") ?? "");
            const team = destinations.find((candidate) => candidate.id === teamId);
            if (team) confirm({ kind: "transfer", teamId, label: `${team.name} (${team.code})` });
          }}
        >
          <label className="flex flex-col gap-1">
            Transfer to team
            <select name="team_id" className="rounded border border-neutral-300 px-2 py-1">
              {destinations.map((team) => (
                <option key={team.id} value={team.id}>
                  {team.name} ({team.code})
                </option>
              ))}
            </select>
          </label>
          <button type="submit" className={BUTTON}>
            Transfer
          </button>
        </form>
      )}
      {confirming && (
        <div role="group" aria-label="Confirm action" className="space-y-2 rounded border border-amber-400 p-3 text-sm">
          <p>
            {confirming.kind === "retire" && "Retire this asset? It leaves the active inventory and becomes read-only."}
            {confirming.kind === "restore" && "Restore this asset to the active inventory?"}
            {confirming.kind === "transfer" &&
              `Transfer this asset to ${confirming.label}? Members of the current team may lose access to it.`}
          </p>
          <div className="flex gap-2">
            <button type="button" className={BUTTON} autoFocus disabled={mutation.isPending} onClick={run}>
              Confirm
            </button>
            <button type="button" className={BUTTON} onClick={() => setConfirming(null)}>
              Cancel
            </button>
          </div>
        </div>
      )}
      {editing && (
        <AssetForm
          asset={current}
          catalog={catalog}
          errors={fieldErrors(mutation.error)}
          pending={mutation.isPending}
          submitLabel="Save changes"
          onSubmit={(input: AssetInput) => mutation.mutate(() => updateAsset(current, input))}
        />
      )}
    </section>
  );
}
