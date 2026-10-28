"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { AssetForm } from "@/components/asset-form";
import { AssetFacts } from "@/components/asset-table";
import { canReport, ReportFinding } from "@/components/finding-report";
import { Button, Field, Notice, PageTitle, Select } from "@/components/ui";
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
import { fetchFindings, findingListKey } from "@/lib/findings";

type Pending = { kind: "retire" } | { kind: "restore" } | { kind: "transfer"; teamId: string; label: string };

export function AssetDetail({ id }: { id: string }) {
  const client = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [reporting, setReporting] = useState(false);
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
  // A transfer confirms how many findings move with the asset (SPEC-0007 BR-16).
  const findings = useQuery({
    queryKey: findingListKey(userId, { asset: id }, 1),
    queryFn: ({ signal }) => fetchFindings({ asset: id }, 1, signal),
    enabled: Boolean(user) && confirming?.kind === "transfer",
    staleTime: 0,
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
  if (asset.isPending)
    return (
      <p role="status" className="m-0 text-ink-muted">
        Loading asset...
      </p>
    );
  if (asset.isError) return <Notice tone="error">{assetErrorMessage(asset.error)}</Notice>;
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
    else mutation.mutate(() => transferAsset(current, confirming.teamId, findings.data?.count));
  }

  return (
    <section className="flex flex-col gap-6" aria-label="Asset">
      <PageTitle>{current.name}</PageTitle>
      <AssetFacts asset={current} />
      {mutation.isError && (
        <Notice tone="error">
          <p className="m-0">{assetErrorMessage(mutation.error)}</p>
          {conflict && (
            <div>
              <Button
                onClick={() => {
                  mutation.reset();
                  setConfirming(null);
                  void asset.refetch();
                }}
              >
                Reload asset
              </Button>
            </div>
          )}
        </Notice>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {canEdit && !editing && <Button onClick={() => setEditing(true)}>Edit</Button>}
        {canRetire && current.status === "active" && <Button onClick={() => confirm({ kind: "retire" })}>Retire</Button>}
        {canRetire && current.status === "retired" && <Button onClick={() => confirm({ kind: "restore" })}>Restore</Button>}
        {canReport(current, access.data) && !reporting && <Button onClick={() => setReporting(true)}>Report finding</Button>}
      </div>
      {destinations.length > 0 && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const teamId = String(new FormData(event.currentTarget).get("team_id") ?? "");
            const team = destinations.find((candidate) => candidate.id === teamId);
            if (team) confirm({ kind: "transfer", teamId, label: `${team.name} (${team.code})` });
          }}
        >
          <Field label="Transfer to team">
            <Select name="team_id">
              {destinations.map((team) => (
                <option key={team.id} value={team.id}>
                  {team.name} ({team.code})
                </option>
              ))}
            </Select>
          </Field>
          <Button type="submit">Transfer</Button>
        </form>
      )}
      {confirming && (
        <Notice tone="confirm">
          <p className="m-0">
            {confirming.kind === "retire" && "Retire this asset? It leaves the active inventory and becomes read-only."}
            {confirming.kind === "restore" && "Restore this asset to the active inventory?"}
            {confirming.kind === "transfer" &&
              (findings.data?.count
                ? `Transfer this asset and its ${findings.data.count} finding(s) to ${confirming.label}? ` +
                  "The findings and their logbooks move with it; members of the current team lose access to them."
                : `Transfer this asset to ${confirming.label}? Members of the current team may lose access to it.`)}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              autoFocus
              disabled={mutation.isPending || (confirming.kind === "transfer" && findings.isPending)}
              onClick={run}
            >
              Confirm
            </Button>
            <Button onClick={() => setConfirming(null)}>Cancel</Button>
          </div>
        </Notice>
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
      {reporting && <ReportFinding asset={current} access={access.data} onCancel={() => setReporting(false)} />}
    </section>
  );
}
