"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { AssetForm } from "@/components/asset-form";
import { Notice } from "@/components/ui";
import {
  accessTeamsKey,
  ASSET_QUERY_KEY,
  assetErrorMessage,
  createAsset,
  fetchAccessTeams,
  fieldErrors,
  handleAssetError,
  osCatalogQuery,
  teamsWith,
  type AssetInput,
} from "@/lib/assets";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

export function AssetRegistration() {
  const client = useQueryClient();
  const router = useRouter();
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const access = useQuery({
    queryKey: accessTeamsKey(user?.id ?? ""),
    queryFn: ({ signal }) => fetchAccessTeams(signal),
    enabled: Boolean(user),
  });
  const catalog = useQuery({ ...osCatalogQuery, enabled: Boolean(user) });
  const create = useMutation({
    mutationFn: ({ input, teamId }: { input: AssetInput; teamId: string }) => createAsset(teamId, input),
    onSuccess: async (asset) => {
      await client.invalidateQueries({ queryKey: ASSET_QUERY_KEY });
      router.push(`/assets/${asset.id}`);
    },
    onError: (error) => handleAssetError(client, error),
  });
  useEffect(() => {
    for (const error of [access.error, catalog.error]) if (error) void handleAssetError(client, error);
  }, [access.error, catalog.error, client]);

  if (!user) return null;
  if (access.isPending)
    return (
      <p role="status" className="m-0 text-ink-muted">
        Loading your teams...
      </p>
    );
  if (access.isError) return <Notice tone="error">{assetErrorMessage(access.error)}</Notice>;
  const teams = teamsWith(access.data, "assets.add_asset", "assets.view_asset");
  if (teams.length === 0) return <p className="m-0">You cannot register assets in any of your teams.</p>;
  return (
    <section className="flex flex-col gap-3" aria-label="Register asset">
      {create.isError && <Notice tone="error">{assetErrorMessage(create.error)}</Notice>}
      <AssetForm
        teams={teams}
        catalog={catalog}
        errors={fieldErrors(create.error)}
        pending={create.isPending}
        submitLabel="Register asset"
        onSubmit={(input, teamId) => create.mutate({ input, teamId })}
      />
    </section>
  );
}
