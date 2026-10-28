import { z } from "zod";

import { AssetDetail } from "@/components/asset-detail";
import { RequireSession } from "@/components/require-session";
import { Notice, Page } from "@/components/ui";

export default async function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // A malformed ID never reaches the API client; the server answers 404 for it anyway.
  const valid = z.uuid().safeParse(id).success;
  return (
    <RequireSession>
      <Page>{valid ? <AssetDetail id={id} /> : <Notice tone="error">Asset not found.</Notice>}</Page>
    </RequireSession>
  );
}
