import { z } from "zod";

import { AssetDetail } from "@/components/asset-detail";
import { RequireSession } from "@/components/require-session";

export default async function AssetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // A malformed ID never reaches the API client; the server answers 404 for it anyway.
  const valid = z.uuid().safeParse(id).success;
  return (
    <RequireSession>
      <main className="mx-auto max-w-3xl space-y-6 p-6">
        {valid ? <AssetDetail id={id} /> : <p role="alert">Asset not found.</p>}
      </main>
    </RequireSession>
  );
}
