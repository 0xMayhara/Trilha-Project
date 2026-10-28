import { z } from "zod";

import { FindingDetail } from "@/components/finding-detail";
import { RequireSession } from "@/components/require-session";
import { Notice, Page } from "@/components/ui";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // A malformed ID never reaches the API client; the server answers 404 for it anyway.
  const valid = z.uuid().safeParse(id).success;
  return (
    <RequireSession>
      <Page>{valid ? <FindingDetail id={id} /> : <Notice tone="error">Finding not found.</Notice>}</Page>
    </RequireSession>
  );
}
