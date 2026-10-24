import { z } from "zod";

import { FindingDetail } from "@/components/finding-detail";
import { RequireSession } from "@/components/require-session";

export default async function FindingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // A malformed ID never reaches the API client; the server answers 404 for it anyway.
  const valid = z.uuid().safeParse(id).success;
  return (
    <RequireSession>
      <main className="mx-auto max-w-3xl space-y-6 p-6">
        {valid ? <FindingDetail id={id} /> : <p role="alert">Finding not found.</p>}
      </main>
    </RequireSession>
  );
}
