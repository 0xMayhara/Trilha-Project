import { z } from "zod";

import { TeamDetailView } from "@/components/admin/teams";
import { Notice } from "@/components/ui";

export default async function AdminTeamPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return z.uuid().safeParse(id).success ? <TeamDetailView id={id} /> : <Notice tone="error">Team not found.</Notice>;
}
