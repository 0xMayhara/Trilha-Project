import { z } from "zod";

import { TeamDetailView } from "@/components/admin/teams";

export default async function AdminTeamPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return z.uuid().safeParse(id).success ? <TeamDetailView id={id} /> : <p role="alert">Team not found.</p>;
}
