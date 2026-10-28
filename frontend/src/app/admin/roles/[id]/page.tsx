import { z } from "zod";

import { RoleDetailView } from "@/components/admin/roles";
import { Notice } from "@/components/ui";

export default async function AdminRolePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return z.uuid().safeParse(id).success ? <RoleDetailView id={id} /> : <Notice tone="error">Role not found.</Notice>;
}
