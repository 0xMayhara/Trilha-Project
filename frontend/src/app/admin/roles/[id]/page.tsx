import { z } from "zod";

import { RoleDetailView } from "@/components/admin/roles";

export default async function AdminRolePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return z.uuid().safeParse(id).success ? <RoleDetailView id={id} /> : <p role="alert">Role not found.</p>;
}
