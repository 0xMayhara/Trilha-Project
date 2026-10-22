import { z } from "zod";

import { UserDetailView } from "@/components/admin/users";

export default async function AdminUserPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // A malformed ID never reaches the API client; the server answers 404 for it anyway.
  return z.uuid().safeParse(id).success ? <UserDetailView id={id} /> : <p role="alert">User not found.</p>;
}
