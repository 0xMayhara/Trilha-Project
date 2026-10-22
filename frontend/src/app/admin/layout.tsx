import type { ReactNode } from "react";

import { AdminSectionNav, RequireAdmin } from "@/components/admin/shared";
import { RequireSession } from "@/components/require-session";

/** UX only: the API answers 403 to every non-Admin regardless of what the browser shows. */
export default function AdminLayout({ children }: { children: ReactNode }) {
  return (
    <RequireSession>
      <main className="mx-auto max-w-6xl space-y-6 p-6">
        <RequireAdmin>
          <AdminSectionNav />
          {children}
        </RequireAdmin>
      </main>
    </RequireSession>
  );
}
