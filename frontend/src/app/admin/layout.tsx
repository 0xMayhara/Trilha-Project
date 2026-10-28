import type { ReactNode } from "react";

import { AdminSectionNav, RequireAdmin } from "@/components/admin/shared";
import { RequireSession } from "@/components/require-session";
import { Page } from "@/components/ui";

/** UX only: the API answers 403 to every non-Admin regardless of what the browser shows. */
export default function AdminLayout({ children }: { children: ReactNode }) {
  return (
    <RequireSession>
      <Page>
        <RequireAdmin>
          <AdminSectionNav />
          {children}
        </RequireAdmin>
      </Page>
    </RequireSession>
  );
}
