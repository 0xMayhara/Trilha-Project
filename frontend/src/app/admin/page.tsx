import { AdminOverview } from "@/components/admin/overview";
import { PageTitle } from "@/components/ui";

export default function AdminPage() {
  return (
    <>
      {/* The mock shows no visible title under the tabs; the h1 stays for screen readers (SPEC-0017 BR-07). */}
      <PageTitle className="sr-only">Administration</PageTitle>
      <AdminOverview />
    </>
  );
}
