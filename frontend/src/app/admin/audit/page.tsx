import { AuditTrail } from "@/components/admin/audit";
import { PageTitle } from "@/components/ui";

export default function AdminAuditPage() {
  return (
    <>
      <PageTitle className="sr-only">Audit trail</PageTitle>
      <AuditTrail />
    </>
  );
}
