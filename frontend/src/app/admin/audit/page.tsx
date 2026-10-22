import { AuditTrail } from "@/components/admin/audit";

export default function AdminAuditPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Audit trail</h1>
      <AuditTrail />
    </>
  );
}
