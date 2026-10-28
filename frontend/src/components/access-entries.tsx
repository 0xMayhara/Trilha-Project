import { Panel } from "@/components/ui";
import { PERMISSION_LABELS, type AccessPage } from "@/lib/access";

export function AccessEntries({ entries }: { entries: AccessPage["results"] }) {
  if (entries.length === 0) return <p className="m-0">You have no memberships in active teams.</p>;
  return (
    <>
      {entries.map((entry) => (
        <Panel key={entry.membership_id} title={`${entry.team.name} (${entry.team.code})`}>
          <p className="m-0">
            <strong>Roles:</strong> {entry.roles.map((role) => role.name).join(", ") || "None"}
          </p>
          <p className="m-0">
            <strong>Available actions:</strong> {entry.permissions.map((code) => PERMISSION_LABELS[code]).join(", ") || "None"}
          </p>
        </Panel>
      ))}
    </>
  );
}
