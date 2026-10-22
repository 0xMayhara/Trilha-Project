import { PERMISSION_LABELS, type AccessPage } from "@/lib/access";

export function AccessEntries({ entries }: { entries: AccessPage["results"] }) {
  if (entries.length === 0) return <p>You have no memberships in active teams.</p>;
  return (
    <ul className="space-y-6">
      {entries.map((entry) => (
        <li key={entry.membership_id} className="rounded border p-4">
          <h2 className="font-semibold">{entry.team.name} ({entry.team.code})</h2>
          <p>Roles: {entry.roles.map((role) => role.name).join(", ") || "None"}</p>
          <p>Available actions: {entry.permissions.map((code) => PERMISSION_LABELS[code]).join(", ") || "None"}</p>
        </li>
      ))}
    </ul>
  );
}
