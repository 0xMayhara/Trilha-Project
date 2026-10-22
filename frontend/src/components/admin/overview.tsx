"use client";

import Link from "next/link";

import { ADMIN_SECTIONS, QueryState, useAdminQuery } from "@/components/admin/shared";
import { fetchTeams, fetchUsers } from "@/lib/admin";

function Count({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="rounded border border-neutral-200 p-3">
      <dt className="text-sm text-neutral-600">{label}</dt>
      <dd className="text-2xl font-semibold">{value ?? "..."}</dd>
    </div>
  );
}

/** Counts come from the list endpoints' `count` (one-row pages); no summary API exists. */
export function AdminOverview() {
  const users = useAdminQuery(["overview", "users"], (signal) => fetchUsers({}, 1, signal, 1));
  const enabled = useAdminQuery(["overview", "enabled"], (signal) => fetchUsers({ is_active: "true" }, 1, signal, 1));
  const admins = useAdminQuery(["overview", "admins"], (signal) => fetchUsers({ is_admin: "true" }, 1, signal, 1));
  const teams = useAdminQuery(["overview", "teams"], (signal) => fetchTeams({}, 1, signal, 1));
  const inactive = useAdminQuery(["overview", "inactive"], (signal) => fetchTeams({ is_active: "false" }, 1, signal, 1));
  return (
    <section className="space-y-6" aria-label="Administration overview">
      <QueryState query={users} label="overview" />
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Count label="Users" value={users.data?.count} />
        <Count label="Enabled users" value={enabled.data?.count} />
        <Count label="Admins" value={admins.data?.count} />
        <Count label="Teams" value={teams.data?.count} />
        <Count label="Inactive teams" value={inactive.data?.count} />
      </dl>
      <ul className="list-disc pl-5 text-sm">
        {ADMIN_SECTIONS.filter((section) => section.href !== "/admin").map((section) => (
          <li key={section.href}>
            <Link href={section.href} className="underline">
              {section.label}
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
