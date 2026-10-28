"use client";

import Link from "next/link";

import { ADMIN_SECTIONS, QueryState, useAdminQuery } from "@/components/admin/shared";
import { Stat, StatGrid } from "@/components/ui";
import { fetchTeams, fetchUsers } from "@/lib/admin";

/** Counts come from the list endpoints' `count` (one-row pages); no summary API exists. */
export function AdminOverview() {
  const users = useAdminQuery(["overview", "users"], (signal) => fetchUsers({}, 1, signal, 1));
  const enabled = useAdminQuery(["overview", "enabled"], (signal) => fetchUsers({ is_active: "true" }, 1, signal, 1));
  const admins = useAdminQuery(["overview", "admins"], (signal) => fetchUsers({ is_admin: "true" }, 1, signal, 1));
  const teams = useAdminQuery(["overview", "teams"], (signal) => fetchTeams({}, 1, signal, 1));
  const inactive = useAdminQuery(["overview", "inactive"], (signal) => fetchTeams({ is_active: "false" }, 1, signal, 1));
  return (
    <section className="flex flex-col gap-6" aria-label="Administration overview">
      <QueryState query={users} label="overview" />
      <StatGrid>
        <Stat label="Users" value={users.data?.count ?? "..."} />
        <Stat label="Enabled users" value={enabled.data?.count ?? "..."} />
        <Stat label="Admins" value={admins.data?.count ?? "..."} />
        <Stat label="Teams" value={teams.data?.count ?? "..."} />
        <Stat label="Inactive teams" value={inactive.data?.count ?? "..."} />
      </StatGrid>
      <ul className="m-0 list-disc pl-6 text-ui">
        {ADMIN_SECTIONS.filter((section) => section.href !== "/admin").map((section) => (
          <li key={section.href}>
            <Link href={section.href}>{section.label}</Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
