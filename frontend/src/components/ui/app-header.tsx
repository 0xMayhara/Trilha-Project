import type { ElementType } from "react";

import { cn } from "@/lib/utils";

export type NavKey = "admin" | "assets" | "findings" | "access" | "password";

const LINK =
  "text-on-brand underline focus-visible:outline-on-brand aria-[current=page]:rounded-sm aria-[current=page]:bg-brand-strong aria-[current=page]:px-2 aria-[current=page]:py-0.5 aria-[current=page]:font-semibold aria-[current=page]:no-underline";

/**
 * Brand band with the name as plain text (the project has no logo) and the main navigation.
 * Pass `LinkComponent={Link}` from next/link. Hiding Administration is convenience: the API decides.
 */
export function AppHeader({
  username,
  isAdmin = false,
  current,
  LinkComponent: A = "a",
  onLogout,
}: {
  username?: string | null;
  isAdmin?: boolean;
  current?: NavKey;
  LinkComponent?: ElementType;
  onLogout?: () => void;
}) {
  const aria = (key: NavKey) => (current === key ? ("page" as const) : undefined);
  return (
    <header className="flex min-h-12 items-center justify-between gap-4 border-b-[3px] border-brand-strong bg-brand px-8 text-on-brand">
      <A href="/" className="text-brand-name text-on-brand no-underline focus-visible:outline-on-brand">
        Trilha
      </A>
      <nav aria-label="Main" className="flex flex-wrap items-center gap-4 text-ui">
        {username ? (
          <>
            <span className="text-on-brand-muted">Signed in as {username}</span>
            {isAdmin ? (
              <A href="/admin" aria-current={aria("admin")} className={LINK}>
                Administration
              </A>
            ) : null}
            <A href="/assets" aria-current={aria("assets")} className={LINK}>
              Assets
            </A>
            <A href="/findings" aria-current={aria("findings")} className={LINK}>
              Findings
            </A>
            <A href="/account/access" aria-current={aria("access")} className={LINK}>
              Your access
            </A>
            <A href="/account/password" aria-current={aria("password")} className={LINK}>
              Change password
            </A>
            <button type="button" onClick={onLogout} className={cn(LINK, "cursor-pointer")}>
              Log out
            </button>
          </>
        ) : (
          <A href="/login" className={LINK}>
            Log in
          </A>
        )}
      </nav>
    </header>
  );
}

const ADMIN_TABS = [
  { key: "overview", href: "/admin", label: "Overview" },
  { key: "users", href: "/admin/users", label: "Users" },
  { key: "teams", href: "/admin/teams", label: "Teams" },
  { key: "roles", href: "/admin/roles", label: "Roles" },
  { key: "audit", href: "/admin/audit", label: "Audit trail" },
] as const;

/** Tabs under the header on every /admin page. */
export function AdminTabs({
  current,
  LinkComponent: A = "a",
}: {
  current: (typeof ADMIN_TABS)[number]["key"];
  LinkComponent?: ElementType;
}) {
  return (
    <nav aria-label="Administration">
      <ul className="m-0 flex list-none flex-wrap gap-1 border-b border-border-strong p-0">
        {ADMIN_TABS.map((tab) => (
          <li key={tab.key}>
            <A
              href={tab.href}
              aria-current={current === tab.key ? "page" : undefined}
              className="block rounded-t-sm border border-b-0 border-border bg-surface-sunken px-4 py-1.5 text-ui text-ink no-underline hover:bg-brand-tint aria-[current=page]:-mb-px aria-[current=page]:border-border-strong aria-[current=page]:bg-surface aria-[current=page]:pb-[7px] aria-[current=page]:font-semibold aria-[current=page]:text-brand"
            >
              {tab.label}
            </A>
          </li>
        ))}
      </ul>
    </nav>
  );
}
