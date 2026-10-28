"use client";

import { useMutation, useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState, type ReactNode } from "react";

import { StepUpProvider, useStepUp } from "@/components/admin/step-up";
import { AdminTabs, Button, Notice } from "@/components/ui";
import {
  ADMIN_QUERY_KEY,
  adminErrorMessage,
  adminKey,
  fetchPlatformSelf,
  handleAdminError,
  platformKey,
  type IssuedLink,
} from "@/lib/admin";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

export const BUTTON = "rounded border border-neutral-400 px-3 py-1 text-sm disabled:opacity-60";
export const PRIMARY = "rounded bg-neutral-900 px-3 py-1 text-sm text-white disabled:opacity-60";
export const INPUT = "rounded border border-neutral-300 px-2 py-1";
export const CELL = "px-2 py-1";
export const HEAD = "border-b border-neutral-300 px-2 py-1 font-semibold";

export function useSessionUser() {
  return useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser }).data;
}

export function usePlatform() {
  const client = useQueryClient();
  const user = useSessionUser();
  const platform = useQuery({
    queryKey: platformKey(user?.id ?? ""),
    queryFn: ({ signal }) => fetchPlatformSelf(signal),
    enabled: Boolean(user),
  });
  useEffect(() => {
    if (platform.error) void handleAdminError(client, platform.error);
  }, [platform.error, client]);
  return platform;
}

/** UX only: hides administration from non-Admins. Every route and use case re-checks on the server. */
export function RequireAdmin({ children }: { children: ReactNode }) {
  const platform = usePlatform();
  const user = useSessionUser();
  if (!user) return null;
  if (platform.isPending)
    return (
      <p role="status" className="m-0 text-ink-muted">
        Loading administration...
      </p>
    );
  if (platform.isError) return <Notice tone="error">{adminErrorMessage(platform.error)}</Notice>;
  if (!platform.data.is_admin) return <Notice tone="error">Administration is not available for your account.</Notice>;
  return <StepUpProvider>{children}</StepUpProvider>;
}

/** A query of admin data keyed by the signed-in user; errors clear caches as SEC-32 requires. */
export function useAdminQuery<T>(parts: readonly unknown[], fetcher: (signal: AbortSignal) => Promise<T>, enabled = true) {
  const client = useQueryClient();
  const user = useSessionUser();
  const query = useQuery({
    queryKey: adminKey(user?.id ?? "", ...parts) as QueryKey,
    queryFn: ({ signal }) => fetcher(signal),
    enabled: Boolean(user) && enabled,
    staleTime: 0,
    refetchOnWindowFocus: false,
  });
  useEffect(() => {
    if (query.error) void handleAdminError(client, query.error);
  }, [query.error, client]);
  return query;
}

/** An administrative change behind the step-up guard. Results are never kept by the mutation cache
 * (gcTime 0): a password link stays only in the component that shows it once. */
export function useAdminMutation<V, R>(fn: (vars: V) => Promise<R>, onSuccess?: (result: R) => void) {
  const client = useQueryClient();
  const guard = useStepUp();
  return useMutation({
    mutationFn: (vars: V) => guard(() => fn(vars)),
    gcTime: 0,
    onSuccess: async (result) => {
      await client.invalidateQueries({ queryKey: ADMIN_QUERY_KEY });
      onSuccess?.(result);
    },
    onError: (error) => handleAdminError(client, error),
  });
}

export function ErrorText({ error }: { error: unknown }) {
  return error ? <Notice tone="error">{adminErrorMessage(error)}</Notice> : null;
}

export function QueryState({ query, label }: { query: { isPending: boolean; isError: boolean; error: unknown }; label: string }) {
  if (query.isPending)
    return (
      <p role="status" className="m-0 text-ink-muted">
        Loading {label}...
      </p>
    );
  if (query.isError) return <ErrorText error={query.error} />;
  return null;
}

/** An explicit second step for destructive or security-sensitive actions. */
export function Confirm({
  message,
  pending,
  onConfirm,
  onCancel,
}: {
  message: string;
  pending: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Notice tone="confirm">
      <p className="m-0">{message}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" autoFocus disabled={pending} onClick={onConfirm}>
          Confirm
        </Button>
        <Button onClick={onCancel}>Cancel</Button>
      </div>
    </Notice>
  );
}
/** Shows a password link once. It is never cached, stored or put in a URL; Done discards it. */
export function OneTimeLink({ link, onDone }: { link: IssuedLink; onDone: () => void }) {
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const minutes = Math.round(link.expires_in_seconds / 60);
  return (
    <section aria-label="One-time password link" className="space-y-2 rounded border border-amber-500 p-3 text-sm">
      <p className="font-semibold">Password link (shown only once)</p>
      <p>
        Deliver this link only through an authorized internal channel. It works once and expires in {minutes} minutes.
      </p>
      <label className="flex flex-col gap-1">
        Link
        <input
          readOnly
          value={link.url}
          autoComplete="off"
          spellCheck={false}
          onFocus={(event) => event.currentTarget.select()}
          className={`${INPUT} font-mono`}
        />
      </label>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className={BUTTON}
          onClick={() => {
            navigator.clipboard.writeText(link.url).then(
              () => setCopy("copied"),
              () => setCopy("failed"),
            );
          }}
        >
          Copy link
        </button>
        <button type="button" className={PRIMARY} onClick={onDone}>
          Done
        </button>
        {copy === "copied" && <span role="status">Copied.</span>}
        {copy === "failed" && <span role="alert">Copy failed. Select the field and copy it manually.</span>}
      </div>
    </section>
  );
}

export const ADMIN_SECTIONS = [
  { href: "/admin", label: "Overview" },
  { href: "/admin/users", label: "Users" },
  { href: "/admin/teams", label: "Teams" },
  { href: "/admin/roles", label: "Roles" },
  { href: "/admin/audit", label: "Audit trail" },
] as const;

type AdminTab = Parameters<typeof AdminTabs>[0]["current"];

/** Nested routes (`/admin/users/new`, `/admin/users/[id]`) mark their parent tab. */
function adminTab(pathname: string): AdminTab {
  const section = pathname.split("/")[2];
  return section === "users" || section === "teams" || section === "roles" || section === "audit" ? section : "overview";
}

export function AdminSectionNav() {
  return <AdminTabs current={adminTab(usePathname())} LinkComponent={Link} />;
}
export function displayName(person: { username: string; first_name: string; last_name: string }) {
  const full = `${person.first_name} ${person.last_name}`.trim();
  return full ? `${full} (${person.username})` : person.username;
}
