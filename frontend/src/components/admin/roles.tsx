"use client";

import Link from "next/link";
import { useState } from "react";

import {
  BUTTON,
  CELL,
  Confirm,
  ErrorText,
  HEAD,
  INPUT,
  Pager,
  PRIMARY,
  QueryState,
  useAdminMutation,
  useAdminQuery,
} from "@/components/admin/shared";
import { PERMISSION_CODES, PERMISSION_LABELS, type PermissionCode } from "@/lib/access";
import {
  createRole,
  fetchCatalog,
  fetchRole,
  fetchRoles,
  grantPermission,
  renameRole,
  revokePermission,
  type RoleAdmin,
} from "@/lib/admin";

export function RoleTable({ roles }: { roles: RoleAdmin[] }) {
  return (
    <table className="w-full border-collapse text-left text-sm">
      <caption className="sr-only">Roles</caption>
      <thead>
        <tr>
          {["Role", "Code", "Permissions"].map((heading) => (
            <th key={heading} scope="col" className={HEAD}>
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {roles.map((role) => (
          <tr key={role.id} className="border-b border-neutral-100">
            <td className={CELL}>
              <Link href={`/admin/roles/${role.id}`} className="underline">
                {role.name}
              </Link>
            </td>
            <td className={CELL}>{role.code}</td>
            <td className={CELL}>
              {role.permissions.length > 0 ? role.permissions.map((code) => PERMISSION_LABELS[code]).join(", ") : "None"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function RoleList() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const roles = useAdminQuery(["roles", q, page], (signal) => fetchRoles(q ? { q } : {}, page, signal));
  const create = useAdminMutation(({ code, name }: { code: string; name: string }) => createRole(code, name));
  return (
    <section className="space-y-6" aria-label="Roles">
      <p className="text-sm">
        Roles are reusable sets of permissions. A role grants its permissions only inside the team where it is assigned.
      </p>
      <form
        aria-label="Create role"
        className="flex flex-wrap items-end gap-3 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          create.mutate({ code: String(form.get("code") ?? "").trim(), name: String(form.get("name") ?? "") });
        }}
      >
        <label className="flex flex-col gap-1">
          Code
          <input name="code" required maxLength={63} pattern="[a-z][a-z0-9_\-]*" className={INPUT} />
        </label>
        <label className="flex flex-col gap-1">
          Name
          <input name="name" required maxLength={150} className={INPUT} />
        </label>
        <button type="submit" className={PRIMARY} disabled={create.isPending}>
          Create role
        </button>
        {create.isSuccess && <p role="status">Role created.</p>}
      </form>
      <ErrorText error={create.error} />
      <form
        role="search"
        aria-label="Filter roles"
        className="flex items-end gap-2 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          setQ(String(new FormData(event.currentTarget).get("q") ?? "").trim());
          setPage(1);
        }}
      >
        <label className="flex flex-col gap-1">
          Code or name
          <input name="q" maxLength={100} className={INPUT} />
        </label>
        <button type="submit" className={BUTTON}>
          Search
        </button>
      </form>
      <QueryState query={roles} label="roles" />
      {roles.data &&
        (roles.data.results.length === 0 ? (
          <p>No roles match.</p>
        ) : (
          <>
            <RoleTable roles={roles.data.results} />
            <Pager
              label="roles"
              page={page}
              count={roles.data.count}
              hasPrevious={Boolean(roles.data.previous)}
              hasNext={Boolean(roles.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}

export function RoleDetailView({ id }: { id: string }) {
  const role = useAdminQuery(["role", id], (signal) => fetchRole(id, signal));
  const catalog = useAdminQuery(["catalog"], (signal) => fetchCatalog(signal));
  const [revoking, setRevoking] = useState<PermissionCode | null>(null);
  const rename = useAdminMutation((name: string) => renameRole(id, name));
  const grant = useAdminMutation((code: PermissionCode) => grantPermission(id, code));
  const revoke = useAdminMutation((code: PermissionCode) => revokePermission(id, code), () => setRevoking(null));

  if (role.isPending || role.isError) return <QueryState query={role} label="role" />;
  const current = role.data;
  const offered = (catalog.data?.results ?? [])
    .map((entry) => entry.code)
    .filter((code) => PERMISSION_CODES.includes(code) && !current.permissions.includes(code));

  return (
    <section className="space-y-6" aria-label="Role">
      <h1 className="text-2xl font-semibold">
        {current.name} ({current.code})
      </h1>
      <form
        aria-label="Rename role"
        key={current.name}
        className="flex items-end gap-2 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          rename.mutate(String(new FormData(event.currentTarget).get("name") ?? ""));
        }}
      >
        <label className="flex flex-col gap-1">
          Name
          <input name="name" required maxLength={150} defaultValue={current.name} className={INPUT} />
        </label>
        <button type="submit" className={BUTTON} disabled={rename.isPending}>
          Rename
        </button>
      </form>
      <ErrorText error={rename.error} />
      <section aria-label="Permissions" className="space-y-2 text-sm">
        <h2 className="text-lg font-semibold">Permissions</h2>
        <p>Changes apply to every membership that holds this role, in every team.</p>
        {current.permissions.length === 0 ? (
          <p>No permissions.</p>
        ) : (
          <ul className="space-y-1">
            {current.permissions.map((code) => (
              <li key={code} className="flex items-center gap-2">
                <span>
                  {PERMISSION_LABELS[code]} <code className="text-neutral-600">{code}</code>
                </span>
                <button type="button" className="underline" onClick={() => setRevoking(code)}>
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
        {revoking && (
          <Confirm
            message={`Revoke "${PERMISSION_LABELS[revoking]}" from ${current.name}? Every member holding this role loses it.`}
            pending={revoke.isPending}
            onConfirm={() => revoke.mutate(revoking)}
            onCancel={() => setRevoking(null)}
          />
        )}
        <QueryState query={catalog} label="permission catalog" />
        {offered.length > 0 && (
          <form
            aria-label="Grant permission"
            className="flex items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              grant.mutate(String(new FormData(event.currentTarget).get("permission")) as PermissionCode);
            }}
          >
            <label className="flex flex-col gap-1">
              Permission
              <select name="permission" className={INPUT}>
                {offered.map((code) => (
                  <option key={code} value={code}>
                    {PERMISSION_LABELS[code]}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" className={BUTTON} disabled={grant.isPending}>
              Grant
            </button>
          </form>
        )}
        <ErrorText error={grant.error ?? revoke.error} />
      </section>
    </section>
  );
}
