"use client";

import Link from "next/link";
import { useState } from "react";

import { Confirm, ErrorText, QueryState, useAdminMutation, useAdminQuery } from "@/components/admin/shared";
import {
  Button,
  Field,
  Input,
  Notice,
  PageTitle,
  Pager,
  SectionTitle,
  Select,
  Table,
  TableBody,
  TableHead,
  Td,
  Tr,
} from "@/components/ui";
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
    <Table caption="Roles">
      <TableHead columns={["Role", "Code", "Permissions"]} />
      <TableBody>
        {roles.map((role) => (
          <Tr key={role.id}>
            <Td>
              <Link href={`/admin/roles/${role.id}`}>{role.name}</Link>
            </Td>
            <Td>{role.code}</Td>
            <Td>
              {role.permissions.length > 0 ? role.permissions.map((code) => PERMISSION_LABELS[code]).join(", ") : "None"}
            </Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
  );
}

export function RoleList() {
  const [q, setQ] = useState("");
  const [page, setPage] = useState(1);
  const roles = useAdminQuery(["roles", q, page], (signal) => fetchRoles(q ? { q } : {}, page, signal));
  const create = useAdminMutation(({ code, name }: { code: string; name: string }) => createRole(code, name));
  return (
    <section className="flex flex-col gap-6" aria-label="Roles">
      <p className="m-0 text-small">
        Roles are reusable sets of permissions. A role grants its permissions only inside the team where it is assigned.
      </p>
      <form
        aria-label="Create role"
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          create.mutate({ code: String(form.get("code") ?? "").trim(), name: String(form.get("name") ?? "") });
        }}
      >
        <Field label="Code">
          <Input name="code" required maxLength={63} pattern="[a-z][a-z0-9_\-]*" className="w-50" />
        </Field>
        <Field label="Name">
          <Input name="name" required maxLength={150} className="w-64" />
        </Field>
        <Button type="submit" variant="primary" disabled={create.isPending}>
          Create role
        </Button>
      </form>
      {create.isSuccess && <Notice tone="success">Role created.</Notice>}
      <ErrorText error={create.error} />
      <form
        role="search"
        aria-label="Filter roles"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setQ(String(new FormData(event.currentTarget).get("q") ?? "").trim());
          setPage(1);
        }}
      >
        <Field label="Code or name">
          <Input name="q" maxLength={100} className="w-56" />
        </Field>
        <Button type="submit">Search</Button>
      </form>
      <QueryState query={roles} label="roles" />
      {roles.data &&
        (roles.data.results.length === 0 ? (
          <p className="m-0">No roles match.</p>
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
    <section className="flex flex-col gap-6" aria-label="Role">
      <PageTitle>
        {current.name} ({current.code})
      </PageTitle>
      <form
        aria-label="Rename role"
        key={current.name}
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          rename.mutate(String(new FormData(event.currentTarget).get("name") ?? ""));
        }}
      >
        <Field label="Name">
          <Input name="name" required maxLength={150} defaultValue={current.name} className="w-64" />
        </Field>
        <Button type="submit" disabled={rename.isPending}>
          Rename
        </Button>
      </form>
      <ErrorText error={rename.error} />
      <section aria-label="Permissions" className="flex flex-col gap-3">
        <SectionTitle>Permissions</SectionTitle>
        <p className="m-0 text-small">Changes apply to every membership that holds this role, in every team.</p>
        {current.permissions.length === 0 ? (
          <p className="m-0">No permissions.</p>
        ) : (
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-ui">
            {current.permissions.map((code) => (
              <li key={code} className="flex items-center gap-2">
                {PERMISSION_LABELS[code]} <code className="font-mono text-[13px] text-ink-muted">{code}</code>
                <Button variant="link" onClick={() => setRevoking(code)}>
                  Revoke
                </Button>
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
            className="flex flex-wrap items-end gap-2"
            onSubmit={(event) => {
              event.preventDefault();
              grant.mutate(String(new FormData(event.currentTarget).get("permission")) as PermissionCode);
            }}
          >
            <Field label="Permission">
              <Select name="permission" className="w-64">
                {offered.map((code) => (
                  <option key={code} value={code}>
                    {PERMISSION_LABELS[code]}
                  </option>
                ))}
              </Select>
            </Field>
            <Button type="submit" disabled={grant.isPending}>
              Grant
            </Button>
          </form>
        )}
        <ErrorText error={grant.error ?? revoke.error} />
      </section>
    </section>
  );
}
