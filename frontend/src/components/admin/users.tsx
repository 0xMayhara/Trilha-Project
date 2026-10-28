"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import {
  Confirm,
  displayName,
  ErrorText,
  OneTimeLink,
  QueryState,
  useAdminMutation,
  useAdminQuery,
  useSessionUser,
} from "@/components/admin/shared";
import {
  Badge,
  Button,
  buttonClasses,
  EnabledBadge,
  Facts,
  Field,
  FilterBar,
  Form,
  Input,
  Notice,
  PageTitle,
  Pager,
  Panel,
  Select,
  Table,
  TableBody,
  TableHead,
  Td,
  Tr,
} from "@/components/ui";
import {
  createUser,
  disableUser,
  enableUser,
  fetchUser,
  fetchUsers,
  grantAdmin,
  issuePasswordLink,
  POSITION_LABELS,
  POSITIONS,
  revokeAdmin,
  setPosition,
  updateUser,
  USER_FILTER_KEYS,
  type Filters,
  type IssuedLink,
  type Position,
  type UserAdmin,
  type UserDetail,
} from "@/lib/admin";

type UserFilters = Filters<(typeof USER_FILTER_KEYS)[number]>;

function readFilters(form: FormData): UserFilters {
  const filters: UserFilters = {};
  for (const key of USER_FILTER_KEYS) {
    const value = String(form.get(key) ?? "").trim();
    if (value) filters[key] = value;
  }
  return filters;
}

export function positionLabel(value: Position | null) {
  return value ? POSITION_LABELS[value] : "None";
}

/** Every value is React text, never HTML (SEC-26). */
export function UserTable({ users }: { users: UserAdmin[] }) {
  return (
    <Table caption="Users">
      <TableHead columns={["User", "Email", "State", "Password", "Position", "Admin"]} />
      <TableBody>
        {users.map((user) => (
          <Tr key={user.id}>
            <Td>
              <Link href={`/admin/users/${user.id}`}>{displayName(user)}</Link>
            </Td>
            <Td>{user.email || "None"}</Td>
            <Td>
              <EnabledBadge enabled={user.is_active} />
            </Td>
            <Td>{user.password_set ? "Set" : user.is_active ? <Badge tone="warn">Pending setup</Badge> : "Pending setup"}</Td>
            <Td>{positionLabel(user.position)}</Td>
            <Td>{user.is_admin ? "Admin" : "No"}</Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
  );
}

export function UserList() {
  const [filters, setFilters] = useState<UserFilters>({});
  const [page, setPage] = useState(1);
  const users = useAdminQuery(["users", filters, page], (signal) => fetchUsers(filters, page, signal));

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters(readFilters(new FormData(event.currentTarget)));
    setPage(1);
  }

  return (
    <section className="flex flex-col gap-6" aria-label="Users">
      <div>
        <Link href="/admin/users/new" className={buttonClasses("primary")}>
          Create user
        </Link>
      </div>
      <FilterBar label="Filter users" onSubmit={apply}>
        <Field label="Name, username or email">
          <Input name="q" maxLength={100} className="w-56" />
        </Field>
        <Field label="State">
          <Select name="is_active" defaultValue="" className="w-28">
            <option value="">Any</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </Select>
        </Field>
        <Field label="Admin">
          <Select name="is_admin" defaultValue="" className="w-30">
            <option value="">Any</option>
            <option value="true">Admins</option>
            <option value="false">Not Admins</option>
          </Select>
        </Field>
        <Field label="Position">
          <Select name="position" defaultValue="" className="w-30">
            <option value="">Any</option>
            {POSITIONS.map((value) => (
              <option key={value} value={value}>
                {POSITION_LABELS[value]}
              </option>
            ))}
            <option value="none">None</option>
          </Select>
        </Field>
        <Button type="submit">Apply filters</Button>
      </FilterBar>
      <QueryState query={users} label="users" />
      {users.data &&
        (users.data.results.length === 0 ? (
          <p className="m-0">No users match.</p>
        ) : (
          <>
            <UserTable users={users.data.results} />
            <Pager
              label="users"
              page={page}
              count={users.data.count}
              hasPrevious={Boolean(users.data.previous)}
              hasNext={Boolean(users.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}

export function UserCreate() {
  const [link, setLink] = useState<{ user: UserAdmin; link: IssuedLink } | null>(null);
  const router = useRouter();
  const create = useAdminMutation(createUser, (result) =>
    setLink({ user: result.user, link: result.password_link }),
  );
  const { reset } = create;
  useEffect(() => {
    if (link) reset(); // the link now lives only in this component's state
  }, [link, reset]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const text = (key: string) => String(form.get(key) ?? "");
    create.mutate({
      username: text("username").trim().toLowerCase(),
      first_name: text("first_name"),
      last_name: text("last_name"),
      email: text("email").trim(),
    });
  }

  if (link) {
    return (
      <section className="flex flex-col gap-6" aria-label="User created">
        <Notice tone="success">Created {link.user.username}. The account has no password until its owner uses the link.</Notice>
        <OneTimeLink
          link={link.link}
          onDone={() => {
            const id = link.user.id;
            setLink(null);
            router.push(`/admin/users/${id}`);
          }}
        />
      </section>
    );
  }

  return (
    <>
      <Form onSubmit={submit} aria-label="Create user">
        <Field label="Username (lowercase letters, digits and . _ @ + -)">
          <Input name="username" required maxLength={150} pattern="[a-z0-9._@+\-]+" autoComplete="off" />
        </Field>
        <Field label="First name">
          <Input name="first_name" maxLength={150} />
        </Field>
        <Field label="Last name">
          <Input name="last_name" maxLength={150} />
        </Field>
        <Field label="Email">
          <Input name="email" type="email" maxLength={254} />
        </Field>
        <ErrorText error={create.error} />
        <Button type="submit" variant="primary" disabled={create.isPending} className="self-start">
          Create user
        </Button>
      </Form>
      <p className="m-0 text-small text-ink-muted">After creating, the one-time password link appears on the next screen.</p>
    </>
  );
}
type Action = "disable" | "enable" | "link" | "grant" | "revoke";

const ACTION_TEXT: Record<Action, (name: string) => string> = {
  disable: (name) => `Disable ${name}? Their password is removed, every session ends, and Admin authority is revoked.`,
  enable: (name) => `Enable ${name}? They must set a new password through a one-time link. Admin authority is not restored.`,
  link: (name) => `Issue a password link for ${name}? Using it replaces their password and ends their sessions.`,
  grant: (name) => `Grant platform Admin authority to ${name}?`,
  revoke: (name) => `Revoke platform Admin authority from ${name}?`,
};

const ACTION_CALL: Record<Action, (id: string) => Promise<unknown>> = {
  disable: disableUser,
  enable: enableUser,
  link: issuePasswordLink,
  grant: grantAdmin,
  revoke: revokeAdmin,
};

function linkOf(result: unknown): IssuedLink | null {
  if (result && typeof result === "object") {
    if ("password_link" in result) return (result as { password_link: IssuedLink }).password_link;
    if ("url" in result) return result as IssuedLink;
  }
  return null;
}

export function UserDetailView({ id }: { id: string }) {
  const me = useSessionUser();
  const user = useAdminQuery(["user", id], (signal) => fetchUser(id, signal));
  const [confirming, setConfirming] = useState<Action | null>(null);
  const [link, setLink] = useState<IssuedLink | null>(null);
  const action = useAdminMutation(
    ({ kind }: { kind: Action }) => ACTION_CALL[kind](id),
    (result) => {
      setConfirming(null);
      setLink(linkOf(result));
    },
  );
  const { reset } = action;
  useEffect(() => {
    if (link) reset();
  }, [link, reset]);

  if (user.isPending || user.isError) return <QueryState query={user} label="user" />;
  const current = user.data;
  const self = me?.id === current.id;

  return (
    <section className="flex flex-col gap-6" aria-label="User">
      <PageTitle>{displayName(current)}</PageTitle>
      <UserFacts user={current} />
      {link && <OneTimeLink link={link} onDone={() => setLink(null)} />}
      <ErrorText error={action.error} />
      <div className="flex flex-wrap items-center gap-2">
        {current.is_active && !self && <Button onClick={() => setConfirming("disable")}>Disable account</Button>}
        {!current.is_active && <Button onClick={() => setConfirming("enable")}>Enable account</Button>}
        {current.is_active && <Button onClick={() => setConfirming("link")}>Issue password link</Button>}
        {current.is_active && !current.is_admin && <Button onClick={() => setConfirming("grant")}>Grant Admin</Button>}
        {current.is_admin && !self && <Button onClick={() => setConfirming("revoke")}>Revoke Admin</Button>}
      </div>
      {confirming && (
        <Confirm
          message={ACTION_TEXT[confirming](current.username)}
          pending={action.isPending}
          onConfirm={() => action.mutate({ kind: confirming })}
          onCancel={() => setConfirming(null)}
        />
      )}
      <PositionForm user={current} />
      <ProfileForm user={current} />
      <Memberships user={current} />
    </section>
  );
}

export function UserFacts({ user }: { user: UserAdmin }) {
  return (
    <Facts
      items={[
        ["Username", user.username],
        ["Email", user.email || "None"],
        ["State", <EnabledBadge key="state" enabled={user.is_active} />],
        ["Password", user.password_set ? "Set" : "Pending setup"],
        ["Position", positionLabel(user.position)],
        ["Platform Admin", user.is_admin ? "Yes" : "No"],
        ["Joined", new Date(user.date_joined).toLocaleString()],
        ["Last login", user.last_login ? new Date(user.last_login).toLocaleString() : "Never"],
      ]}
    />
  );
}

function PositionForm({ user }: { user: UserDetail }) {
  const change = useAdminMutation((value: Position | null) => setPosition(user.id, value));
  return (
    <div className="flex flex-col gap-2">
      <form
        aria-label="Operational position"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          const value = String(new FormData(event.currentTarget).get("position") ?? "");
          change.mutate(value === "" ? null : (value as Position));
        }}
      >
        <Field label="Position (grants no permission by itself)">
          <Select name="position" defaultValue={user.position ?? ""} key={user.position ?? ""} className="w-64">
            <option value="">None</option>
            {POSITIONS.map((value) => (
              <option key={value} value={value}>
                {POSITION_LABELS[value]}
              </option>
            ))}
          </Select>
        </Field>
        <Button type="submit" disabled={change.isPending}>
          Save position
        </Button>
      </form>
      <ErrorText error={change.error} />
    </div>
  );
}

function ProfileForm({ user }: { user: UserDetail }) {
  const save = useAdminMutation((changes: { first_name: string; last_name: string; email: string }) =>
    updateUser(user.id, changes),
  );
  return (
    <Panel title="Profile">
      <Form
        aria-label="Profile"
        key={`${user.first_name}|${user.last_name}|${user.email}`}
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          save.mutate({
            first_name: String(form.get("first_name") ?? ""),
            last_name: String(form.get("last_name") ?? ""),
            email: String(form.get("email") ?? "").trim(),
          });
        }}
      >
        <Field label="First name">
          <Input name="first_name" maxLength={150} defaultValue={user.first_name} />
        </Field>
        <Field label="Last name">
          <Input name="last_name" maxLength={150} defaultValue={user.last_name} />
        </Field>
        <Field label="Email">
          <Input name="email" type="email" maxLength={254} defaultValue={user.email} />
        </Field>
        <ErrorText error={save.error} />
        {save.isSuccess && <Notice tone="success">Profile saved.</Notice>}
        <div>
          <Button type="submit" disabled={save.isPending}>
            Save profile
          </Button>
        </div>
      </Form>
    </Panel>
  );
}

function Memberships({ user }: { user: UserDetail }) {
  return (
    <Panel title="Team memberships">
      {user.memberships.length === 0 ? (
        <p className="m-0">No team memberships.</p>
      ) : (
        <ul className="m-0 list-disc pl-6 text-ui">
          {user.memberships.map((membership) => (
            <li key={membership.membership_id}>
              <Link href={`/admin/teams/${membership.team.id}`}>
                {membership.team.name} ({membership.team.code})
              </Link>
              {membership.team.is_active ? "" : " (inactive)"}
              {": "}
              {membership.roles.length > 0 ? membership.roles.map((role) => role.name).join(", ") : "no roles"}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
