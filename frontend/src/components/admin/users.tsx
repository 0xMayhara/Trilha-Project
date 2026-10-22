"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";

import {
  BUTTON,
  CELL,
  Confirm,
  displayName,
  ErrorText,
  HEAD,
  INPUT,
  OneTimeLink,
  Pager,
  PRIMARY,
  QueryState,
  useAdminMutation,
  useAdminQuery,
  useSessionUser,
} from "@/components/admin/shared";
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
    <table className="w-full border-collapse text-left text-sm">
      <caption className="sr-only">Users</caption>
      <thead>
        <tr>
          {["User", "Email", "State", "Password", "Position", "Admin"].map((heading) => (
            <th key={heading} scope="col" className={HEAD}>
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {users.map((user) => (
          <tr key={user.id} className="border-b border-neutral-100">
            <td className={CELL}>
              <Link href={`/admin/users/${user.id}`} className="underline">
                {displayName(user)}
              </Link>
            </td>
            <td className={CELL}>{user.email || "None"}</td>
            <td className={CELL}>{user.is_active ? "Enabled" : "Disabled"}</td>
            <td className={CELL}>{user.password_set ? "Set" : "Pending setup"}</td>
            <td className={CELL}>{positionLabel(user.position)}</td>
            <td className={CELL}>{user.is_admin ? "Admin" : "No"}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
    <section className="space-y-4" aria-label="Users">
      <Link href="/admin/users/new" className={`inline-block ${PRIMARY}`}>
        Create user
      </Link>
      <form role="search" aria-label="Filter users" onSubmit={apply} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          Name, username or email
          <input name="q" maxLength={100} className={INPUT} />
        </label>
        <label className="flex flex-col gap-1">
          State
          <select name="is_active" className={INPUT} defaultValue="">
            <option value="">Any</option>
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Admin
          <select name="is_admin" className={INPUT} defaultValue="">
            <option value="">Any</option>
            <option value="true">Admins</option>
            <option value="false">Not Admins</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Position
          <select name="position" className={INPUT} defaultValue="">
            <option value="">Any</option>
            {POSITIONS.map((value) => (
              <option key={value} value={value}>
                {POSITION_LABELS[value]}
              </option>
            ))}
            <option value="none">None</option>
          </select>
        </label>
        <button type="submit" className={BUTTON}>
          Apply filters
        </button>
      </form>
      <QueryState query={users} label="users" />
      {users.data &&
        (users.data.results.length === 0 ? (
          <p>No users match.</p>
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
      <section className="space-y-3" aria-label="User created">
        <p role="status">
          Created {link.user.username}. The account has no password until its owner uses the link.
        </p>
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
    <form onSubmit={submit} className="max-w-md space-y-3 text-sm" aria-label="Create user">
      <label className="flex flex-col gap-1">
        Username (lowercase letters, digits and . _ @ + -)
        <input name="username" required maxLength={150} pattern="[a-z0-9._@+\-]+" autoComplete="off" className={INPUT} />
      </label>
      <label className="flex flex-col gap-1">
        First name
        <input name="first_name" maxLength={150} className={INPUT} />
      </label>
      <label className="flex flex-col gap-1">
        Last name
        <input name="last_name" maxLength={150} className={INPUT} />
      </label>
      <label className="flex flex-col gap-1">
        Email
        <input name="email" type="email" maxLength={254} className={INPUT} />
      </label>
      <ErrorText error={create.error} />
      <button type="submit" disabled={create.isPending} className={PRIMARY}>
        Create user
      </button>
    </form>
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
    <section className="space-y-6" aria-label="User">
      <h1 className="text-2xl font-semibold">{displayName(current)}</h1>
      <UserFacts user={current} />
      {link && <OneTimeLink link={link} onDone={() => setLink(null)} />}
      <ErrorText error={action.error} />
      <div className="flex flex-wrap gap-2">
        {current.is_active && !self && (
          <button type="button" className={BUTTON} onClick={() => setConfirming("disable")}>
            Disable account
          </button>
        )}
        {!current.is_active && (
          <button type="button" className={BUTTON} onClick={() => setConfirming("enable")}>
            Enable account
          </button>
        )}
        {current.is_active && (
          <button type="button" className={BUTTON} onClick={() => setConfirming("link")}>
            Issue password link
          </button>
        )}
        {current.is_active && !current.is_admin && (
          <button type="button" className={BUTTON} onClick={() => setConfirming("grant")}>
            Grant Admin
          </button>
        )}
        {current.is_admin && !self && (
          <button type="button" className={BUTTON} onClick={() => setConfirming("revoke")}>
            Revoke Admin
          </button>
        )}
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
  const facts: [string, string][] = [
    ["Username", user.username],
    ["Email", user.email || "None"],
    ["State", user.is_active ? "Enabled" : "Disabled"],
    ["Password", user.password_set ? "Set" : "Pending setup"],
    ["Position", positionLabel(user.position)],
    ["Platform Admin", user.is_admin ? "Yes" : "No"],
    ["Joined", new Date(user.date_joined).toLocaleString()],
    ["Last login", user.last_login ? new Date(user.last_login).toLocaleString() : "Never"],
  ];
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {facts.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="font-semibold">{label}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function PositionForm({ user }: { user: UserDetail }) {
  const change = useAdminMutation((value: Position | null) => setPosition(user.id, value));
  return (
    <form
      aria-label="Operational position"
      className="flex items-end gap-2 text-sm"
      onSubmit={(event) => {
        event.preventDefault();
        const value = String(new FormData(event.currentTarget).get("position") ?? "");
        change.mutate(value === "" ? null : (value as Position));
      }}
    >
      <label className="flex flex-col gap-1">
        Position (grants no permission by itself)
        <select name="position" defaultValue={user.position ?? ""} key={user.position ?? ""} className={INPUT}>
          <option value="">None</option>
          {POSITIONS.map((value) => (
            <option key={value} value={value}>
              {POSITION_LABELS[value]}
            </option>
          ))}
        </select>
      </label>
      <button type="submit" className={BUTTON} disabled={change.isPending}>
        Save position
      </button>
      <ErrorText error={change.error} />
    </form>
  );
}

function ProfileForm({ user }: { user: UserDetail }) {
  const save = useAdminMutation((changes: { first_name: string; last_name: string; email: string }) =>
    updateUser(user.id, changes),
  );
  return (
    <form
      aria-label="Profile"
      key={`${user.first_name}|${user.last_name}|${user.email}`}
      className="max-w-md space-y-2 text-sm"
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
      <h2 className="text-lg font-semibold">Profile</h2>
      <label className="flex flex-col gap-1">
        First name
        <input name="first_name" maxLength={150} defaultValue={user.first_name} className={INPUT} />
      </label>
      <label className="flex flex-col gap-1">
        Last name
        <input name="last_name" maxLength={150} defaultValue={user.last_name} className={INPUT} />
      </label>
      <label className="flex flex-col gap-1">
        Email
        <input name="email" type="email" maxLength={254} defaultValue={user.email} className={INPUT} />
      </label>
      <ErrorText error={save.error} />
      {save.isSuccess && <p role="status">Profile saved.</p>}
      <button type="submit" className={BUTTON} disabled={save.isPending}>
        Save profile
      </button>
    </form>
  );
}

function Memberships({ user }: { user: UserDetail }) {
  return (
    <section aria-label="Team memberships" className="space-y-2 text-sm">
      <h2 className="text-lg font-semibold">Team memberships</h2>
      {user.memberships.length === 0 ? (
        <p>No team memberships.</p>
      ) : (
        <ul className="list-disc pl-5">
          {user.memberships.map((membership) => (
            <li key={membership.membership_id}>
              <Link href={`/admin/teams/${membership.team.id}`} className="underline">
                {membership.team.name} ({membership.team.code})
              </Link>
              {membership.team.is_active ? "" : " (inactive)"}
              {": "}
              {membership.roles.length > 0 ? membership.roles.map((role) => role.name).join(", ") : "no roles"}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
