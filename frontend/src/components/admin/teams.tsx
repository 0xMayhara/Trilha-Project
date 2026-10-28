"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

import {
  BUTTON,
  CELL,
  Confirm,
  displayName,
  ErrorText,
  HEAD,
  INPUT,
  PRIMARY,
  QueryState,
  useAdminMutation,
  useAdminQuery,
} from "@/components/admin/shared";
import { Pager } from "@/components/ui";
import { positionLabel } from "@/components/admin/users";
import {
  activateTeam,
  addMember,
  assignRole,
  createTeam,
  deactivateTeam,
  fetchActivationPreview,
  fetchMembers,
  fetchRoles,
  fetchTeam,
  fetchTeams,
  fetchUsers,
  removeMember,
  renameTeam,
  revokeRole,
  TEAM_FILTER_KEYS,
  type Filters,
  type Member,
  type TeamAdmin,
} from "@/lib/admin";

type TeamFilters = Filters<(typeof TEAM_FILTER_KEYS)[number]>;

export function TeamTable({ teams }: { teams: TeamAdmin[] }) {
  return (
    <table className="w-full border-collapse text-left text-sm">
      <caption className="sr-only">Teams</caption>
      <thead>
        <tr>
          {["Team", "Code", "State", "Members"].map((heading) => (
            <th key={heading} scope="col" className={HEAD}>
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {teams.map((team) => (
          <tr key={team.id} className="border-b border-neutral-100">
            <td className={CELL}>
              <Link href={`/admin/teams/${team.id}`} className="underline">
                {team.name}
              </Link>
            </td>
            <td className={CELL}>{team.code}</td>
            <td className={CELL}>{team.is_active ? "Active" : "Inactive"}</td>
            <td className={CELL}>{team.member_count}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function TeamList() {
  const [filters, setFilters] = useState<TeamFilters>({});
  const [page, setPage] = useState(1);
  const teams = useAdminQuery(["teams", filters, page], (signal) => fetchTeams(filters, page, signal));
  const create = useAdminMutation(({ code, name }: { code: string; name: string }) => createTeam(code, name));

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const next: TeamFilters = {};
    for (const key of TEAM_FILTER_KEYS) {
      const value = String(form.get(key) ?? "").trim();
      if (value) next[key] = value;
    }
    setFilters(next);
    setPage(1);
  }

  return (
    <section className="space-y-6" aria-label="Teams">
      <form
        aria-label="Create team"
        className="flex flex-wrap items-end gap-3 text-sm"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          create.mutate({ code: String(form.get("code") ?? "").trim(), name: String(form.get("name") ?? "") });
        }}
      >
        <label className="flex flex-col gap-1">
          Code (lowercase, digits, _ or -)
          <input name="code" required maxLength={63} pattern="[a-z][a-z0-9_\-]*" className={INPUT} />
        </label>
        <label className="flex flex-col gap-1">
          Name
          <input name="name" required maxLength={150} className={INPUT} />
        </label>
        <button type="submit" className={PRIMARY} disabled={create.isPending}>
          Create team
        </button>
        {create.isSuccess && (
          <p role="status">
            Team created inactive. <Link href={`/admin/teams/${create.data.id}`} className="underline">Open it to activate.</Link>
          </p>
        )}
      </form>
      <ErrorText error={create.error} />
      <form role="search" aria-label="Filter teams" onSubmit={apply} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          Code or name
          <input name="q" maxLength={100} className={INPUT} />
        </label>
        <label className="flex flex-col gap-1">
          State
          <select name="is_active" defaultValue="" className={INPUT}>
            <option value="">Any</option>
            <option value="true">Active</option>
            <option value="false">Inactive</option>
          </select>
        </label>
        <button type="submit" className={BUTTON}>
          Apply filters
        </button>
      </form>
      <QueryState query={teams} label="teams" />
      {teams.data &&
        (teams.data.results.length === 0 ? (
          <p>No teams match.</p>
        ) : (
          <>
            <TeamTable teams={teams.data.results} />
            <Pager
              label="teams"
              page={page}
              count={teams.data.count}
              hasPrevious={Boolean(teams.data.previous)}
              hasNext={Boolean(teams.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}

export function TeamDetailView({ id }: { id: string }) {
  const team = useAdminQuery(["team", id], (signal) => fetchTeam(id, signal));
  const [confirmDeactivate, setConfirmDeactivate] = useState(false);
  const rename = useAdminMutation((name: string) => renameTeam(id, name));
  const deactivate = useAdminMutation(() => deactivateTeam(id), () => setConfirmDeactivate(false));

  if (team.isPending || team.isError) return <QueryState query={team} label="team" />;
  const current = team.data;
  return (
    <section className="space-y-6" aria-label="Team">
      <h1 className="text-2xl font-semibold">
        {current.name} ({current.code})
      </h1>
      <p className="text-sm">
        {current.is_active ? "Active" : "Inactive"}, {current.member_count} members.
      </p>
      <form
        aria-label="Rename team"
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
      {current.is_active ? (
        <div className="space-y-2">
          <button type="button" className={BUTTON} onClick={() => setConfirmDeactivate(true)}>
            Deactivate team
          </button>
          {confirmDeactivate && (
            <Confirm
              message={`Deactivate ${current.name}? Its members lose access to its data until it is activated again.`}
              pending={deactivate.isPending}
              onConfirm={() => deactivate.mutate(undefined)}
              onCancel={() => setConfirmDeactivate(false)}
            />
          )}
          <ErrorText error={deactivate.error} />
        </div>
      ) : (
        <Activation team={current} />
      )}
      <MemberSection team={current} />
    </section>
  );
}

function Activation({ team }: { team: TeamAdmin }) {
  const [reviewing, setReviewing] = useState(false);
  const preview = useAdminQuery(["team", team.id, "preview"], (signal) => fetchActivationPreview(team.id, signal), reviewing);
  const activate = useAdminMutation(
    ({ revision, code }: { revision: string; code: string }) => activateTeam(team.id, revision, code),
    () => setReviewing(false),
  );
  if (!reviewing) {
    return (
      <button type="button" className={BUTTON} onClick={() => setReviewing(true)}>
        Review activation
      </button>
    );
  }
  if (preview.isPending || preview.isError) return <QueryState query={preview} label="activation preview" />;
  const { revision, membership_count: members, role_assignment_count: grants } = preview.data;
  return (
    <form
      aria-label="Activate team"
      className="space-y-2 rounded border border-amber-400 p-3 text-sm"
      onSubmit={(event) => {
        event.preventDefault();
        activate.mutate({ revision, code: String(new FormData(event.currentTarget).get("code") ?? "") });
      }}
    >
      <p>
        Activating restores {members} memberships and {grants} role assignments. Disabled accounts stay denied.
      </p>
      <label className="flex flex-col gap-1">
        Type the team code ({team.code}) to confirm
        <input name="code" required autoComplete="off" maxLength={63} className={INPUT} />
      </label>
      <ErrorText error={activate.error} />
      <div className="flex gap-2">
        <button type="submit" className={PRIMARY} disabled={activate.isPending}>
          Activate
        </button>
        <button type="button" className={BUTTON} onClick={() => setReviewing(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function MemberSection({ team }: { team: TeamAdmin }) {
  const [page, setPage] = useState(1);
  const members = useAdminQuery(["team", team.id, "members", page], (signal) => fetchMembers(team.id, page, signal));
  const roles = useAdminQuery(["roles", "all"], (signal) => fetchRoles({}, 1, signal, 100));
  return (
    <section aria-label="Members" className="space-y-3 text-sm">
      <h2 className="text-lg font-semibold">Members</h2>
      <AddMember teamId={team.id} />
      <QueryState query={members} label="members" />
      {members.data &&
        (members.data.results.length === 0 ? (
          <p>No members yet.</p>
        ) : (
          <>
            <MemberTable teamId={team.id} members={members.data.results} roles={roles.data?.results ?? []} />
            <Pager
              label="members"
              page={page}
              count={members.data.count}
              hasPrevious={Boolean(members.data.previous)}
              hasNext={Boolean(members.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}

function AddMember({ teamId }: { teamId: string }) {
  const [term, setTerm] = useState("");
  const found = useAdminQuery(
    ["users", { q: term, is_active: "true" }, 1],
    (signal) => fetchUsers({ q: term, is_active: "true" }, 1, signal),
    term.length > 0,
  );
  const add = useAdminMutation((userId: string) => addMember(teamId, userId), () => setTerm(""));
  return (
    <div className="space-y-2">
      <form
        role="search"
        aria-label="Find a user to add"
        className="flex items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setTerm(String(new FormData(event.currentTarget).get("q") ?? "").trim());
        }}
      >
        <label className="flex flex-col gap-1">
          Find enabled user
          <input name="q" maxLength={100} className={INPUT} />
        </label>
        <button type="submit" className={BUTTON}>
          Search
        </button>
      </form>
      {term && <QueryState query={found} label="users" />}
      {term && found.data && (
        <ul className="space-y-1">
          {found.data.results.length === 0 && <li>No enabled user matches.</li>}
          {found.data.results.map((candidate) => (
            <li key={candidate.id} className="flex items-center gap-2">
              <span>{displayName(candidate)}</span>
              <button type="button" className={BUTTON} disabled={add.isPending} onClick={() => add.mutate(candidate.id)}>
                Add to team
              </button>
            </li>
          ))}
        </ul>
      )}
      <ErrorText error={add.error} />
    </div>
  );
}

type RoleOption = { id: string; code: string; name: string };
type Pending = { kind: "remove"; member: Member } | { kind: "revoke"; member: Member; role: RoleOption };

export function MemberTable({ teamId, members, roles }: { teamId: string; members: Member[]; roles: RoleOption[] }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const remove = useAdminMutation((userId: string) => removeMember(teamId, userId), () => setPending(null));
  const revoke = useAdminMutation(
    ({ membershipId, roleId }: { membershipId: string; roleId: string }) => revokeRole(membershipId, roleId),
    () => setPending(null),
  );
  const assign = useAdminMutation(({ membershipId, roleId }: { membershipId: string; roleId: string }) =>
    assignRole(membershipId, roleId),
  );
  return (
    <div className="space-y-2">
      <table className="w-full border-collapse text-left text-sm">
        <caption className="sr-only">Team members</caption>
        <thead>
          <tr>
            {["Member", "State", "Position", "Roles", "Actions"].map((heading) => (
              <th key={heading} scope="col" className={HEAD}>
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {members.map((member) => {
            const held = new Set(member.roles.map((role) => role.id));
            const available = roles.filter((role) => !held.has(role.id));
            return (
              <tr key={member.membership_id} className="border-b border-neutral-100 align-top">
                <td className={CELL}>
                  <Link href={`/admin/users/${member.user.id}`} className="underline">
                    {displayName(member.user)}
                  </Link>
                </td>
                <td className={CELL}>{member.user.is_active ? "Enabled" : "Disabled"}</td>
                <td className={CELL}>{positionLabel(member.user.position)}</td>
                <td className={CELL}>
                  <ul>
                    {member.roles.length === 0 && <li>None</li>}
                    {member.roles.map((role) => (
                      <li key={role.id} className="flex items-center gap-2">
                        {role.name}
                        <button
                          type="button"
                          className="underline"
                          aria-label={`Revoke ${role.name} from ${member.user.username}`}
                          onClick={() => setPending({ kind: "revoke", member, role })}
                        >
                          Revoke
                        </button>
                      </li>
                    ))}
                  </ul>
                </td>
                <td className={`${CELL} space-y-1`}>
                  {available.length > 0 && (
                    <form
                      aria-label={`Assign a role to ${member.user.username}`}
                      className="flex gap-1"
                      onSubmit={(event) => {
                        event.preventDefault();
                        const roleId = String(new FormData(event.currentTarget).get("role_id") ?? "");
                        if (roleId) assign.mutate({ membershipId: member.membership_id, roleId });
                      }}
                    >
                      <label className="sr-only" htmlFor={`role-${member.membership_id}`}>
                        Role
                      </label>
                      <select id={`role-${member.membership_id}`} name="role_id" className={INPUT}>
                        {available.map((role) => (
                          <option key={role.id} value={role.id}>
                            {role.name} ({role.code})
                          </option>
                        ))}
                      </select>
                      <button type="submit" className={BUTTON} disabled={assign.isPending}>
                        Assign
                      </button>
                    </form>
                  )}
                  <button type="button" className={BUTTON} onClick={() => setPending({ kind: "remove", member })}>
                    Remove from team
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {pending && (
        <Confirm
          message={
            pending.kind === "remove"
              ? `Remove ${pending.member.user.username} from this team? Their roles here are revoked first.`
              : `Revoke ${pending.role.name} from ${pending.member.user.username}?`
          }
          pending={remove.isPending || revoke.isPending}
          onConfirm={() =>
            pending.kind === "remove"
              ? remove.mutate(pending.member.user.id)
              : revoke.mutate({ membershipId: pending.member.membership_id, roleId: pending.role.id })
          }
          onCancel={() => setPending(null)}
        />
      )}
      <ErrorText error={remove.error ?? revoke.error ?? assign.error} />
    </div>
  );
}
