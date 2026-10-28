"use client";

import Link from "next/link";
import { useState, type FormEvent } from "react";

import {
  Confirm,
  displayName,
  ErrorText,
  QueryState,
  useAdminMutation,
  useAdminQuery,
} from "@/components/admin/shared";
import {
  Button,
  EnabledBadge,
  Field,
  FilterBar,
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
  TeamStateBadge,
  Tr,
} from "@/components/ui";
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
    <Table caption="Teams">
      <TableHead columns={["Team", "Code", "State", "Members"]} />
      <TableBody>
        {teams.map((team) => (
          <Tr key={team.id}>
            <Td>
              <Link href={`/admin/teams/${team.id}`}>{team.name}</Link>
            </Td>
            <Td>{team.code}</Td>
            <Td>
              <TeamStateBadge active={team.is_active} />
            </Td>
            <Td>{team.member_count}</Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
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
    <section className="flex flex-col gap-6" aria-label="Teams">
      <form
        aria-label="Create team"
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          create.mutate({ code: String(form.get("code") ?? "").trim(), name: String(form.get("name") ?? "") });
        }}
      >
        <Field label="Code (lowercase, digits, _ or -)">
          <Input name="code" required maxLength={63} pattern="[a-z][a-z0-9_\-]*" className="w-50" />
        </Field>
        <Field label="Name">
          <Input name="name" required maxLength={150} className="w-64" />
        </Field>
        <Button type="submit" variant="primary" disabled={create.isPending}>
          Create team
        </Button>
      </form>
      {create.isSuccess && (
        <Notice tone="success">
          <p className="m-0">
            Team created inactive. <Link href={`/admin/teams/${create.data.id}`}>Open it to activate.</Link>
          </p>
        </Notice>
      )}
      <ErrorText error={create.error} />
      <FilterBar label="Filter teams" onSubmit={apply}>
        <Field label="Code or name">
          <Input name="q" maxLength={100} className="w-56" />
        </Field>
        <Field label="State">
          <Select name="is_active" defaultValue="" className="w-30">
            <option value="">Any</option>
            <option value="true">Active</option>
            <option value="false">Inactive</option>
          </Select>
        </Field>
        <Button type="submit">Apply filters</Button>
      </FilterBar>
      <QueryState query={teams} label="teams" />
      {teams.data &&
        (teams.data.results.length === 0 ? (
          <p className="m-0">No teams match.</p>
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
    <section className="flex flex-col gap-6" aria-label="Team">
      <PageTitle>
        {current.name} ({current.code})
      </PageTitle>
      <p className="m-0">
        <TeamStateBadge active={current.is_active} /> {current.member_count} members.
      </p>
      <form
        aria-label="Rename team"
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
      {current.is_active ? (
        <div className="flex flex-col items-start gap-2">
          <Button onClick={() => setConfirmDeactivate(true)}>Deactivate team</Button>
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
      <div>
        <Button onClick={() => setReviewing(true)}>Review activation</Button>
      </div>
    );
  }
  if (preview.isPending || preview.isError) return <QueryState query={preview} label="activation preview" />;
  const { revision, membership_count: members, role_assignment_count: grants } = preview.data;
  return (
    <Notice tone="confirm" aria-label="Activate team">
      <form
        className="flex flex-col gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          activate.mutate({ revision, code: String(new FormData(event.currentTarget).get("code") ?? "") });
        }}
      >
        <p className="m-0">
          Activating restores {members} memberships and {grants} role assignments. Disabled accounts stay denied.
        </p>
        <Field label={`Type the team code (${team.code}) to confirm`}>
          <Input name="code" required autoComplete="off" maxLength={63} className="w-60" />
        </Field>
        <ErrorText error={activate.error} />
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" disabled={activate.isPending}>
            Activate
          </Button>
          <Button onClick={() => setReviewing(false)}>Cancel</Button>
        </div>
      </form>
    </Notice>
  );
}

function MemberSection({ team }: { team: TeamAdmin }) {
  const [page, setPage] = useState(1);
  const members = useAdminQuery(["team", team.id, "members", page], (signal) => fetchMembers(team.id, page, signal));
  const roles = useAdminQuery(["roles", "all"], (signal) => fetchRoles({}, 1, signal, 100));
  return (
    <section aria-label="Members" className="flex flex-col gap-3">
      <SectionTitle>Members</SectionTitle>
      <AddMember teamId={team.id} />
      <QueryState query={members} label="members" />
      {members.data &&
        (members.data.results.length === 0 ? (
          <p className="m-0">No members yet.</p>
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
    <div className="flex flex-col gap-2">
      <form
        role="search"
        aria-label="Find a user to add"
        className="flex flex-wrap items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setTerm(String(new FormData(event.currentTarget).get("q") ?? "").trim());
        }}
      >
        <Field label="Find enabled user">
          <Input name="q" maxLength={100} className="w-60" />
        </Field>
        <Button type="submit">Search</Button>
      </form>
      {term && <QueryState query={found} label="users" />}
      {term && found.data && (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-ui">
          {found.data.results.length === 0 && <li>No enabled user matches.</li>}
          {found.data.results.map((candidate) => (
            <li key={candidate.id} className="flex items-center gap-2">
              <span>{displayName(candidate)}</span>
              <Button disabled={add.isPending} onClick={() => add.mutate(candidate.id)}>
                Add to team
              </Button>
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
    <div className="flex flex-col gap-3">
      <Table caption="Team members">
        <TableHead columns={["Member", "State", "Position", "Roles", "Actions"]} />
        <TableBody>
          {members.map((member) => {
            const held = new Set(member.roles.map((role) => role.id));
            const available = roles.filter((role) => !held.has(role.id));
            return (
              <Tr key={member.membership_id}>
                <Td>
                  <Link href={`/admin/users/${member.user.id}`}>{displayName(member.user)}</Link>
                </Td>
                <Td>
                  <EnabledBadge enabled={member.user.is_active} />
                </Td>
                <Td>{positionLabel(member.user.position)}</Td>
                <Td>
                  <ul className="m-0 flex list-none flex-col gap-1 p-0">
                    {member.roles.length === 0 && <li>None</li>}
                    {member.roles.map((role) => (
                      <li key={role.id} className="flex items-center gap-2">
                        {role.name}
                        <Button
                          variant="link"
                          aria-label={`Revoke ${role.name} from ${member.user.username}`}
                          onClick={() => setPending({ kind: "revoke", member, role })}
                        >
                          Revoke
                        </Button>
                      </li>
                    ))}
                  </ul>
                </Td>
                <Td>
                  <div className="flex flex-col items-start gap-1.5">
                    {available.length > 0 && (
                      <form
                        aria-label={`Assign a role to ${member.user.username}`}
                        className="flex flex-wrap items-center gap-2"
                        onSubmit={(event) => {
                          event.preventDefault();
                          const roleId = String(new FormData(event.currentTarget).get("role_id") ?? "");
                          if (roleId) assign.mutate({ membershipId: member.membership_id, roleId });
                        }}
                      >
                        <label className="sr-only" htmlFor={`role-${member.membership_id}`}>
                          Role
                        </label>
                        <Select id={`role-${member.membership_id}`} name="role_id" className="w-48">
                          {available.map((role) => (
                            <option key={role.id} value={role.id}>
                              {role.name} ({role.code})
                            </option>
                          ))}
                        </Select>
                        <Button type="submit" disabled={assign.isPending}>
                          Assign
                        </Button>
                      </form>
                    )}
                    <Button onClick={() => setPending({ kind: "remove", member })}>Remove from team</Button>
                  </div>
                </Td>
              </Tr>
            );
          })}
        </TableBody>
      </Table>
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
