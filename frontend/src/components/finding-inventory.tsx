"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { FindingTable } from "@/components/finding-table";
import { Button, Field, FilterBar, Input, Notice, Pager, Select } from "@/components/ui";
import { adminKey, fetchPlatformSelf, fetchTeams, platformKey } from "@/lib/admin";
import { accessTeamsKey, fetchAccessTeams, fieldErrors, teamsWith } from "@/lib/assets";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";
import {
  CATEGORIES,
  CATEGORY_LABELS,
  fetchFindings,
  FINDING_FILTER_KEYS,
  FINDING_STATUS_LABELS,
  FINDING_STATUSES,
  findingErrorMessage,
  findingListKey,
  handleFindingError,
  SEVERITIES,
  SEVERITY_LABELS,
  type FindingFilters,
} from "@/lib/findings";

function readFilters(form: FormData): FindingFilters {
  const filters: FindingFilters = {};
  for (const key of FINDING_FILTER_KEYS) {
    const value = String(form.get(key) ?? "").trim();
    if (value) filters[key] = value;
  }
  return filters;
}

export function FindingInventory() {
  const client = useQueryClient();
  const [filters, setFilters] = useState<FindingFilters>({});
  const [page, setPage] = useState(1);
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const userId = user?.id ?? "";
  const access = useQuery({
    queryKey: accessTeamsKey(userId),
    queryFn: ({ signal }) => fetchAccessTeams(signal),
    enabled: Boolean(user),
  });
  // Admins read every team's findings (oversight), so their team filter lists every team.
  const platform = useQuery({
    queryKey: platformKey(userId),
    queryFn: ({ signal }) => fetchPlatformSelf(signal),
    enabled: Boolean(user),
  });
  const isAdmin = platform.data?.is_admin === true;
  const allTeams = useQuery({
    queryKey: adminKey(userId, "teams", "finding-filter"),
    // shortcut: the first 100 teams; add a search box if a deployment ever has more.
    queryFn: ({ signal }) => fetchTeams({}, 1, signal, 100),
    enabled: Boolean(user) && isAdmin,
  });
  const findings = useQuery({
    queryKey: findingListKey(userId, filters, page),
    queryFn: ({ signal }) => fetchFindings(filters, page, signal),
    enabled: Boolean(user),
    staleTime: 0,
  });
  useEffect(() => {
    for (const error of [findings.error, access.error]) if (error) void handleFindingError(client, error);
  }, [findings.error, access.error, client]);

  if (!user) return null;
  const viewable = isAdmin ? (allTeams.data?.results ?? []) : teamsWith(access.data, "findings.view_finding");
  const errors = fieldErrors(findings.error);
  const filtered = Object.keys(filters).length > 0;

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters(readFilters(new FormData(event.currentTarget)));
    setPage(1);
  }

  return (
    <section className="flex flex-col gap-6" aria-label="Findings">
      <p className="m-0 text-small text-ink-muted">Report a finding from the page of the affected asset.</p>
      <FilterBar label="Filter findings" onSubmit={apply}>
        <Field label="Title" error={errors.q ? `Title: ${errors.q.join(" ")}` : undefined}>
          <Input name="q" maxLength={100} defaultValue={filters.q} className="w-44" />
        </Field>
        <Field label="Status">
          <Select name="status" defaultValue={filters.status ?? ""} className="w-32">
            <option value="">Any status</option>
            {FINDING_STATUSES.map((status) => (
              <option key={status} value={status}>
                {FINDING_STATUS_LABELS[status]}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Severity">
          <Select name="severity" defaultValue={filters.severity ?? ""} className="w-32">
            <option value="">Any severity</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABELS[severity]}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Category">
          <Select name="category" defaultValue={filters.category ?? ""} className="w-36">
            <option value="">Any category</option>
            {CATEGORIES.map((category) => (
              <option key={category} value={category}>
                {CATEGORY_LABELS[category]}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Team">
          <Select name="team" defaultValue={filters.team ?? ""} className="w-44">
            <option value="">{isAdmin ? "All teams" : "All my teams"}</option>
            {viewable.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Assignee">
          <Select name="assignee" defaultValue={filters.assignee ?? ""} className="w-32">
            <option value="">Anyone</option>
            <option value="me">Me</option>
            <option value="none">Unassigned</option>
          </Select>
        </Field>
        <Button type="submit">Apply filters</Button>
      </FilterBar>
      {Object.entries(errors)
        .filter(([field]) => field !== "q")
        .map(([field, messages]) => (
          <Notice key={field} tone="error">
            {field}: {messages.join(" ")}
          </Notice>
        ))}
      {findings.isPending && (
        <p role="status" className="m-0 text-ink-muted">
          Loading findings...
        </p>
      )}
      {findings.isError && Object.keys(errors).length === 0 && <Notice tone="error">{findingErrorMessage(findings.error)}</Notice>}
      {findings.data &&
        (findings.data.results.length === 0 ? (
          <p className="m-0">{filtered ? "No findings match these filters." : "No findings you can view yet."}</p>
        ) : (
          <>
            <FindingTable findings={findings.data.results} />
            <Pager
              label="findings"
              page={page}
              count={findings.data.count}
              hasPrevious={Boolean(findings.data.previous)}
              hasNext={Boolean(findings.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}
