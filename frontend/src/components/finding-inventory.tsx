"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";

import { FindingTable } from "@/components/finding-table";
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

const INPUT = "rounded border border-neutral-300 px-2 py-1";

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
    <section className="space-y-4" aria-label="Findings">
      <p className="text-sm text-neutral-600">Report a finding from the page of the affected asset.</p>
      <form role="search" aria-label="Filter findings" onSubmit={apply} className="flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          Title
          <input name="q" maxLength={100} defaultValue={filters.q} className={INPUT} aria-invalid={Boolean(errors.q)} />
        </label>
        <label className="flex flex-col gap-1">
          Status
          <select name="status" defaultValue={filters.status ?? ""} className={INPUT}>
            <option value="">Any status</option>
            {FINDING_STATUSES.map((status) => (
              <option key={status} value={status}>
                {FINDING_STATUS_LABELS[status]}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Severity
          <select name="severity" defaultValue={filters.severity ?? ""} className={INPUT}>
            <option value="">Any severity</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABELS[severity]}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Category
          <select name="category" defaultValue={filters.category ?? ""} className={INPUT}>
            <option value="">Any category</option>
            {CATEGORIES.map((category) => (
              <option key={category} value={category}>
                {CATEGORY_LABELS[category]}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Team
          <select name="team" defaultValue={filters.team ?? ""} className={INPUT}>
            <option value="">{isAdmin ? "All teams" : "All my teams"}</option>
            {viewable.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Assignee
          <select name="assignee" defaultValue={filters.assignee ?? ""} className={INPUT}>
            <option value="">Anyone</option>
            <option value="me">Me</option>
            <option value="none">Unassigned</option>
          </select>
        </label>
        <button type="submit" className="rounded border border-neutral-400 px-3 py-1">
          Apply filters
        </button>
      </form>
      {Object.entries(errors).map(([field, messages]) => (
        <p key={field} role="alert" className="text-sm text-red-700">
          {field === "q" ? "Title" : field}: {messages.join(" ")}
        </p>
      ))}
      {findings.isPending && <p role="status">Loading findings...</p>}
      {findings.isError && Object.keys(errors).length === 0 && <p role="alert">{findingErrorMessage(findings.error)}</p>}
      {findings.data &&
        (findings.data.results.length === 0 ? (
          <p>{filtered ? "No findings match these filters." : "No findings you can view yet."}</p>
        ) : (
          <>
            <FindingTable findings={findings.data.results} />
            <nav className="flex gap-4 text-sm" aria-label="Finding pages">
              <button type="button" disabled={!findings.data.previous} onClick={() => setPage(page - 1)}>
                Previous
              </button>
              <span>
                Page {page} ({findings.data.count} findings)
              </span>
              <button type="button" disabled={!findings.data.next} onClick={() => setPage(page + 1)}>
                Next
              </button>
            </nav>
          </>
        ))}
    </section>
  );
}
