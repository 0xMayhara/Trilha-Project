"use client";

import { useState, type FormEvent } from "react";

import { BUTTON, CELL, HEAD, INPUT, Pager, QueryState, useAdminQuery } from "@/components/admin/shared";
import { AUDIT_FILTER_KEYS, fetchAudit, type AuditEntry, type Filters } from "@/lib/admin";

type AuditFilters = Filters<(typeof AUDIT_FILTER_KEYS)[number]>;

/** A local `datetime-local` value as ISO 8601 with the browser's offset, as the API requires. */
export function toIsoWithOffset(local: string): string | undefined {
  if (!local) return undefined;
  const moment = new Date(local);
  return Number.isNaN(moment.getTime()) ? undefined : moment.toISOString();
}

export function readAuditFilters(form: FormData): AuditFilters {
  const filters: AuditFilters = {};
  for (const key of AUDIT_FILTER_KEYS) {
    const raw = String(form.get(key) ?? "").trim();
    const value = key.startsWith("occurred_") ? toIsoWithOffset(raw) : raw;
    if (value) filters[key] = value;
  }
  return filters;
}

/** Changes and metadata are stored data: shown as preformatted text, never interpreted (SEC-26). */
export function AuditTable({ entries }: { entries: AuditEntry[] }) {
  return (
    <table className="w-full border-collapse text-left text-sm">
      <caption className="sr-only">Audit events</caption>
      <thead>
        <tr>
          {["When", "Actor", "Action", "Outcome", "Resource", "Source", "Details"].map((heading) => (
            <th key={heading} scope="col" className={HEAD}>
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {entries.map((entry) => (
          <tr key={entry.event_id} className="border-b border-neutral-100 align-top">
            <td className={CELL}>{new Date(entry.occurred_at).toLocaleString()}</td>
            <td className={CELL}>
              {entry.actor.label || entry.actor.type}
              {entry.actor.id && <span className="block text-xs text-neutral-600">{entry.actor.id}</span>}
            </td>
            <td className={CELL}>{entry.action}</td>
            <td className={CELL}>{entry.outcome}</td>
            <td className={CELL}>
              {entry.resource.type || "None"}
              {entry.resource.id && <span className="block text-xs text-neutral-600">{entry.resource.id}</span>}
            </td>
            <td className={CELL}>{entry.source}</td>
            <td className={CELL}>
              <pre className="max-w-md overflow-x-auto whitespace-pre-wrap text-xs">
                {JSON.stringify({ changes: entry.changes, metadata: entry.metadata }, null, 2)}
              </pre>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function AuditTrail() {
  const [filters, setFilters] = useState<AuditFilters>({});
  const [page, setPage] = useState(1);
  const events = useAdminQuery(["audit", filters, page], (signal) => fetchAudit(filters, page, signal));

  function apply(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFilters(readAuditFilters(new FormData(event.currentTarget)));
    setPage(1);
  }

  const text = (name: string, label: string, maxLength: number) => (
    <label className="flex flex-col gap-1">
      {label}
      <input name={name} maxLength={maxLength} className={INPUT} />
    </label>
  );

  return (
    <section className="space-y-4" aria-label="Audit trail">
      <p className="text-sm">Exact-match filters. Without dates, the last 30 days are shown; a range covers at most 366 days.</p>
      <form role="search" aria-label="Filter audit events" onSubmit={apply} className="flex flex-wrap items-end gap-3 text-sm">
        {text("action", "Action (e.g. rbac.admin_granted)", 100)}
        {text("actor_id", "Actor ID", 36)}
        {text("resource_type", "Resource type (e.g. accounts.user)", 100)}
        {text("resource_id", "Resource ID", 64)}
        <label className="flex flex-col gap-1">
          Outcome
          <select name="outcome" defaultValue="" className={INPUT}>
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          Source
          <select name="source" defaultValue="" className={INPUT}>
            <option value="">Any</option>
            <option value="http">Web</option>
            <option value="command">Command</option>
            <option value="task">Task</option>
            <option value="sync">Sync</option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          From
          <input name="occurred_after" type="datetime-local" className={INPUT} />
        </label>
        <label className="flex flex-col gap-1">
          To
          <input name="occurred_before" type="datetime-local" className={INPUT} />
        </label>
        <button type="submit" className={BUTTON}>
          Search
        </button>
      </form>
      <QueryState query={events} label="audit events" />
      {events.data &&
        (events.data.results.length === 0 ? (
          <p>No audit events match.</p>
        ) : (
          <>
            <AuditTable entries={events.data.results} />
            <Pager
              label="events"
              page={page}
              count={events.data.count}
              hasPrevious={Boolean(events.data.previous)}
              hasNext={Boolean(events.data.next)}
              onPage={setPage}
            />
          </>
        ))}
    </section>
  );
}
