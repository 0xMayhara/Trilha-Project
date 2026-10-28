"use client";

import { useState, type FormEvent } from "react";

import { QueryState, useAdminQuery } from "@/components/admin/shared";
import { Badge, Button, Field, FilterBar, Input, Pager, Select, Sub, Table, TableBody, TableHead, Td, Tr } from "@/components/ui";
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
    <Table caption="Audit events">
      <TableHead columns={["When", "Actor", "Action", "Outcome", "Resource", "Source", "Details"]} />
      <TableBody>
        {entries.map((entry) => (
          <Tr key={entry.event_id}>
            <Td>{new Date(entry.occurred_at).toLocaleString()}</Td>
            <Td>
              {entry.actor.label || entry.actor.type}
              {entry.actor.id && <Sub className="font-mono">{entry.actor.id}</Sub>}
            </Td>
            <Td>{entry.action}</Td>
            <Td>
              <Badge tone={entry.outcome === "success" ? "ok" : "warn"}>{entry.outcome}</Badge>
            </Td>
            <Td>
              {entry.resource.type || "None"}
              {entry.resource.id && <Sub className="font-mono">{entry.resource.id}</Sub>}
            </Td>
            <Td>{entry.source}</Td>
            <Td>
              <pre className="m-0 max-w-90 overflow-x-auto font-mono text-[12px] leading-4 whitespace-pre-wrap">
                {JSON.stringify({ changes: entry.changes, metadata: entry.metadata }, null, 2)}
              </pre>
            </Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
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

  const text = (name: string, label: string, maxLength: number, width: string) => (
    <Field label={label}>
      <Input name={name} maxLength={maxLength} className={width} />
    </Field>
  );

  return (
    <section className="flex flex-col gap-6" aria-label="Audit trail">
      <p className="m-0 text-small">Exact-match filters. Without dates, the last 30 days are shown; a range covers at most 366 days.</p>
      <FilterBar label="Filter audit events" onSubmit={apply}>
        {text("action", "Action (e.g. rbac.admin_granted)", 100, "w-52")}
        {text("actor_id", "Actor ID", 36, "w-32")}
        {text("resource_type", "Resource type (e.g. accounts.user)", 100, "w-50")}
        {text("resource_id", "Resource ID", 64, "w-32")}
        <Field label="Outcome">
          <Select name="outcome" defaultValue="" className="w-26">
            <option value="">Any</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="denied">Denied</option>
          </Select>
        </Field>
        <Field label="Source">
          <Select name="source" defaultValue="" className="w-26">
            <option value="">Any</option>
            <option value="http">Web</option>
            <option value="command">Command</option>
            <option value="task">Task</option>
            <option value="sync">Sync</option>
          </Select>
        </Field>
        <Field label="From">
          <Input name="occurred_after" type="datetime-local" className="w-48" />
        </Field>
        <Field label="To">
          <Input name="occurred_before" type="datetime-local" className="w-48" />
        </Field>
        <Button type="submit">Search</Button>
      </FilterBar>
      <QueryState query={events} label="audit events" />
      {events.data &&
        (events.data.results.length === 0 ? (
          <p className="m-0">No audit events match.</p>
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
