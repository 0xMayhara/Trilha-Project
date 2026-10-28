"use client";

import { Fragment, useState, type FormEvent, type ReactNode } from "react";

import { QueryState, useAdminQuery } from "@/components/admin/shared";
import {
  AuditChangesTable,
  AuditMetadataFacts,
  AuditRawJson,
  auditSummary,
  Badge,
  Button,
  DetailRow,
  Facts,
  Field,
  FilterBar,
  Input,
  Pager,
  Select,
  Sub,
  Table,
  TableBody,
  TableHead,
  Td,
  Tr,
  type AuditChanges,
} from "@/components/ui";
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

/** API `changes` are `{field: {before, after}}`; any other shape is left to the raw JSON and never throws (SPEC-0031 BR-03). */
export function toAuditChanges(changes: Record<string, unknown>): AuditChanges {
  return Object.fromEntries(
    Object.entries(changes).flatMap(([field, value]) => {
      if (!value || typeof value !== "object" || Array.isArray(value) || !("before" in value || "after" in value)) return [];
      const { before = null, after = null } = value as { before?: unknown; after?: unknown };
      return [[field, [before, after] as const]];
    }),
  );
}

const when = (entry: AuditEntry) => new Date(entry.occurred_at).toLocaleString();
const Mono = ({ children, muted = false }: { children: ReactNode; muted?: boolean }) => (
  <code className={`font-mono text-code ${muted ? "text-ink-muted" : ""}`}>{children}</code>
);
const H3 = ({ children }: { children: ReactNode }) => <h3 className="m-0 text-label text-ink-muted">{children}</h3>;
const withId = (name: string, id: string | null) => (id ? <>{name} <Mono muted>{id}</Mono></> : name);

/** The open row's detail. Stored data, shown as text only (SEC-26; SPEC-0031 SEC-01, SEC-02). */
export function AuditDetail({ entry }: { entry: AuditEntry }) {
  const { actor, resource } = entry;
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,4fr)]">
      <div className="flex flex-col gap-2">
        <H3>Changes</H3>
        <AuditChangesTable changes={toAuditChanges(entry.changes)} />
      </div>
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <H3>Event</H3>
          <Facts
            items={[
              ["Event ID", <Mono key="e">{entry.event_id}</Mono>],
              ["Actor", withId(actor.label || actor.type, actor.id)],
              ["Resource", resource.type ? withId(resource.type, resource.id) : "None"],
              ["Source", entry.source],
              ["Request", entry.request_id ? <Mono key="r">{entry.request_id}</Mono> : "None"],
              ["Client IP", entry.client_ip ? <Mono key="c">{entry.client_ip}</Mono> : "None"],
            ]}
          />
        </div>
        <div className="flex flex-col gap-2">
          <H3>Metadata</H3>
          <AuditMetadataFacts metadata={entry.metadata} />
        </div>
        <AuditRawJson value={{ changes: entry.changes, metadata: entry.metadata }} />
      </div>
    </div>
  );
}

/** One line per event with a text summary; one row open at a time (SPEC-0031 BR-02, BR-05). */
export function AuditTable({ entries }: { entries: AuditEntry[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Table caption="Audit events">
      <TableHead columns={["When", "Actor", "Action", "Outcome", "Details"]} />
      <TableBody>
        {entries.map((entry) => {
          const isOpen = open === entry.event_id;
          const summary = auditSummary(toAuditChanges(entry.changes), entry.metadata);
          const detailId = `audit-${entry.event_id}`;
          return (
            <Fragment key={entry.event_id}>
              <Tr className={isOpen ? "!bg-brand-tint" : undefined}>
                <Td className="whitespace-nowrap">{when(entry)}</Td>
                <Td>
                  {entry.actor.label || entry.actor.type}
                  {entry.actor.id && <Sub className="font-mono">{entry.actor.id}</Sub>}
                </Td>
                <Td>
                  <Mono>{entry.action}</Mono>
                </Td>
                <Td>
                  <Badge tone={entry.outcome === "success" ? "ok" : "warn"}>{entry.outcome}</Badge>
                </Td>
                <Td className="max-w-80">
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="min-w-0 truncate text-small" title={summary}>
                      {summary}
                    </span>
                    <Button
                      type="button"
                      variant="link"
                      className="shrink-0"
                      aria-expanded={isOpen}
                      aria-controls={detailId}
                      aria-label={`${isOpen ? "Hide" : "Show"} details of ${entry.action} at ${when(entry)}`}
                      onClick={() => setOpen(isOpen ? null : entry.event_id)}
                    >
                      {isOpen ? "Hide" : "Show"}
                    </Button>
                  </div>
                </Td>
              </Tr>
              {isOpen && (
                <DetailRow colSpan={5} id={detailId}>
                  <AuditDetail entry={entry} />
                </DetailRow>
              )}
            </Fragment>
          );
        })}
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
            {/* A new filter or page remounts the table, which closes the open row (SPEC-0031 BR-05). */}
            <AuditTable key={JSON.stringify([filters, page])} entries={events.data.results} />
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
