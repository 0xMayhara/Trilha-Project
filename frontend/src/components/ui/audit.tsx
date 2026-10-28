import type { ReactNode } from "react";

import { Facts } from "./facts";
import { Sub, Table, TableBody, TableHead, Td, Tr } from "./table";

/** `changes` of an audit event: each field maps to [before, after]. */
export type AuditChanges = Record<string, readonly [unknown, unknown]>;
export type AuditMetadata = Record<string, unknown>;

const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
const isList = (v: unknown): v is unknown[] => Array.isArray(v);

/** Plain text for one value. Lists and objects never print raw. */
export function auditValue(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (isList(value)) return `${value.length} items`;
  if (typeof value === "object") return "Object";
  return String(value);
}

function listDiff(before: unknown[], after: unknown[]) {
  const keyOf = (v: unknown) => JSON.stringify(v);
  const beforeKeys = new Set(before.map(keyOf));
  const afterKeys = new Set(after.map(keyOf));
  return {
    added: after.filter((v) => !beforeKeys.has(keyOf(v))),
    removed: before.filter((v) => !afterKeys.has(keyOf(v))),
    kept: before.filter((v) => afterKeys.has(keyOf(v))).length,
  };
}

/** One-line summary for the Details column, e.g. "is_admin: false → true" or "reason: forbidden". */
export function auditSummary(changes: AuditChanges, metadata: AuditMetadata): string {
  const changed = Object.entries(changes).filter(([, [a, b]]) => !same(a, b));
  const first = changed[0];
  if (first) {
    const [field, [before, after]] = first;
    let text: string;
    if (isList(before) && isList(after)) {
      const { added, removed } = listDiff(before, after);
      const parts = [added.length ? `${added.length} added` : "", removed.length ? `${removed.length} removed` : ""].filter(Boolean);
      text = `${field}: ${parts.join(", ") || "reordered"}`;
    } else {
      text = `${field}: ${auditValue(before)} → ${auditValue(after)}`;
    }
    return changed.length > 1 ? `${text}, and ${changed.length - 1} more` : text;
  }
  const meta = Object.entries(metadata)[0];
  return meta ? `${meta[0]}: ${auditValue(meta[1])}` : "No details";
}

const Mono = ({ children, className = "" }: { children: ReactNode; className?: string }) => (
  <div className={`font-mono text-code ${className}`}>{children}</div>
);

/** Before and after of each field. Lists show only what was added and removed. */
export function AuditChangesTable({ changes }: { changes: AuditChanges }) {
  const rows = Object.entries(changes);
  if (!rows.length) return <p className="m-0 text-small text-ink-muted">No field changes recorded.</p>;
  return (
    <Table caption="Changes">
      <TableHead columns={["Field", "Before", "After"]} />
      <TableBody>
        {rows.map(([field, [before, after]]) => {
          if (isList(before) && isList(after)) {
            const { added, removed, kept } = listDiff(before, after);
            return (
              <Tr key={field}>
                <Td><Mono>{field}</Mono></Td>
                <Td>
                  {removed.map((v) => <Mono key={JSON.stringify(v)} className="text-danger">− {auditValue(v)}</Mono>)}
                  <Sub>{kept} unchanged</Sub>
                </Td>
                <Td>{added.map((v) => <Mono key={JSON.stringify(v)} className="text-success">+ {auditValue(v)}</Mono>)}</Td>
              </Tr>
            );
          }
          const unchanged = same(before, after);
          return (
            <Tr key={field} className={unchanged ? "text-ink-muted" : undefined}>
              <Td><Mono>{field}</Mono></Td>
              <Td>{auditValue(before)}</Td>
              <Td>{unchanged ? "Unchanged" : auditValue(after)}</Td>
            </Tr>
          );
        })}
      </TableBody>
    </Table>
  );
}

export function AuditMetadataFacts({ metadata }: { metadata: AuditMetadata }) {
  const items = Object.entries(metadata);
  if (!items.length) return <p className="m-0 text-small text-ink-muted">No metadata.</p>;
  return <Facts items={items.map(([key, value]) => [key, auditValue(value)])} />;
}

/** Collapsed raw JSON with a height cap. Text only, never HTML. */
export function AuditRawJson({ value }: { value: unknown }) {
  return (
    <details className="text-small">
      <summary className="cursor-pointer text-brand underline">Raw JSON</summary>
      <pre className="m-0 mt-2 max-h-56 overflow-auto border border-border bg-surface p-3 font-mono text-code whitespace-pre">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}
