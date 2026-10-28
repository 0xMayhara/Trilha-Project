import type { ReactNode } from "react";

export type LogbookEntry =
  | { id: string; kind: "comment"; author: string; at: string; body: ReactNode; redactedNote?: undefined }
  | { id: string; kind: "comment"; author: string; at: string; body?: undefined; redactedNote: string }
  | { id: string; kind: "system"; text: string; author: string; at: string };

/** Operational Logbook of a finding, oldest first. Plain text only, never HTML from users. */
export function Logbook({ entries }: { entries: LogbookEntry[] }) {
  if (entries.length === 0) return <p className="text-small">No entries yet.</p>;
  return (
    <ol className="m-0 flex list-none flex-col gap-2 p-0" aria-label="Logbook entries">
      {entries.map((entry) => (
        <li key={entry.id}>
          {entry.kind === "system" ? (
            <p className="m-0 text-center text-caption text-ink-muted">
              {entry.text} · {entry.author} · {entry.at}
            </p>
          ) : (
            <div className="border border-border bg-stripe px-3 py-2 text-ui">
              <p className="m-0 mb-0.5 text-caption text-ink-muted">
                {entry.author} · {entry.at}
              </p>
              {entry.redactedNote ? (
                <p className="m-0 text-ink-muted italic">{entry.redactedNote}</p>
              ) : (
                <p className="m-0 whitespace-pre-wrap">{entry.body}</p>
              )}
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}
