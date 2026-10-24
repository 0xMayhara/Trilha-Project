import { redactedText, systemEventText, userLabel, type Entry } from "@/lib/findings";

/** The Operational Logbook, read-only in slice B: comments as messages, system events as one-line
 * notices from fixed templates. Plain text only (`white-space: pre-wrap`), never HTML (SEC-26). */
export function LogbookEntries({ entries }: { entries: Entry[] }) {
  if (entries.length === 0) return <p className="text-sm">No entries yet.</p>;
  return (
    <ol className="space-y-2" aria-label="Logbook entries">
      {entries.map((entry) => (
        <li key={entry.id} data-sequence={entry.sequence}>
          {entry.kind === "system" ? (
            <p className="text-center text-xs text-neutral-600">
              {systemEventText(entry)} · {userLabel(entry.actor)} · {entry.created_at.slice(0, 16).replace("T", " ")}
            </p>
          ) : (
            <div className="rounded border border-neutral-200 bg-neutral-50 p-2 text-sm">
              <p className="text-xs text-neutral-600">
                {userLabel(entry.actor)} · {entry.created_at.slice(0, 16).replace("T", " ")}
              </p>
              {entry.redacted ? (
                <p className="italic text-neutral-600">{redactedText(entry)}</p>
              ) : (
                <p className="whitespace-pre-wrap">{entry.body}</p>
              )}
            </div>
          )}
        </li>
      ))}
    </ol>
  );
}
