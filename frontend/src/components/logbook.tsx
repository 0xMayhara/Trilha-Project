import { Logbook, type LogbookEntry } from "@/components/ui";
import { redactedText, systemEventText, userLabel, type Entry } from "@/lib/findings";

const at = (entry: Entry) => entry.created_at.slice(0, 16).replace("T", " ");

/** The Operational Logbook, read-only in slice B: comments as messages, system events as one-line
 * notices from fixed templates. Plain text only (`white-space: pre-wrap`), never HTML (SEC-26). */
export function LogbookEntries({ entries }: { entries: Entry[] }) {
  return (
    <Logbook
      entries={entries.map((entry): LogbookEntry => {
        const author = userLabel(entry.actor);
        if (entry.kind === "system") return { id: entry.id, kind: "system", text: systemEventText(entry), author, at: at(entry) };
        if (entry.redacted) return { id: entry.id, kind: "comment", author, at: at(entry), redactedNote: redactedText(entry) };
        return { id: entry.id, kind: "comment", author, at: at(entry), body: entry.body };
      })}
    />
  );
}
