import { FindingInventory } from "@/components/finding-inventory";
import { RequireSession } from "@/components/require-session";

export default function FindingsPage() {
  return (
    <RequireSession>
      <main className="mx-auto max-w-6xl space-y-6 p-6">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <FindingInventory />
      </main>
    </RequireSession>
  );
}
