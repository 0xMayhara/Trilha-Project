import { OwnAccess } from "@/components/own-access";
import { RequireSession } from "@/components/require-session";

export default function AccessPage() {
  return (
    <RequireSession>
      <main className="mx-auto max-w-3xl space-y-6 p-6">
        <h1 className="text-2xl font-semibold">Your access</h1>
        <OwnAccess />
      </main>
    </RequireSession>
  );
}
