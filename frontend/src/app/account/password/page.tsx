import { PasswordChangeForm } from "@/components/password-change-form";
import { RequireSession } from "@/components/require-session";

export default function PasswordChangePage() {
  return (
    <main className="mx-auto flex max-w-sm flex-col gap-4 px-4 py-16">
      <h1 className="text-2xl font-semibold">Change password</h1>
      <RequireSession>
        <PasswordChangeForm />
      </RequireSession>
    </main>
  );
}
