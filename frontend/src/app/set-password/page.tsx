import { SetPasswordLoader } from "./set-password-loader";

export default function SetPasswordPage() {
  return (
    <main className="mx-auto flex max-w-sm flex-col gap-4 px-4 py-16">
      <h1 className="text-2xl font-semibold">Set your password</h1>
      <SetPasswordLoader />
    </main>
  );
}
