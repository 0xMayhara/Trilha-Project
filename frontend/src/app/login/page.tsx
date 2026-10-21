import { LoginForm } from "@/components/login-form";

export default function LoginPage() {
  return (
    <main className="mx-auto flex max-w-sm flex-col gap-4 px-4 py-16">
      <h1 className="text-2xl font-semibold">Log in to Trilha</h1>
      <LoginForm />
    </main>
  );
}
