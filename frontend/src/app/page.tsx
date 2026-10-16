import { HealthStatus } from "@/components/health-status";

export default function HomePage() {
  return (
    <main className="mx-auto flex max-w-2xl flex-col gap-4 px-4 py-16">
      <h1 className="text-2xl font-semibold">Trilha</h1>
      <p className="text-neutral-600">Security remediation management platform.</p>
      <HealthStatus />
    </main>
  );
}
