import { HealthStatus } from "@/components/health-status";
import { Page, PageTitle, Panel } from "@/components/ui";

export default function HomePage() {
  return (
    <Page width="medium">
      <PageTitle>Trilha</PageTitle>
      <p className="m-0 text-ink-muted">Security remediation management platform.</p>
      <Panel title="Status">
        <HealthStatus />
      </Panel>
    </Page>
  );
}
