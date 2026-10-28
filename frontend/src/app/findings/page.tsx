import { FindingInventory } from "@/components/finding-inventory";
import { RequireSession } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function FindingsPage() {
  return (
    <RequireSession>
      <Page>
        <PageTitle>Findings</PageTitle>
        <FindingInventory />
      </Page>
    </RequireSession>
  );
}
