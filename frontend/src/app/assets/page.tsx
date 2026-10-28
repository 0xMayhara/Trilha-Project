import { AssetInventory } from "@/components/asset-inventory";
import { RequireSession } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function AssetsPage() {
  return (
    <RequireSession>
      <Page>
        <PageTitle>Assets</PageTitle>
        <AssetInventory />
      </Page>
    </RequireSession>
  );
}
