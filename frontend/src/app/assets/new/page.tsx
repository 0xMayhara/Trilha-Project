import { AssetRegistration } from "@/components/asset-registration";
import { RequireSession } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function NewAssetPage() {
  return (
    <RequireSession>
      <Page width="medium">
        <PageTitle>Register asset</PageTitle>
        <AssetRegistration />
      </Page>
    </RequireSession>
  );
}
