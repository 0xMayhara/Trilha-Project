import { OwnAccess } from "@/components/own-access";
import { RequireSession } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function AccessPage() {
  return (
    <RequireSession>
      <Page width="medium">
        <PageTitle>Your access</PageTitle>
        <OwnAccess />
      </Page>
    </RequireSession>
  );
}
