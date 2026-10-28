import { PasswordChangeForm } from "@/components/password-change-form";
import { RequireSession } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function PasswordChangePage() {
  return (
    <Page width="medium">
      <PageTitle>Change password</PageTitle>
      <RequireSession>
        <PasswordChangeForm />
      </RequireSession>
    </Page>
  );
}
