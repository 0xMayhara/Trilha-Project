import { Page, PageTitle } from "@/components/ui";

import { SetPasswordLoader } from "./set-password-loader";

export default function SetPasswordPage() {
  return (
    <Page width="narrow">
      <PageTitle>Set your password</PageTitle>
      <SetPasswordLoader />
    </Page>
  );
}
