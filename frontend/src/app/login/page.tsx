import { LoginForm } from "@/components/login-form";
import { RedirectIfSignedIn } from "@/components/require-session";
import { Page, PageTitle } from "@/components/ui";

export default function LoginPage() {
  return (
    <Page width="narrow">
      <PageTitle>Log in to Trilha</PageTitle>
      <RedirectIfSignedIn>
        <LoginForm />
      </RedirectIfSignedIn>
    </Page>
  );
}
