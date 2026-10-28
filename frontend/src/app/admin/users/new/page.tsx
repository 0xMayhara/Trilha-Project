import { UserCreate } from "@/components/admin/users";
import { PageTitle } from "@/components/ui";

export default function AdminNewUserPage() {
  return (
    <>
      <PageTitle className="sr-only">Create user</PageTitle>
      <UserCreate />
    </>
  );
}
