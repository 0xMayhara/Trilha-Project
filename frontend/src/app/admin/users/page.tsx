import { UserList } from "@/components/admin/users";
import { PageTitle } from "@/components/ui";

export default function AdminUsersPage() {
  return (
    <>
      <PageTitle className="sr-only">Users</PageTitle>
      <UserList />
    </>
  );
}
