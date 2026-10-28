import { RoleList } from "@/components/admin/roles";
import { PageTitle } from "@/components/ui";

export default function AdminRolesPage() {
  return (
    <>
      <PageTitle className="sr-only">Roles and permissions</PageTitle>
      <RoleList />
    </>
  );
}
