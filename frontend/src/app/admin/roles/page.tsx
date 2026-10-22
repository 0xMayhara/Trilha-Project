import { RoleList } from "@/components/admin/roles";

export default function AdminRolesPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Roles and permissions</h1>
      <RoleList />
    </>
  );
}
