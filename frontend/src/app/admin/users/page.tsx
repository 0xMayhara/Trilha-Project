import { UserList } from "@/components/admin/users";

export default function AdminUsersPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Users</h1>
      <UserList />
    </>
  );
}
