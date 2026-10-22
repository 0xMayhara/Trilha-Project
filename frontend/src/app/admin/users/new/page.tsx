import { UserCreate } from "@/components/admin/users";

export default function AdminNewUserPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Create user</h1>
      <UserCreate />
    </>
  );
}
