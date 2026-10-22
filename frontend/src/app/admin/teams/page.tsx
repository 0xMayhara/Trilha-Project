import { TeamList } from "@/components/admin/teams";

export default function AdminTeamsPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Teams</h1>
      <TeamList />
    </>
  );
}
