import { TeamList } from "@/components/admin/teams";
import { PageTitle } from "@/components/ui";

export default function AdminTeamsPage() {
  return (
    <>
      <PageTitle className="sr-only">Teams</PageTitle>
      <TeamList />
    </>
  );
}
