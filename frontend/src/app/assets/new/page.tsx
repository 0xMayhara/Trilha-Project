import { AssetRegistration } from "@/components/asset-registration";
import { RequireSession } from "@/components/require-session";

export default function NewAssetPage() {
  return (
    <RequireSession>
      <main className="mx-auto max-w-3xl space-y-6 p-6">
        <h1 className="text-2xl font-semibold">Register asset</h1>
        <AssetRegistration />
      </main>
    </RequireSession>
  );
}
