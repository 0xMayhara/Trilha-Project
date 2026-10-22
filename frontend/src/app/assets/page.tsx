import { AssetInventory } from "@/components/asset-inventory";
import { RequireSession } from "@/components/require-session";

export default function AssetsPage() {
  return (
    <RequireSession>
      <main className="mx-auto max-w-6xl space-y-6 p-6">
        <h1 className="text-2xl font-semibold">Assets</h1>
        <AssetInventory />
      </main>
    </RequireSession>
  );
}
