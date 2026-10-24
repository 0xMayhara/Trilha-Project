"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { FindingForm } from "@/components/finding-form";
import type { AccessPage } from "@/lib/access";
import { assetErrorMessage, can, fieldErrors, type Asset } from "@/lib/assets";
import { createFinding, FINDINGS_QUERY_KEY, handleFindingError } from "@/lib/findings";

const BUTTON = "rounded border border-neutral-400 px-3 py-1 text-sm disabled:opacity-60";

export function canReport(asset: Asset, access: AccessPage | undefined) {
  return (
    asset.status === "active" &&
    can(access, asset.team.id, "assets.view_asset", "findings.view_finding", "findings.add_finding")
  );
}

/** "Report finding" on an active asset, shown when own access holds add + view and asset view in its
 * team. UX only: the API decides, and answers one generic error for an unusable asset. */
export function ReportFinding({ asset, access }: { asset: Asset; access: AccessPage | undefined }) {
  const client = useQueryClient();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const report = useMutation({
    mutationFn: (input: Parameters<typeof createFinding>[1]) => createFinding(asset.id, input),
    onSuccess: async (finding) => {
      await client.invalidateQueries({ queryKey: FINDINGS_QUERY_KEY });
      router.push(`/findings/${finding.id}`);
    },
    onError: (error) => handleFindingError(client, error),
  });
  if (!canReport(asset, access)) return null;
  if (!open) {
    return (
      <button type="button" className={BUTTON} onClick={() => setOpen(true)}>
        Report finding
      </button>
    );
  }
  const errors = fieldErrors(report.error);
  return (
    <section aria-label="Report finding" className="space-y-3 rounded border border-neutral-300 p-3">
      <h2 className="text-lg font-semibold">Report a finding on {asset.name}</h2>
      {report.isError && (
        <p role="alert" className="text-sm text-red-700">
          {errors.asset_id ? errors.asset_id.join(" ") : assetErrorMessage(report.error)}
        </p>
      )}
      <FindingForm errors={errors} pending={report.isPending} submitLabel="Report finding" onSubmit={(input) => report.mutate(input)} />
      <button type="button" className={BUTTON} onClick={() => setOpen(false)}>
        Cancel
      </button>
    </section>
  );
}
