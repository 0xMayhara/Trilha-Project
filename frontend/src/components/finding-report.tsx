"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";

import { FindingForm } from "@/components/finding-form";
import { Notice, Panel } from "@/components/ui";
import type { AccessPage } from "@/lib/access";
import { assetErrorMessage, can, fieldErrors, type Asset } from "@/lib/assets";
import { createFinding, FINDINGS_QUERY_KEY, handleFindingError } from "@/lib/findings";

export function canReport(asset: Asset, access: AccessPage | undefined) {
  return (
    asset.status === "active" &&
    can(access, asset.team.id, "assets.view_asset", "findings.view_finding", "findings.add_finding")
  );
}

/** The "Report finding" form of an active asset, shown when own access holds add + view and asset view in
 * its team. UX only: the API decides, and answers one generic error for an unusable asset. */
export function ReportFinding({
  asset,
  access,
  onCancel,
}: {
  asset: Asset;
  access: AccessPage | undefined;
  onCancel: () => void;
}) {
  const client = useQueryClient();
  const router = useRouter();
  const report = useMutation({
    mutationFn: (input: Parameters<typeof createFinding>[1]) => createFinding(asset.id, input),
    onSuccess: async (finding) => {
      await client.invalidateQueries({ queryKey: FINDINGS_QUERY_KEY });
      router.push(`/findings/${finding.id}`);
    },
    onError: (error) => handleFindingError(client, error),
  });
  if (!canReport(asset, access)) return null;
  const errors = fieldErrors(report.error);
  return (
    <Panel title={`Report a finding on ${asset.name}`}>
      {report.isError && (
        <Notice tone="error">{errors.asset_id ? errors.asset_id.join(" ") : assetErrorMessage(report.error)}</Notice>
      )}
      <FindingForm
        errors={errors}
        pending={report.isPending}
        submitLabel="Report finding"
        onSubmit={(input) => report.mutate(input)}
        onCancel={onCancel}
      />
    </Panel>
  );
}
