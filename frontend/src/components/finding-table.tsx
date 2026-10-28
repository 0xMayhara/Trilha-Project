import Link from "next/link";

import { FindingStatusBadge, LevelBadge, Table, TableBody, TableHead, Td, Tr } from "@/components/ui";
import { CRITICALITY_LABELS, ENVIRONMENT_LABELS, KIND_LABELS, exposureSummary, hardeningSummary } from "@/lib/assets";
import {
  CATEGORY_LABELS,
  FINDING_STATUS_LABELS,
  SEVERITY_LABELS,
  userLabel,
  type Finding,
  type FindingSummary,
} from "@/lib/findings";

const HEADINGS = ["Title", "Asset", "Team", "Severity", "Category", "Status", "Assignee", "Reported"];

/** Every value is rendered as React text, never HTML (SPEC-0007 SEC-26). */
export function FindingTable({ findings }: { findings: FindingSummary[] }) {
  return (
    <Table caption="Findings">
      <TableHead columns={HEADINGS} />
      <TableBody>
        {findings.map((finding) => (
          <Tr key={finding.id}>
            <Td>
              <Link href={`/findings/${finding.id}`}>{finding.title}</Link>
            </Td>
            <Td>
              {finding.asset.name}
              {finding.asset.status === "retired" && " (retired)"}
            </Td>
            <Td>
              {finding.team.name} ({finding.team.code})
            </Td>
            <Td>
              <LevelBadge level={finding.severity} />
            </Td>
            <Td>{CATEGORY_LABELS[finding.category]}</Td>
            <Td>
              <FindingStatusBadge status={finding.status} />
            </Td>
            <Td>{finding.assignee ? userLabel(finding.assignee) : "Unassigned"}</Td>
            <Td>{finding.created_at.slice(0, 10)}</Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
  );
}
function Facts({ facts }: { facts: [string, string][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {facts.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="font-semibold">{term}</dt>
          <dd className="whitespace-pre-wrap">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function FindingFacts({ finding }: { finding: Finding }) {
  return (
    <Facts
      facts={[
        ["Severity", SEVERITY_LABELS[finding.severity]],
        ["Category", CATEGORY_LABELS[finding.category]],
        ["Status", FINDING_STATUS_LABELS[finding.status]],
        ["CVE IDs", finding.cve_ids.join(", ") || "None"],
        ["Team", `${finding.team.name} (${finding.team.code})`],
        ["Assignee", finding.assignee ? userLabel(finding.assignee) : "Unassigned"],
        ["Reported by", userLabel(finding.reported_by)],
        ["Reported", finding.created_at.slice(0, 10)],
        ["Description", finding.description || "None"],
      ]}
    />
  );
}

/** The asset context of a finding; posture is what the team declared, not a verification. */
export function FindingAsset({ finding }: { finding: Finding }) {
  const asset = finding.asset;
  return (
    <section aria-label="Asset" className="space-y-2">
      <h2 className="text-lg font-semibold">
        Asset:{" "}
        <Link href={`/assets/${asset.id}`} className="underline">
          {asset.name}
        </Link>
        {asset.status === "retired" && " (retired)"}
      </h2>
      <Facts
        facts={[
          ["Kind", KIND_LABELS[asset.kind]],
          ["Environment", asset.environment ? ENVIRONMENT_LABELS[asset.environment] : "Unspecified"],
          ["Criticality", asset.criticality ? CRITICALITY_LABELS[asset.criticality] : "Unassessed"],
          ["Hardening (declared)", hardeningSummary(asset.hardening_status)],
          ["Internet exposure (declared)", exposureSummary(asset.internet_exposure)],
          ["Operating system", [asset.os_label, asset.os_version].filter(Boolean).join(" ") || "Unspecified"],
        ]}
      />
    </section>
  );
}
