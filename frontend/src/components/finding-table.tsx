import Link from "next/link";

import { Facts, FindingStatusBadge, LevelBadge, Panel, Table, TableBody, TableHead, Td, Tr } from "@/components/ui";
import { ENVIRONMENT_LABELS, KIND_LABELS, exposureSummary, hardeningSummary } from "@/lib/assets";
import {
  CATEGORY_LABELS,
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

export function FindingFacts({ finding }: { finding: Finding }) {
  return (
    <Facts
      items={[
        ["Severity", <LevelBadge key="severity" level={finding.severity} />],
        ["Category", CATEGORY_LABELS[finding.category]],
        ["Status", <FindingStatusBadge key="status" status={finding.status} />],
        [
          "CVE IDs",
          finding.cve_ids.length ? (
            <span key="cves" className="font-mono text-[13px]">
              {finding.cve_ids.join(", ")}
            </span>
          ) : (
            "None"
          ),
        ],
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
    <Panel
      title={
        <>
          Asset: <Link href={`/assets/${asset.id}`}>{asset.name}</Link>
          {asset.status === "retired" && " (retired)"}
        </>
      }
    >
      <Facts
        items={[
          ["Kind", KIND_LABELS[asset.kind]],
          ["Environment", asset.environment ? ENVIRONMENT_LABELS[asset.environment] : "Unspecified"],
          ["Criticality", <LevelBadge key="criticality" level={asset.criticality} />],
          ["Hardening (declared)", hardeningSummary(asset.hardening_status)],
          ["Internet exposure (declared)", exposureSummary(asset.internet_exposure)],
          ["Operating system", [asset.os_label, asset.os_version].filter(Boolean).join(" ") || "Unspecified"],
        ]}
      />
    </Panel>
  );
}
