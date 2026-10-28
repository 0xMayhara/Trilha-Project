import Link from "next/link";

import { AssetStatusBadge, LevelBadge, Table, TableBody, TableHead, Td, Tr } from "@/components/ui";
import {
  CRITICALITY_LABELS,
  ENVIRONMENT_LABELS,
  KIND_LABELS,
  exposureSummary,
  hardeningSummary,
  osSummary,
  type Asset,
} from "@/lib/assets";

const HEADINGS = [
  "Name",
  "Kind",
  "Hostname",
  "IP addresses",
  "Operating system",
  "Team",
  "Environment",
  "Criticality",
  "Hardening",
  "Internet exposure",
  "Status",
];

/** Every value is rendered as React text, never HTML (SEC-19). */
export function AssetTable({ assets }: { assets: Asset[] }) {
  return (
    <Table caption="Assets">
      <TableHead columns={HEADINGS} />
      <TableBody>
        {assets.map((asset) => (
          <Tr key={asset.id}>
            <Td className="whitespace-nowrap">
              <Link href={`/assets/${asset.id}`}>{asset.name}</Link>
            </Td>
            <Td>{KIND_LABELS[asset.kind]}</Td>
            <Td>{asset.hostname || "None"}</Td>
            <Td>{asset.ip_addresses.join(", ") || "None"}</Td>
            <Td>{osSummary(asset)}</Td>
            <Td>
              {asset.team.name} ({asset.team.code})
            </Td>
            <Td>{asset.environment ? ENVIRONMENT_LABELS[asset.environment] : "Unspecified"}</Td>
            <Td>
              <LevelBadge level={asset.criticality} />
            </Td>
            <Td>{hardeningSummary(asset.hardening_status)}</Td>
            <Td>{exposureSummary(asset.internet_exposure)}</Td>
            <Td>
              <AssetStatusBadge status={asset.status} />
            </Td>
          </Tr>
        ))}
      </TableBody>
    </Table>
  );
}

export function AssetFacts({ asset }: { asset: Asset }) {
  const facts: [string, string][] = [
    ["Team", `${asset.team.name} (${asset.team.code})`],
    ["Kind", KIND_LABELS[asset.kind]],
    ["Hostname", asset.hostname || "None"],
    ["IP addresses", asset.ip_addresses.join(", ") || "None"],
    ["Operating system", osSummary(asset)],
    ...(asset.operating_system ? [["Legacy OS text", asset.operating_system] as [string, string]] : []),
    ["Environment", asset.environment ? ENVIRONMENT_LABELS[asset.environment] : "Unspecified"],
    ["Criticality", asset.criticality ? CRITICALITY_LABELS[asset.criticality] : "Unassessed"],
    // Declared by the team, not verified (SPEC-0007 BR-25).
    ["Hardening (declared)", hardeningSummary(asset.hardening_status)],
    ["Internet exposure (declared)", exposureSummary(asset.internet_exposure)],
    ["Status", asset.status === "active" ? "Active" : "Retired"],
  ];
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
      {facts.map(([term, value]) => (
        <div key={term} className="contents">
          <dt className="font-semibold">{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
