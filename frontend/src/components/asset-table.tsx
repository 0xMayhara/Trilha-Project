import Link from "next/link";

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
    <table className="w-full border-collapse text-left text-sm">
      <caption className="sr-only">Assets</caption>
      <thead>
        <tr>
          {HEADINGS.map((heading) => (
            <th key={heading} scope="col" className="border-b border-neutral-300 px-2 py-1 font-semibold">
              {heading}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {assets.map((asset) => (
          <tr key={asset.id} className="border-b border-neutral-100">
            <td className="px-2 py-1">
              <Link href={`/assets/${asset.id}`} className="underline">
                {asset.name}
              </Link>
            </td>
            <td className="px-2 py-1">{KIND_LABELS[asset.kind]}</td>
            <td className="px-2 py-1">{asset.hostname || "None"}</td>
            <td className="px-2 py-1">{asset.ip_addresses.join(", ") || "None"}</td>
            <td className="px-2 py-1">{osSummary(asset)}</td>
            <td className="px-2 py-1">
              {asset.team.name} ({asset.team.code})
            </td>
            <td className="px-2 py-1">{asset.environment ? ENVIRONMENT_LABELS[asset.environment] : "Unspecified"}</td>
            <td className="px-2 py-1">{asset.criticality ? CRITICALITY_LABELS[asset.criticality] : "Unassessed"}</td>
            <td className="px-2 py-1">{hardeningSummary(asset.hardening_status)}</td>
            <td className="px-2 py-1">{exposureSummary(asset.internet_exposure)}</td>
            <td className="px-2 py-1">{asset.status === "active" ? "Active" : "Retired"}</td>
          </tr>
        ))}
      </tbody>
    </table>
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
