"use client";

import type { FormEvent, ReactNode } from "react";

import {
  ASSET_KINDS,
  CRITICALITIES,
  CRITICALITY_LABELS,
  ENVIRONMENT_LABELS,
  ENVIRONMENTS,
  KIND_LABELS,
  readAssetForm,
  type Asset,
  type AssetInput,
  type OsCatalogEntry,
} from "@/lib/assets";

type Team = { id: string; code: string; name: string };
/** The OS catalog query, as `useQuery` returns it. */
type Catalog = { data?: OsCatalogEntry[]; isError: boolean; refetch: () => unknown };

const INPUT = "rounded border border-neutral-300 px-3 py-2";

function Field({ label, name, errors, children }: { label: string; name: string; errors: Record<string, string[]>; children: ReactNode }) {
  const messages = errors[name];
  return (
    <label className="flex flex-col gap-1 text-sm">
      {label}
      {children}
      {messages && (
        <span id={`${name}-error`} className="text-red-700">
          {messages.join(" ")}
        </span>
      )}
    </label>
  );
}

/** Native form; FormData is read on submit. The server validates and canonicalizes everything. */
export function AssetForm({
  asset,
  teams,
  catalog,
  errors,
  pending,
  submitLabel,
  onSubmit,
}: {
  asset?: Asset;
  teams?: Team[];
  catalog: Catalog;
  errors: Record<string, string[]>;
  pending: boolean;
  submitLabel: string;
  onSubmit: (input: AssetInput, teamId: string) => void;
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    onSubmit(readAssetForm(form), String(form.get("team_id") ?? ""));
  }
  const described = (name: string) => (errors[name] ? `${name}-error` : undefined);

  // Without the catalog the OS select would submit "Unspecified" and erase a saved choice (SEC-14).
  if (!catalog.data) {
    return catalog.isError ? (
      <div role="alert" className="space-y-2 text-sm text-red-700">
        <p>Operating systems are unavailable; editing is paused.</p>
        <button type="button" className="rounded border border-neutral-400 px-3 py-1" onClick={() => void catalog.refetch()}>
          Retry
        </button>
      </div>
    ) : (
      <p role="status">Loading operating systems...</p>
    );
  }
  const options = catalog.data;
  const families = [...new Map(options.map((option) => [option.family, option.family_label]))];
  const saved = asset?.os_product ?? "";
  const legacy = asset?.operating_system ?? "";
  const osDescribed = [described("os_product"), legacy ? "os-legacy" : undefined].filter(Boolean).join(" ");

  return (
    <form onSubmit={submit} className="flex max-w-xl flex-col gap-3">
      {teams && (
        <Field label="Team" name="team_id" errors={errors}>
          <select name="team_id" required className={INPUT} aria-describedby={described("team_id")}>
            {teams.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </select>
        </Field>
      )}
      <Field label="Name" name="name" errors={errors}>
        <input name="name" required maxLength={150} defaultValue={asset?.name} className={INPUT} aria-describedby={described("name")} />
      </Field>
      <Field label="Kind" name="kind" errors={errors}>
        <select name="kind" required defaultValue={asset?.kind ?? "server"} className={INPUT} aria-describedby={described("kind")}>
          {ASSET_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {KIND_LABELS[kind]}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Hostname (DNS name, optional)" name="hostname" errors={errors}>
        <input name="hostname" maxLength={253} defaultValue={asset?.hostname} className={INPUT} aria-describedby={described("hostname")} />
      </Field>
      <Field label="IP addresses (one per line, up to 16)" name="ip_addresses" errors={errors}>
        <textarea
          name="ip_addresses"
          rows={3}
          defaultValue={asset?.ip_addresses.join("\n")}
          className={INPUT}
          aria-describedby={described("ip_addresses")}
        />
      </Field>
      <Field label="Operating system" name="os_product" errors={errors}>
        <select name="os_product" defaultValue={saved} className={INPUT} aria-describedby={osDescribed || undefined}>
          <option value="">{legacy ? "Not classified" : "Unspecified"}</option>
          {/* A code newer than this cached catalog stays selected, so saving keeps it. */}
          {saved && !options.some((option) => option.code === saved) && <option value={saved}>{`${saved} (unrecognized)`}</option>}
          {families.map(([family, label]) => (
            <optgroup key={family} label={label}>
              {options
                .filter((option) => option.family === family)
                .map((option) => (
                  <option key={option.code} value={option.code}>
                    {option.label}
                  </option>
                ))}
            </optgroup>
          ))}
        </select>
      </Field>
      {legacy && (
        <p id="os-legacy" className="text-sm text-neutral-600">
          {`Legacy OS text: "${legacy}" (kept as recorded)`}
        </p>
      )}
      <Field label="Operating system version (optional)" name="os_version" errors={errors}>
        <input
          name="os_version"
          maxLength={32}
          defaultValue={asset?.os_version}
          className={INPUT}
          aria-describedby={described("os_version")}
        />
      </Field>
      <Field label="Environment" name="environment" errors={errors}>
        <select name="environment" defaultValue={asset?.environment ?? ""} className={INPUT} aria-describedby={described("environment")}>
          <option value="">Unspecified</option>
          {ENVIRONMENTS.map((environment) => (
            <option key={environment} value={environment}>
              {ENVIRONMENT_LABELS[environment]}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Criticality" name="criticality" errors={errors}>
        <select name="criticality" defaultValue={asset?.criticality ?? ""} className={INPUT} aria-describedby={described("criticality")}>
          <option value="">Unassessed</option>
          {CRITICALITIES.map((criticality) => (
            <option key={criticality} value={criticality}>
              {CRITICALITY_LABELS[criticality]}
            </option>
          ))}
        </select>
      </Field>
      <button type="submit" disabled={pending} className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-60">
        {submitLabel}
      </button>
    </form>
  );
}
