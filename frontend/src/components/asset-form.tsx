"use client";

import type { FormEvent } from "react";

import { Button, Field, Form, Input, Notice, Select, Textarea } from "@/components/ui";
import {
  ASSET_KINDS,
  CRITICALITIES,
  CRITICALITY_LABELS,
  ENVIRONMENT_LABELS,
  ENVIRONMENTS,
  EXPOSURE_LABELS,
  HARDENING_LABELS,
  HARDENING_STATUSES,
  INTERNET_EXPOSURES,
  KIND_LABELS,
  readAssetForm,
  type Asset,
  type AssetInput,
  type OsCatalogEntry,
} from "@/lib/assets";

type Team = { id: string; code: string; name: string };
/** The OS catalog query, as `useQuery` returns it. */
type Catalog = { data?: OsCatalogEntry[]; isError: boolean; refetch: () => unknown };

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
  const error = (name: string) => errors[name]?.join(" ");

  // Without the catalog the OS select would submit "Unspecified" and erase a saved choice (SEC-14).
  if (!catalog.data) {
    return catalog.isError ? (
      <Notice tone="error">
        <p className="m-0">Operating systems are unavailable; editing is paused.</p>
        <div>
          <Button onClick={() => void catalog.refetch()}>Retry</Button>
        </div>
      </Notice>
    ) : (
      <p role="status" className="m-0 text-ink-muted">
        Loading operating systems...
      </p>
    );
  }
  const options = catalog.data;
  const families = [...new Map(options.map((option) => [option.family, option.family_label]))];
  const saved = asset?.os_product ?? "";
  const legacy = asset?.operating_system ?? "";

  return (
    <Form onSubmit={submit}>
      {teams && (
        <Field label="Team" error={error("team_id")}>
          <Select name="team_id" required>
            {teams.map((team) => (
              <option key={team.id} value={team.id}>
                {team.name} ({team.code})
              </option>
            ))}
          </Select>
        </Field>
      )}
      <Field label="Name" error={error("name")}>
        <Input name="name" required maxLength={150} defaultValue={asset?.name} />
      </Field>
      <Field label="Kind" error={error("kind")}>
        <Select name="kind" required defaultValue={asset?.kind ?? "server"}>
          {ASSET_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {KIND_LABELS[kind]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Hostname (DNS name, optional)" error={error("hostname")}>
        <Input name="hostname" maxLength={253} defaultValue={asset?.hostname} />
      </Field>
      <Field label="IP addresses (one per line, up to 16)" error={error("ip_addresses")}>
        <Textarea name="ip_addresses" rows={3} defaultValue={asset?.ip_addresses.join("\n")} />
      </Field>
      <Field
        label="Operating system"
        help={legacy ? `Legacy OS text: "${legacy}" (kept as recorded)` : undefined}
        error={error("os_product")}
      >
        <Select name="os_product" defaultValue={saved}>
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
        </Select>
      </Field>
      <Field label="Operating system version (optional)" error={error("os_version")}>
        <Input name="os_version" maxLength={32} defaultValue={asset?.os_version} />
      </Field>
      <Field label="Environment" error={error("environment")}>
        <Select name="environment" defaultValue={asset?.environment ?? ""}>
          <option value="">Unspecified</option>
          {ENVIRONMENTS.map((environment) => (
            <option key={environment} value={environment}>
              {ENVIRONMENT_LABELS[environment]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Criticality" error={error("criticality")}>
        <Select name="criticality" defaultValue={asset?.criticality ?? ""}>
          <option value="">Unassessed</option>
          {CRITICALITIES.map((criticality) => (
            <option key={criticality} value={criticality}>
              {CRITICALITY_LABELS[criticality]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Hardening (declared)" error={error("hardening_status")}>
        <Select name="hardening_status" defaultValue={asset?.hardening_status ?? ""}>
          <option value="">Not assessed</option>
          {HARDENING_STATUSES.map((status) => (
            <option key={status} value={status}>
              {HARDENING_LABELS[status]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Internet exposure (declared)" error={error("internet_exposure")}>
        <Select name="internet_exposure" defaultValue={asset?.internet_exposure ?? ""}>
          <option value="">Unknown</option>
          {INTERNET_EXPOSURES.map((exposure) => (
            <option key={exposure} value={exposure}>
              {EXPOSURE_LABELS[exposure]}
            </option>
          ))}
        </Select>
      </Field>
      <div>
        <Button type="submit" variant="primary" disabled={pending}>
          {submitLabel}
        </Button>
      </div>
    </Form>
  );
}
