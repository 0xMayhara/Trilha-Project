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
} from "@/lib/assets";

type Team = { id: string; code: string; name: string };

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
  errors,
  pending,
  submitLabel,
  onSubmit,
}: {
  asset?: Asset;
  teams?: Team[];
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
      <Field label="Operating system (optional)" name="operating_system" errors={errors}>
        <input
          name="operating_system"
          maxLength={150}
          defaultValue={asset?.operating_system}
          className={INPUT}
          aria-describedby={described("operating_system")}
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
