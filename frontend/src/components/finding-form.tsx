"use client";

import type { FormEvent, ReactNode } from "react";

import {
  CATEGORIES,
  CATEGORY_LABELS,
  readFindingForm,
  SEVERITIES,
  SEVERITY_LABELS,
  type Finding,
  type FindingInput,
} from "@/lib/findings";

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

/** Native form read with FormData on submit. The server validates and canonicalizes every field. */
export function FindingForm({
  finding,
  errors,
  pending,
  submitLabel,
  onSubmit,
}: {
  finding?: Finding;
  errors: Record<string, string[]>;
  pending: boolean;
  submitLabel: string;
  onSubmit: (input: FindingInput) => void;
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(readFindingForm(new FormData(event.currentTarget)));
  }
  const described = (name: string) => (errors[name] ? `${name}-error` : undefined);
  return (
    <form onSubmit={submit} className="flex max-w-xl flex-col gap-3">
      <Field label="Title" name="title" errors={errors}>
        <input name="title" required maxLength={200} defaultValue={finding?.title} className={INPUT} aria-describedby={described("title")} />
      </Field>
      <Field label="Description (optional, plain text)" name="description" errors={errors}>
        <textarea
          name="description"
          rows={5}
          maxLength={10000}
          defaultValue={finding?.description}
          className={INPUT}
          aria-describedby={described("description")}
        />
      </Field>
      <Field label="Category" name="category" errors={errors}>
        <select name="category" required defaultValue={finding?.category ?? "vulnerability"} className={INPUT} aria-describedby={described("category")}>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {CATEGORY_LABELS[category]}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Technical severity" name="severity" errors={errors}>
        <select name="severity" required defaultValue={finding?.severity ?? "high"} className={INPUT} aria-describedby={described("severity")}>
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {SEVERITY_LABELS[severity]}
            </option>
          ))}
        </select>
      </Field>
      <Field label="CVE IDs (optional, one per line)" name="cve_ids" errors={errors}>
        <textarea
          name="cve_ids"
          rows={3}
          defaultValue={finding?.cve_ids.join("\n")}
          className={INPUT}
          aria-describedby={described("cve_ids")}
        />
      </Field>
      <p className="text-sm text-neutral-600">Never paste passwords, keys or personal data into findings.</p>
      <button type="submit" disabled={pending} className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-60">
        {submitLabel}
      </button>
    </form>
  );
}
