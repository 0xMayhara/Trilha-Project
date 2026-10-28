"use client";

import type { FormEvent } from "react";

import { Button, Field, Form, Input, Select, Textarea } from "@/components/ui";
import {
  CATEGORIES,
  CATEGORY_LABELS,
  readFindingForm,
  SEVERITIES,
  SEVERITY_LABELS,
  type Finding,
  type FindingInput,
} from "@/lib/findings";

/** Native form read with FormData on submit. The server validates and canonicalizes every field. */
export function FindingForm({
  finding,
  errors,
  pending,
  submitLabel,
  onSubmit,
  onCancel,
}: {
  finding?: Finding;
  errors: Record<string, string[]>;
  pending: boolean;
  submitLabel: string;
  onSubmit: (input: FindingInput) => void;
  onCancel?: () => void;
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onSubmit(readFindingForm(new FormData(event.currentTarget)));
  }
  const error = (name: string) => errors[name]?.join(" ");
  return (
    <Form onSubmit={submit}>
      <Field label="Title" error={error("title")}>
        <Input name="title" required maxLength={200} defaultValue={finding?.title} />
      </Field>
      <Field label="Description (optional, plain text)" error={error("description")}>
        <Textarea name="description" rows={4} maxLength={10000} defaultValue={finding?.description} />
      </Field>
      <Field label="Category" error={error("category")}>
        <Select name="category" required defaultValue={finding?.category ?? "vulnerability"} className="w-60">
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>
              {CATEGORY_LABELS[category]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Technical severity" error={error("severity")}>
        <Select name="severity" required defaultValue={finding?.severity ?? "high"} className="w-60">
          {SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {SEVERITY_LABELS[severity]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="CVE IDs (optional, one per line)" error={error("cve_ids")}>
        <Textarea name="cve_ids" rows={2} defaultValue={finding?.cve_ids.join("\n")} className="font-mono text-[13px]" />
      </Field>
      <p className="m-0 text-small text-ink-muted">Never paste passwords, keys or personal data into findings.</p>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="submit" variant="primary" disabled={pending}>
          {submitLabel}
        </Button>
        {onCancel && <Button onClick={onCancel}>Cancel</Button>}
      </div>
    </Form>
  );
}
