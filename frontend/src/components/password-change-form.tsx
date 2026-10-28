"use client";

import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { NewPasswordFields, readNewPassword } from "@/components/new-password-fields";
import { Button, Field, Form, Input, Notice } from "@/components/ui";
import { authErrorMessage, changePassword } from "@/lib/auth";

export function PasswordChangeForm() {
  const [mismatch, setMismatch] = useState<string | null>(null);
  const change = useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) =>
      changePassword(current, next),
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const result = readNewPassword(new FormData(form));
    setMismatch("mismatch" in result ? result.mismatch : null);
    if ("password" in result) {
      const current = String(new FormData(form).get("current_password") ?? "");
      change.mutate({ current, next: result.password }, { onSuccess: () => form.reset() });
    }
  }

  return (
    <Form onSubmit={onSubmit}>
      <Field label="Current password">
        <Input name="current_password" type="password" autoComplete="current-password" required maxLength={1024} />
      </Field>
      <NewPasswordFields mismatch={mismatch} />
      {change.isError && <Notice tone="error">{authErrorMessage(change.error)}</Notice>}
      {change.isSuccess && <Notice tone="success">Password changed. Your other sessions have been signed out.</Notice>}
      <div>
        <Button type="submit" variant="primary" disabled={change.isPending}>
          Change password
        </Button>
      </div>
    </Form>
  );
}
