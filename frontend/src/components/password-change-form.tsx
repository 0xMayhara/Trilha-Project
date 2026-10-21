"use client";

import { useMutation } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { NewPasswordFields, readNewPassword } from "@/components/new-password-fields";
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
    <form onSubmit={onSubmit} className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-sm">
        Current password
        <input
          name="current_password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={1024}
          className="rounded border border-neutral-300 px-3 py-2"
        />
      </label>
      <NewPasswordFields />
      {(mismatch ?? change.isError) && (
        <p role="alert" className="text-sm text-red-700">
          {mismatch ?? authErrorMessage(change.error)}
        </p>
      )}
      {change.isSuccess && (
        <p role="status" className="text-sm text-green-700">
          Password changed. Your other sessions have been signed out.
        </p>
      )}
      <button
        type="submit"
        disabled={change.isPending}
        className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-60"
      >
        Change password
      </button>
    </form>
  );
}
