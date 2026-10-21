"use client";

import { useMutation } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";

import { NewPasswordFields, readNewPassword } from "@/components/new-password-fields";
import { authErrorMessage, setPassword } from "@/lib/auth";
import { readPasswordLink, removeFragment } from "@/lib/password-link";

/** Rendered only in the browser (see set-password/page.tsx): it reads the link from the address. */
export default function SetPasswordForm() {
  // Kept in memory only, never in browser storage (SPEC-0003 SEC-22).
  const [link] = useState(() => readPasswordLink(window.location.hash));
  const [mismatch, setMismatch] = useState<string | null>(null);
  const submit = useMutation({
    mutationFn: (password: string) => setPassword(link!, password),
  });

  useEffect(() => {
    removeFragment(window.location, window.history);
  }, []);

  if (link === null) {
    return (
      <p role="alert" className="text-sm text-red-700">
        This link is incomplete. Ask an administrator for a new one.
      </p>
    );
  }
  if (submit.isSuccess) {
    return (
      <p role="status" className="text-sm text-green-700">
        Your password is set. <Link href="/login" className="underline">Log in</Link>.
      </p>
    );
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const result = readNewPassword(new FormData(event.currentTarget));
    setMismatch("mismatch" in result ? result.mismatch : null);
    if ("password" in result) {
      submit.mutate(result.password);
    }
  }

  return (
    <form onSubmit={onSubmit} className="flex flex-col gap-3">
      <NewPasswordFields />
      {(mismatch ?? submit.isError) && (
        <p role="alert" className="text-sm text-red-700">
          {mismatch ?? authErrorMessage(submit.error)}
        </p>
      )}
      <button
        type="submit"
        disabled={submit.isPending}
        className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-60"
      >
        Set password
      </button>
    </form>
  );
}
