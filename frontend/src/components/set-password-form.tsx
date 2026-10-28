"use client";

import { useMutation } from "@tanstack/react-query";
import Link from "next/link";
import { useEffect, useState, type FormEvent } from "react";

import { NewPasswordFields, readNewPassword } from "@/components/new-password-fields";
import { Button, Form, Notice } from "@/components/ui";
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
      <Notice tone="error">This link is incomplete. Ask an administrator for a new one.</Notice>
    );
  }
  if (submit.isSuccess) {
    return (
      <Notice tone="success">
        <p className="m-0">
          Your password is set. <Link href="/login">Log in</Link>.
        </p>
      </Notice>
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
    <Form onSubmit={onSubmit} className="max-w-none">
      <NewPasswordFields mismatch={mismatch} />
      {submit.isError && <Notice tone="error">{authErrorMessage(submit.error)}</Notice>}
      <Button type="submit" variant="primary" disabled={submit.isPending}>
        Set password
      </Button>
    </Form>
  );
}
