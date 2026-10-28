"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";

import { Button, Field, Form, Input, Notice } from "@/components/ui";
import { authErrorMessage, logIn, SESSION_QUERY_KEY } from "@/lib/auth";

export function LoginForm() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const login = useMutation({
    mutationFn: (form: FormData) =>
      logIn(String(form.get("username") ?? ""), String(form.get("password") ?? "")),
    onSuccess: (user) => {
      queryClient.setQueryData(SESSION_QUERY_KEY, user);
      router.push("/");
    },
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    login.mutate(new FormData(event.currentTarget));
  }

  return (
    <Form onSubmit={onSubmit} className="max-w-none">
      <Field label="Username">
        <Input name="username" autoComplete="username" required maxLength={150} />
      </Field>
      <Field label="Password">
        <Input name="password" type="password" autoComplete="current-password" required maxLength={1024} />
      </Field>
      {login.isError && <Notice tone="error">{authErrorMessage(login.error)}</Notice>}
      <Button type="submit" variant="primary" disabled={login.isPending}>
        Log in
      </Button>
    </Form>
  );
}
