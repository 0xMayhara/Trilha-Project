"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";

import { authErrorMessage, logIn, SESSION_QUERY_KEY } from "@/lib/auth";

const inputClass = "rounded border border-neutral-300 px-3 py-2";

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
    <form onSubmit={onSubmit} className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-sm">
        Username
        <input name="username" autoComplete="username" required maxLength={150} className={inputClass} />
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Password
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={1024}
          className={inputClass}
        />
      </label>
      {login.isError && (
        <p role="alert" className="text-sm text-red-700">
          {authErrorMessage(login.error)}
        </p>
      )}
      <button
        type="submit"
        disabled={login.isPending}
        className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-60"
      >
        Log in
      </button>
    </form>
  );
}
