"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";

import { ApiError } from "@/lib/api-client";
import { afterReauthentication, reauthenticate, StepUpCancelled, withStepUp } from "@/lib/admin";

type Guard = <T>(run: () => Promise<T>) => Promise<T>;
type Pending = { resolve: () => void; reject: (error: Error) => void };

const StepUpContext = createContext<Guard | null>(null);

/** Runs an administrative request; on 403 `reauthentication_required` it asks for the password once
 * and retries once. The proof itself lives only in the server session (SPEC-0010 BR-07). */
export function useStepUp(): Guard {
  const guard = useContext(StepUpContext);
  if (!guard) throw new Error("useStepUp must be used inside StepUpProvider.");
  return guard;
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const confirm = useCallback(() => new Promise<void>((resolve, reject) => setPending({ resolve, reject })), []);
  const guard = useCallback<Guard>((run) => withStepUp(run, confirm), [confirm]);

  return (
    <StepUpContext.Provider value={guard}>
      {children}
      {pending && (
        <StepUpDialog
          onConfirmed={() => {
            pending.resolve();
            setPending(null);
          }}
          onCancel={() => {
            pending.reject(new StepUpCancelled());
            setPending(null);
          }}
        />
      )}
    </StepUpContext.Provider>
  );
}

function reauthenticationMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.code === "invalid_credentials") return "The password is incorrect.";
    if (error.status === 429) return "Too many attempts. Wait a while and try again.";
    if (error.status === 401) return "Your session has ended. Log in again.";
  }
  return "Could not confirm your password. Try again.";
}

function StepUpDialog({ onConfirmed, onCancel }: { onConfirmed: () => void; onCancel: () => void }) {
  const client = useQueryClient();
  const dialog = useRef<HTMLDialogElement>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = dialog.current;
    // The native modal dialog makes the page behind it inert and handles Escape as "cancel".
    element?.showModal();
    return () => {
      element?.close();
      opener?.focus();
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const password = String(new FormData(form).get("password") ?? "");
    setBusy(true);
    setError(null);
    try {
      // No request may travel with the old session key while it rotates (design review F-08).
      await client.cancelQueries();
      await reauthenticate(password);
      await afterReauthentication(client);
      form.reset();
      onConfirmed();
    } catch (caught) {
      setError(reauthenticationMessage(caught));
      setBusy(false);
    }
  }

  return (
    <dialog
      ref={dialog}
      aria-labelledby="step-up-title"
      className="m-auto w-full max-w-sm rounded border border-neutral-300 p-4 backdrop:bg-black/40"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <form onSubmit={submit} className="space-y-3 text-sm">
        <h2 id="step-up-title" className="text-lg font-semibold">
          Confirm your password
        </h2>
        <p>Administrative changes need a password confirmation in the last 10 minutes.</p>
        <label className="flex flex-col gap-1">
          Password
          <input
            name="password"
            type="password"
            required
            autoFocus
            autoComplete="current-password"
            maxLength={1024}
            aria-invalid={Boolean(error)}
            aria-describedby={error ? "step-up-error" : undefined}
            className="rounded border border-neutral-300 px-2 py-1"
          />
        </label>
        {error && (
          <p id="step-up-error" role="alert" className="text-red-700">
            {error}
          </p>
        )}
        <div className="flex gap-2">
          <button type="submit" disabled={busy} className="rounded bg-neutral-900 px-3 py-1 text-white disabled:opacity-60">
            {busy ? "Confirming..." : "Confirm"}
          </button>
          <button type="button" onClick={onCancel} className="rounded border border-neutral-400 px-3 py-1">
            Cancel
          </button>
        </div>
      </form>
    </dialog>
  );
}
