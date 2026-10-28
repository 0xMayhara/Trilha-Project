"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useState, type FormEvent, type ReactNode } from "react";

import { Button, Dialog, Field, Input } from "@/components/ui";
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
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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

  // The native modal dialog makes the page behind it inert, handles Escape as "cancel" and returns focus.
  return (
    <Dialog title="Confirm your password" onCancel={onCancel}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <p className="m-0">Administrative changes need a password confirmation in the last 10 minutes.</p>
        <Field label="Password" error={error ? <span role="alert">{error}</span> : undefined}>
          <Input name="password" type="password" required autoFocus autoComplete="current-password" maxLength={1024} />
        </Field>
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? "Confirming..." : "Confirm"}
          </Button>
          <Button onClick={onCancel}>Cancel</Button>
        </div>
      </form>
    </Dialog>
  );
}
