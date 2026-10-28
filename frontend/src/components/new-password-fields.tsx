import { Field, Input } from "@/components/ui";

/** New password and its confirmation. The server applies the password rules; this only catches
 * typos before submitting. */
export function NewPasswordFields({ mismatch }: { mismatch?: string | null }) {
  return (
    <>
      <Field label="New password" help="At least 12 characters.">
        <Input name="new_password" type="password" autoComplete="new-password" required minLength={12} maxLength={1024} />
      </Field>
      <Field label="Repeat the new password" error={mismatch}>
        <Input name="confirm_password" type="password" autoComplete="new-password" required maxLength={1024} />
      </Field>
    </>
  );
}

/** The new password, or an error message when the two entries differ. */
export function readNewPassword(form: FormData): { password: string } | { mismatch: string } {
  const password = String(form.get("new_password") ?? "");
  if (password !== String(form.get("confirm_password") ?? "")) {
    return { mismatch: "The two passwords do not match." };
  }
  return { password };
}
