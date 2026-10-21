const inputClass = "rounded border border-neutral-300 px-3 py-2";

/** New password and its confirmation. The server applies the password rules; this only catches
 * typos before submitting. */
export function NewPasswordFields() {
  return (
    <>
      <label className="flex flex-col gap-1 text-sm">
        New password
        <input
          name="new_password"
          type="password"
          autoComplete="new-password"
          required
          minLength={12}
          maxLength={1024}
          className={inputClass}
        />
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Repeat the new password
        <input
          name="confirm_password"
          type="password"
          autoComplete="new-password"
          required
          maxLength={1024}
          className={inputClass}
        />
      </label>
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
