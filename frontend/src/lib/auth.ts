import { z } from "zod";

import { ApiError, apiFetch } from "@/lib/api-client";
import type { PasswordLink } from "@/lib/password-link";

/** Session authentication client (SPEC-0003). The session lives in an HttpOnly cookie: nothing here
 * stores credentials, and route guards built on it are UX only. */

export const sessionUserSchema = z.object({
  id: z.string(),
  username: z.string(),
  first_name: z.string(),
  last_name: z.string(),
});
export type SessionUser = z.infer<typeof sessionUserSchema>;

export const SESSION_QUERY_KEY = ["auth", "me"] as const;

const noContent = z.undefined();

/** The signed-in user, or null when signed out (401). Other errors propagate. */
export async function fetchSessionUser(): Promise<SessionUser | null> {
  try {
    return await apiFetch("/api/v1/auth/me/", sessionUserSchema);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      return null;
    }
    throw error;
  }
}

/** Anonymous endpoints need the CSRF cookie before the first POST. */
function ensureCsrfCookie(): Promise<undefined> {
  return apiFetch("/api/v1/auth/csrf/", noContent);
}

export async function logIn(username: string, password: string): Promise<SessionUser> {
  await ensureCsrfCookie();
  return apiFetch("/api/v1/auth/login/", sessionUserSchema, {
    method: "POST",
    body: { username, password },
  });
}

export function logOut(): Promise<undefined> {
  return apiFetch("/api/v1/auth/logout/", noContent, { method: "POST" });
}

/** Whether a logout attempt left no server session: it succeeded, or there was none (401). Any
 * other failure means the session may still be valid, so the UI must not claim "signed out". */
export function logoutEndedSession(error: unknown): boolean {
  return !error || (error instanceof ApiError && error.status === 401);
}

export function changePassword(currentPassword: string, newPassword: string): Promise<undefined> {
  return apiFetch("/api/v1/auth/password/change/", noContent, {
    method: "POST",
    body: { current_password: currentPassword, new_password: newPassword },
  });
}

/** The token goes in the JSON body, never in a URL path or query string. */
export async function setPassword(link: PasswordLink, newPassword: string): Promise<undefined> {
  await ensureCsrfCookie();
  return apiFetch("/api/v1/auth/password/set/", noContent, {
    method: "POST",
    body: { uid: link.uid, token: link.token, new_password: newPassword },
  });
}

const fieldErrorsSchema = z.record(z.string(), z.array(z.string()));

/** A message to show for a failed authentication request. */
export function authErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return "Something went wrong. Try again.";
  }
  switch (error.code) {
    case "invalid_credentials":
      return "Invalid username or password.";
    case "invalid_link":
      return "This link is invalid or has expired. Ask an administrator for a new one.";
    case "throttled":
      return "Too many attempts. Wait a while and try again.";
    case "permission_denied":
      return "Your session has expired. Reload the page and try again.";
    case "validation_error": {
      const details = fieldErrorsSchema.safeParse(error.details);
      const messages = details.success ? Object.values(details.data).flat() : [];
      return messages.length > 0 ? messages.join(" ") : "Check the form and try again.";
    }
    default:
      return "Something went wrong. Try again.";
  }
}
