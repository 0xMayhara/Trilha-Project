import { z } from "zod";

/** Same-origin JSON client for the Django API (SPEC-0001 SEC-21). */

export const CSRF_COOKIE_NAME = "csrftoken";
const CSRF_HEADER_NAME = "X-CSRFToken";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS", "TRACE"]);

const errorEnvelopeSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.unknown().optional(),
    request_id: z.string().optional(),
  }),
});

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
    readonly requestId?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type ApiRequestInit = Omit<RequestInit, "body" | "credentials"> & { body?: unknown };

export function readCookie(name: string, cookies?: string): string | undefined {
  const source = cookies ?? (typeof document === "undefined" ? "" : document.cookie);
  for (const part of source.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (rawName === name) {
      return decodeURIComponent(rawValue.join("="));
    }
  }
  return undefined;
}

export async function apiFetch<T>(
  path: string,
  schema: z.ZodType<T>,
  init: ApiRequestInit = {},
): Promise<T> {
  // Credentials and the CSRF token must never be sent to another origin.
  if (!path.startsWith("/api/")) {
    throw new Error("apiFetch only accepts same-origin paths starting with /api/.");
  }

  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");

  let body: string | undefined;
  if (init.body !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.body);
  }

  if (!SAFE_METHODS.has(method)) {
    const csrfToken = readCookie(CSRF_COOKIE_NAME);
    if (csrfToken) {
      headers.set(CSRF_HEADER_NAME, csrfToken);
    }
  }

  const response = await fetch(path, {
    ...init,
    method,
    headers,
    body,
    credentials: "same-origin",
  });

  if (!response.ok) {
    throw await toApiError(response);
  }

  const payload: unknown = response.status === 204 ? undefined : await response.json();
  const parsed = schema.safeParse(payload);
  if (!parsed.success) {
    throw new ApiError(response.status, "invalid_response", "Unexpected response from the server.");
  }
  return parsed.data;
}

async function toApiError(response: Response): Promise<ApiError> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }

  const parsed = errorEnvelopeSchema.safeParse(payload);
  if (!parsed.success) {
    return new ApiError(response.status, "unexpected_response", "Unexpected response from the server.");
  }
  const { code, message, details, request_id: requestId } = parsed.data.error;
  return new ApiError(response.status, code, message, details, requestId);
}
