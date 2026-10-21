import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "./api-client";
import {
  authErrorMessage,
  changePassword,
  fetchSessionUser,
  logIn,
  logOut,
  logoutEndedSession,
  setPassword,
} from "./auth";

const user = { id: "6f1d…", username: "alice", first_name: "", last_name: "" };

function jsonResponse(status: number, body?: unknown): Response {
  return body === undefined
    ? new Response(null, { status })
    : new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

describe("session authentication client", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "csrftoken=t0ken" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  function calls(): { url: string; method: string; body: unknown; headers: Headers }[] {
    return fetchMock.mock.calls.map(([url, init]) => ({
      url: String(url),
      method: init?.method ?? "GET",
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
      headers: new Headers(init?.headers),
    }));
  }

  it("fetches the CSRF cookie before logging in and sends the token", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse(204)).mockResolvedValueOnce(jsonResponse(200, user));

    await expect(logIn("alice", "pw")).resolves.toEqual(user);

    const [csrf, login] = calls();
    expect(csrf).toMatchObject({ url: "/api/v1/auth/csrf/", method: "GET" });
    expect(login).toMatchObject({
      url: "/api/v1/auth/login/",
      method: "POST",
      body: { username: "alice", password: "pw" },
    });
    expect(login!.headers.get("X-CSRFToken")).toBe("t0ken");
  });

  it("reports a signed-out visitor as null and other failures as errors", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonResponse(401, { error: { code: "not_authenticated", message: "x" } }),
    );
    await expect(fetchSessionUser()).resolves.toBeNull();

    fetchMock.mockResolvedValueOnce(jsonResponse(200, user));
    await expect(fetchSessionUser()).resolves.toEqual(user);

    fetchMock.mockResolvedValueOnce(jsonResponse(500, { error: { code: "server_error", message: "x" } }));
    await expect(fetchSessionUser()).rejects.toBeInstanceOf(ApiError);
  });

  it("posts the link token in the body, never in the URL", async () => {
    fetchMock.mockResolvedValue(jsonResponse(204));

    await setPassword({ uid: "MTIz", token: "secret-token" }, "a-new-passphrase");

    const [, submit] = calls();
    expect(submit).toMatchObject({
      url: "/api/v1/auth/password/set/",
      method: "POST",
      body: { uid: "MTIz", token: "secret-token", new_password: "a-new-passphrase" },
    });
    for (const call of calls()) {
      expect(call.url).not.toContain("secret-token");
    }
  });

  it("logs out and changes the password with CSRF-protected POSTs", async () => {
    fetchMock.mockResolvedValue(jsonResponse(204));

    await logOut();
    await changePassword("old-pass", "new-pass");

    const [logout, change] = calls();
    expect(logout).toMatchObject({ url: "/api/v1/auth/logout/", method: "POST" });
    expect(change).toMatchObject({
      url: "/api/v1/auth/password/change/",
      body: { current_password: "old-pass", new_password: "new-pass" },
    });
    expect(change!.headers.get("X-CSRFToken")).toBe("t0ken");
  });
});

describe("authErrorMessage", () => {
  it.each([
    ["invalid_credentials", "Invalid username or password."],
    ["invalid_link", "This link is invalid or has expired. Ask an administrator for a new one."],
    ["throttled", "Too many attempts. Wait a while and try again."],
    ["permission_denied", "Your session has expired. Reload the page and try again."],
    ["server_error", "Something went wrong. Try again."],
  ])("explains %s", (code, message) => {
    expect(authErrorMessage(new ApiError(400, code, "server text"))).toBe(message);
  });

  it("lists validation messages from the server", () => {
    const error = new ApiError(400, "validation_error", "Invalid input.", {
      new_password: ["This password is too common."],
    });

    expect(authErrorMessage(error)).toBe("This password is too common.");
  });

  it("does not trust non-API errors", () => {
    expect(authErrorMessage(new Error("boom"))).toBe("Something went wrong. Try again.");
  });
});

describe("logoutEndedSession", () => {
  it("is true after a successful logout or when there was no session", () => {
    expect(logoutEndedSession(null)).toBe(true);
    expect(logoutEndedSession(new ApiError(401, "not_authenticated", "x"))).toBe(true);
  });

  it.each([
    ["CSRF rejection", new ApiError(403, "permission_denied", "x")],
    ["server error", new ApiError(503, "service_unavailable", "x")],
    ["network failure", new TypeError("Failed to fetch")],
  ])("is false after a %s, when the session may still be valid", (_name, error) => {
    expect(logoutEndedSession(error)).toBe(false);
  });
});
