import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { ApiError, apiFetch, readCookie } from "./api-client";

const okSchema = z.object({ status: z.literal("ok") });

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("apiFetch", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    vi.stubGlobal("document", { cookie: "theme=dark; csrftoken=t0ken%2Bvalue" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
  });

  function sentInit(): RequestInit {
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init).toBeDefined();
    return init as RequestInit;
  }

  it.each(["POST", "PUT", "PATCH", "DELETE"])("sends the CSRF header on %s", async (method) => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: "ok" }));

    await apiFetch("/api/v1/resource/", okSchema, { method, body: { a: 1 } });

    const headers = new Headers(sentInit().headers);
    expect(headers.get("X-CSRFToken")).toBe("t0ken+value");
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("does not send the CSRF header on GET", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: "ok" }));

    await apiFetch("/api/v1/health/live/", okSchema);

    expect(new Headers(sentInit().headers).has("X-CSRFToken")).toBe(false);
  });

  it("always uses same-origin credentials", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: "ok" }));

    await apiFetch("/api/v1/health/live/", okSchema, { method: "POST" });

    expect(sentInit().credentials).toBe("same-origin");
  });

  it.each(["https://evil.example/api/v1/", "//evil.example/api/v1/", "api/v1/", "/other/"])(
    "refuses non same-origin API path %s",
    async (path) => {
      await expect(apiFetch(path, okSchema)).rejects.toThrow(/same-origin/);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("parses the error envelope into an ApiError", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(400, {
        error: {
          code: "validation_error",
          message: "Invalid input.",
          details: { name: ["Too long."] },
          request_id: "6b0c0b7e-1f1a-4c4e-9a43-6c2b1f0f6a11",
        },
      }),
    );

    const error = await apiFetch("/api/v1/x/", okSchema).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 400,
      code: "validation_error",
      message: "Invalid input.",
      details: { name: ["Too long."] },
      requestId: "6b0c0b7e-1f1a-4c4e-9a43-6c2b1f0f6a11",
    });
  });

  it("handles a malformed error body", async () => {
    fetchMock.mockResolvedValue(new Response("<html>Bad gateway</html>", { status: 502 }));

    const error = await apiFetch("/api/v1/x/", okSchema).catch((caught: unknown) => caught);

    expect(error).toMatchObject({ status: 502, code: "unexpected_response" });
  });

  it("rejects a success payload that does not match the schema", async () => {
    fetchMock.mockResolvedValue(jsonResponse(200, { status: "<script>" }));

    const error = await apiFetch("/api/v1/x/", okSchema).catch((caught: unknown) => caught);

    expect(error).toMatchObject({ status: 200, code: "invalid_response" });
  });
});

describe("readCookie", () => {
  it("returns undefined for a missing cookie", () => {
    expect(readCookie("csrftoken", "theme=dark")).toBeUndefined();
  });
});
