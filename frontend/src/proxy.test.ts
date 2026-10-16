import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { config, proxy } from "./proxy";

const matcher = new RegExp(`^${config.matcher[0]!.source}$`);

describe("proxy content security policy", () => {
  it("sets a nonce-based policy without unsafe-eval outside development", () => {
    const response = proxy(new NextRequest("http://localhost/"));

    const policy = response.headers.get("Content-Security-Policy") ?? "";
    expect(policy).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
    expect(policy).not.toContain("unsafe-eval");
    expect(policy).toContain("frame-ancestors 'none'");
  });

  it("uses a fresh nonce per request", () => {
    const first = proxy(new NextRequest("http://localhost/")).headers.get("Content-Security-Policy");
    const second = proxy(new NextRequest("http://localhost/")).headers.get("Content-Security-Policy");

    expect(first).not.toBe(second);
  });

  it.each(["/", "/remediations", "/api-keys", "/apis/overview"])("applies to page %s", (path) => {
    expect(matcher.test(path)).toBe(true);
  });

  it.each(["/api/v1/health/live/", "/_next/static/chunk.js", "/favicon.ico"])(
    "skips non-page path %s",
    (path) => {
      expect(matcher.test(path)).toBe(false);
    },
  );
});
