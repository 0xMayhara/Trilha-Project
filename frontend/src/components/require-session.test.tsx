import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

import { RedirectIfSignedIn, RequireSession } from "@/components/require-session";
import { SESSION_QUERY_KEY } from "@/lib/auth";

vi.mock("next/navigation", () => ({ useRouter: () => ({ replace: vi.fn(), push: vi.fn() }) }));

const user = { id: "11111111-1111-4111-8111-111111111111", username: "alice", first_name: "", last_name: "" };

function render(session: unknown, node: React.ReactNode) {
  const client = new QueryClient();
  if (session !== undefined) client.setQueryData(SESSION_QUERY_KEY, session);
  return renderToStaticMarkup(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

describe("session-aware routing (UX only)", () => {
  it("test_login_page_is_hidden_from_signed_in_users", () => {
    const form = <p>login form</p>;
    expect(render(user, <RedirectIfSignedIn>{form}</RedirectIfSignedIn>)).toBe("");
    expect(render(null, <RedirectIfSignedIn>{form}</RedirectIfSignedIn>)).toContain("login form");
    // An unknown session (loading or unavailable) never locks anyone out of the login page.
    expect(render(undefined, <RedirectIfSignedIn>{form}</RedirectIfSignedIn>)).toContain("login form");
  });

  it("keeps protected pages hidden from signed-out users", () => {
    const page = <p>private</p>;
    expect(render(null, <RequireSession>{page}</RequireSession>)).toBe("");
    expect(render(user, <RequireSession>{page}</RequireSession>)).toContain("private");
  });
});
