import { describe, expect, it, vi } from "vitest";

import { readPasswordLink, removeFragment } from "./password-link";

describe("readPasswordLink", () => {
  it("reads uid and token from the fragment", () => {
    expect(readPasswordLink("#uid=MTIz&token=abc-def")).toEqual({ uid: "MTIz", token: "abc-def" });
  });

  it.each(["", "#", "#uid=MTIz", "#token=abc", "#uid=&token=abc"])(
    "rejects an incomplete fragment %j",
    (hash) => {
      expect(readPasswordLink(hash)).toBeNull();
    },
  );
});

describe("removeFragment", () => {
  it("removes uid and token from the address bar and history", () => {
    const history = { replaceState: vi.fn() };

    removeFragment({ hash: "#uid=MTIz&token=secret", pathname: "/set-password", search: "" }, history);

    expect(history.replaceState).toHaveBeenCalledExactlyOnceWith(null, "", "/set-password");
    expect(JSON.stringify(history.replaceState.mock.calls)).not.toContain("secret");
  });

  it("leaves an address without a fragment alone", () => {
    const history = { replaceState: vi.fn() };

    removeFragment({ hash: "", pathname: "/set-password", search: "" }, history);

    expect(history.replaceState).not.toHaveBeenCalled();
  });
});
