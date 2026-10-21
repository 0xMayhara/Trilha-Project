/** One-time set-password links (SPEC-0003 SEC-14). The CLI prints
 * `<base>/set-password#uid=…&token=…`. The fragment never reaches a server, and this page removes it
 * from the address bar and history as soon as it has been read. */

export type PasswordLink = { uid: string; token: string };

export function readPasswordLink(hash: string): PasswordLink | null {
  const params = new URLSearchParams(hash.replace(/^#/, ""));
  const uid = params.get("uid");
  const token = params.get("token");
  return uid && token ? { uid, token } : null;
}

export function removeFragment(
  location: Pick<Location, "hash" | "pathname" | "search">,
  history: Pick<History, "replaceState">,
): void {
  if (location.hash) {
    history.replaceState(null, "", location.pathname + location.search);
  }
}
