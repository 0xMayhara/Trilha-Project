"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect } from "react";

import { AppHeader, Notice, type NavKey } from "@/components/ui";
import { clearOwnAccess } from "@/lib/access";
import { clearAdminQueries, fetchPlatformSelf, platformKey, type PlatformSelf } from "@/lib/admin";
import { clearAssetQueries } from "@/lib/assets";
import { clearFindingQueries } from "@/lib/findings";

import {
  authErrorMessage,
  fetchSessionUser,
  logOut,
  logoutEndedSession,
  SESSION_QUERY_KEY,
} from "@/lib/auth";

const SECTIONS: [prefix: string, key: NavKey][] = [
  ["/admin", "admin"],
  ["/assets", "assets"],
  ["/findings", "findings"],
  ["/account/access", "access"],
  ["/account/password", "password"],
];

function navKey(pathname: string): NavKey | undefined {
  return SECTIONS.find(([prefix]) => pathname === prefix || pathname.startsWith(`${prefix}/`))?.[1];
}

/** Administration is shown from the server's platform state only; hiding it is UX, the API decides (SEC-32). */
export function SiteHeader({
  username,
  platform,
  current,
  onLogout,
}: {
  username: string | null;
  platform: PlatformSelf | undefined;
  current?: NavKey;
  onLogout?: () => void;
}) {
  return (
    <AppHeader
      username={username}
      isAdmin={platform?.is_admin === true}
      current={current}
      LinkComponent={Link}
      onLogout={onLogout}
    />
  );
}

export function AuthNav() {
  const router = useRouter();
  const pathname = usePathname();
  const queryClient = useQueryClient();
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const platform = useQuery({
    queryKey: platformKey(user?.id ?? ""),
    queryFn: ({ signal }) => fetchPlatformSelf(signal),
    enabled: Boolean(user),
  });
  useEffect(() => {
    if (user === null) {
      void clearOwnAccess(queryClient);
      void clearAssetQueries(queryClient);
      void clearFindingQueries(queryClient);
      void clearAdminQueries(queryClient);
    }
  }, [user, queryClient]);
  const logout = useMutation({
    mutationFn: logOut,
    onSettled: async (_data, error) => {
      // Show "signed out" only when the server session is gone; otherwise re-read the real state.
      if (!logoutEndedSession(error)) {
        await queryClient.invalidateQueries({ queryKey: SESSION_QUERY_KEY });
        return;
      }
      await clearOwnAccess(queryClient);
      await clearAssetQueries(queryClient);
      await clearFindingQueries(queryClient);
      await clearAdminQueries(queryClient);
      queryClient.setQueryData(SESSION_QUERY_KEY, null);
      router.push("/login");
    },
  });

  if (user === undefined) {
    return null;
  }
  return (
    <>
      <SiteHeader
        username={user?.username ?? null}
        platform={platform.data}
        current={navKey(pathname)}
        onLogout={() => {
          // AppHeader has no disabled state, so a second click while pending is ignored here.
          if (!logout.isPending) logout.mutate();
        }}
      />
      {logout.isError && (
        <div className="mx-auto max-w-6xl px-8 pt-4">
          <Notice tone="error">{authErrorMessage(logout.error)}</Notice>
        </div>
      )}
    </>
  );
}
