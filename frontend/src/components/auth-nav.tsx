"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { clearOwnAccess } from "@/lib/access";
import { clearAdminQueries, fetchPlatformSelf, platformKey, type PlatformSelf } from "@/lib/admin";
import { clearAssetQueries } from "@/lib/assets";

import {
  authErrorMessage,
  fetchSessionUser,
  logOut,
  logoutEndedSession,
  SESSION_QUERY_KEY,
} from "@/lib/auth";

/** Shown from the server's platform state only; hiding it is UX, the API decides (SEC-32). */
export function AdministrationLink({ platform }: { platform: PlatformSelf | undefined }) {
  return platform?.is_admin === true ? (
    <Link href="/admin" className="underline">
      Administration
    </Link>
  ) : null;
}

export function AuthNav() {
  const router = useRouter();
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
      await clearAdminQueries(queryClient);
      queryClient.setQueryData(SESSION_QUERY_KEY, null);
      router.push("/login");
    },
  });

  if (user === undefined) {
    return null;
  }
  if (user === null) {
    return (
      <Link href="/login" className="text-sm underline">
        Log in
      </Link>
    );
  }
  return (
    <div className="flex items-center gap-4 text-sm">
      <span className="text-neutral-600">Signed in as {user.username}</span>
      <AdministrationLink platform={platform.data} />
      <Link href="/assets" className="underline">Assets</Link>
      <Link href="/account/access" className="underline">Your access</Link>
      <Link href="/account/password" className="underline">
        Change password
      </Link>
      <button
        type="button"
        className="underline"
        disabled={logout.isPending}
        onClick={() => logout.mutate()}
      >
        Log out
      </button>
      {logout.isError && (
        <span role="alert" className="text-red-700">
          {authErrorMessage(logout.error)}
        </span>
      )}
    </div>
  );
}
