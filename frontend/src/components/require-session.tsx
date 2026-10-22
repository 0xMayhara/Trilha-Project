"use client";

import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";

import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

/** Sends signed-out visitors to the login page. UX only: the API enforces every check. */
export function RequireSession({ children }: { children: ReactNode }) {
  const router = useRouter();
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });

  useEffect(() => {
    if (user === null) {
      router.replace("/login");
    }
  }, [user, router]);

  return user ? children : null;
}

/** Sends signed-in visitors away from pages meant for signed-out users, such as the login page.
 * While the session is unknown (loading or unavailable) the page still renders. UX only. */
export function RedirectIfSignedIn({ children, to = "/" }: { children: ReactNode; to?: string }) {
  const router = useRouter();
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });

  useEffect(() => {
    if (user) {
      router.replace(to);
    }
  }, [user, router, to]);

  return user ? null : children;
}
