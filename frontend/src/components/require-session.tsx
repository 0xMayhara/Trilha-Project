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
