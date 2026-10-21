"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useRouter } from "next/navigation";

import { fetchSessionUser, logOut, SESSION_QUERY_KEY } from "@/lib/auth";

export function AuthNav() {
  const router = useRouter();
  const queryClient = useQueryClient();
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const logout = useMutation({
    mutationFn: logOut,
    onSettled: () => {
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
    </div>
  );
}
