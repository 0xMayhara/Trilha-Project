"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { AccessEntries } from "@/components/access-entries";
import { accessErrorMessage, accessQueryKey, fetchOwnAccess, handleAccessError } from "@/lib/access";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";

export function OwnAccess() {
  const client = useQueryClient();
  const [page, setPage] = useState(1);
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const access = useQuery({
    queryKey: accessQueryKey(user?.id ?? "", page),
    queryFn: ({ signal }) => fetchOwnAccess(page, signal),
    enabled: Boolean(user),
    staleTime: 0,
  });
  useEffect(() => {
    if (access.error) void handleAccessError(client, access.error);
  }, [access.error, client]);

  if (!user) return null;
  return (
    <section className="space-y-4" aria-label="Your team access">
      <p>Access is grouped by team. The server checks current permissions for every action.</p>
      <button type="button" className="underline" onClick={() => void access.refetch()}>Refresh access</button>
      {access.isPending && <p role="status">Loading access…</p>}
      {access.isError ? <p role="alert">{accessErrorMessage(access.error)}</p> : access.data && (
        <>
          <AccessEntries entries={access.data.results} />
          <nav className="flex gap-4" aria-label="Access pages">
            <button type="button" disabled={!access.data.previous} onClick={() => setPage(page - 1)}>Previous</button>
            <span>Page {page}</span>
            <button type="button" disabled={!access.data.next} onClick={() => setPage(page + 1)}>Next</button>
          </nav>
        </>
      )}
    </section>
  );
}
