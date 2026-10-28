"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { AccessEntries } from "@/components/access-entries";
import { Button, Notice } from "@/components/ui";
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
    <section className="flex flex-col gap-6" aria-label="Your team access">
      <p className="m-0">Access is grouped by team. The server checks current permissions for every action.</p>
      <div>
        <Button variant="link" onClick={() => void access.refetch()}>
          Refresh access
        </Button>
      </div>
      {access.isPending && (
        <p role="status" className="m-0 text-ink-muted">
          Loading access…
        </p>
      )}
      {access.isError ? (
        <Notice tone="error">{accessErrorMessage(access.error)}</Notice>
      ) : (
        access.data && (
          <>
            <AccessEntries entries={access.data.results} />
            {/* The access API returns no total, so this pager shows the page number only. */}
            <nav className="flex items-center gap-4 text-small" aria-label="Access pages">
              <Button variant="link" disabled={!access.data.previous} onClick={() => setPage(page - 1)}>
                Previous
              </Button>
              <span>Page {page}</span>
              <Button variant="link" disabled={!access.data.next} onClick={() => setPage(page + 1)}>
                Next
              </Button>
            </nav>
          </>
        )
      )}
    </section>
  );
}
