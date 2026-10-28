"use client";

import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";

import { FindingForm } from "@/components/finding-form";
import { FindingAsset, FindingFacts } from "@/components/finding-table";
import { LogbookEntries } from "@/components/logbook";
import { Button, Notice, PageTitle, Panel } from "@/components/ui";
import { ApiError } from "@/lib/api-client";
import { fieldErrors } from "@/lib/assets";
import { fetchSessionUser, SESSION_QUERY_KEY } from "@/lib/auth";
import {
  fetchFinding,
  fetchLogbook,
  findingErrorMessage,
  findingKey,
  FINDINGS_QUERY_KEY,
  handleFindingError,
  logbookKey,
  lostAccess,
  updateFinding,
  type FindingInput,
} from "@/lib/findings";

function Logbook({ userId, id, onLost }: { userId: string; id: string; onLost: () => void }) {
  const client = useQueryClient();
  // Read-only in slice B: the latest page, then earlier pages on request. No polling yet.
  const logbook = useInfiniteQuery({
    queryKey: logbookKey(userId, id),
    queryFn: ({ pageParam, signal }) => fetchLogbook(id, pageParam, signal),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (page) => (page.has_more_before && page.results[0] ? page.results[0].sequence : undefined),
    staleTime: 0,
  });
  useEffect(() => {
    const error = logbook.error;
    if (!error) return;
    void handleFindingError(client, error, { userId, id }).then(() => {
      if (lostAccess(error)) onLost();
    });
  }, [logbook.error, client, userId, id, onLost]);
  const entries = logbook.data ? [...logbook.data.pages].reverse().flatMap((page) => page.results) : [];
  return (
    <Panel title="Operational Logbook">
      {logbook.isPending && (
        <p role="status" className="m-0 text-ink-muted">
          Loading logbook...
        </p>
      )}
      {logbook.isError && <Notice tone="error">{findingErrorMessage(logbook.error)}</Notice>}
      {logbook.hasNextPage && (
        <div>
          <Button disabled={logbook.isFetchingNextPage} onClick={() => void logbook.fetchNextPage()}>
            Load earlier
          </Button>
        </div>
      )}
      {logbook.data && <LogbookEntries entries={entries} />}
    </Panel>
  );
}
export function FindingDetail({ id }: { id: string }) {
  const client = useQueryClient();
  const [editing, setEditing] = useState(false);
  // After a 403/404 the finding's queries are removed and stay disabled: no refetch, no stale copy.
  const [lost, setLost] = useState(false);
  const markLost = useCallback(() => setLost(true), []);
  const { data: user } = useQuery({ queryKey: SESSION_QUERY_KEY, queryFn: fetchSessionUser });
  const userId = user?.id ?? "";
  const finding = useQuery({
    queryKey: findingKey(userId, id),
    queryFn: ({ signal }) => fetchFinding(id, signal),
    enabled: Boolean(user) && !lost,
    staleTime: 0,
  });
  // Every edit sends the version shown on screen; the server rejects stale ones with 409.
  const save = useMutation({
    mutationFn: ({ input }: { input: FindingInput }) => updateFinding(finding.data!, input),
    onSuccess: async (updated) => {
      client.setQueryData(findingKey(userId, id), updated);
      await client.invalidateQueries({ queryKey: [...FINDINGS_QUERY_KEY, userId, "list"] });
      await client.invalidateQueries({ queryKey: logbookKey(userId, id) });
      setEditing(false);
    },
    onError: (error) => {
      if (lostAccess(error)) markLost();
      return handleFindingError(client, error, { userId, id });
    },
  });
  useEffect(() => {
    const error = finding.error;
    if (!error) return;
    void handleFindingError(client, error, { userId, id }).then(() => {
      if (lostAccess(error)) markLost();
    });
  }, [finding.error, client, userId, id, markLost]);

  if (!user) return null;
  if (lost) return <Notice tone="error">You no longer have access to this finding.</Notice>;
  if (finding.isPending)
    return (
      <p role="status" className="m-0 text-ink-muted">
        Loading finding...
      </p>
    );
  if (finding.isError) return <Notice tone="error">{findingErrorMessage(finding.error)}</Notice>;
  const current = finding.data;
  const conflict = save.error instanceof ApiError && save.error.status === 409;
  return (
    <section className="flex flex-col gap-6" aria-label="Finding">
      <PageTitle>{current.title}</PageTitle>
      <FindingFacts finding={current} />
      {save.isError && (
        <Notice tone="error">
          <p className="m-0">{findingErrorMessage(save.error)}</p>
          {conflict && (
            <div>
              <Button
                onClick={() => {
                  save.reset();
                  void finding.refetch();
                }}
              >
                Reload finding
              </Button>
            </div>
          )}
        </Notice>
      )}
      {current.capabilities.edit && !editing && (
        <div>
          <Button onClick={() => setEditing(true)}>Edit</Button>
        </div>
      )}
      {editing && (
        <FindingForm
          finding={current}
          errors={fieldErrors(save.error)}
          pending={save.isPending}
          submitLabel="Save changes"
          onSubmit={(input) => save.mutate({ input })}
        />
      )}
      <FindingAsset finding={current} />
      <Logbook userId={userId} id={id} onLost={markLost} />
    </section>
  );
}
