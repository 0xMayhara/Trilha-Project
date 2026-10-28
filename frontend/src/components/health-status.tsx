"use client";

import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import { Badge } from "@/components/ui";
import { apiFetch } from "@/lib/api-client";

const healthSchema = z.object({ status: z.literal("ok") });

export function HealthStatus() {
  const { data, isPending, isError } = useQuery({
    queryKey: ["health", "live"],
    queryFn: () => apiFetch("/api/v1/health/live/", healthSchema),
  });

  if (isPending) {
    return (
      <p role="status" className="m-0 text-ink-muted">
        Checking API…
      </p>
    );
  }
  if (isError) {
    return (
      <p role="alert" className="m-0">
        <Badge tone="warn">Unavailable</Badge> API unavailable.
      </p>
    );
  }
  return (
    <p className="m-0">
      <Badge tone="ok">OK</Badge> API status: {data.status}
    </p>
  );
}
