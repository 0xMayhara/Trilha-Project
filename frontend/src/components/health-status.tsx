"use client";

import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

import { apiFetch } from "@/lib/api-client";

const healthSchema = z.object({ status: z.literal("ok") });

export function HealthStatus() {
  const { data, isPending, isError } = useQuery({
    queryKey: ["health", "live"],
    queryFn: () => apiFetch("/api/v1/health/live/", healthSchema),
  });

  if (isPending) {
    return <p className="text-sm text-neutral-500">Checking API…</p>;
  }
  if (isError) {
    return (
      <p role="alert" className="text-sm text-red-700">
        API unavailable.
      </p>
    );
  }
  return <p className="text-sm text-green-700">API status: {data.status}</p>;
}
