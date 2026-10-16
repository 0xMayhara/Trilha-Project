"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";

import { ApiError } from "@/lib/api-client";

function shouldRetry(failureCount: number, error: unknown): boolean {
  // Client errors (validation, auth, permission, not found) do not succeed on retry.
  if (error instanceof ApiError && error.status < 500) {
    return false;
  }
  return failureCount < 2;
}

export function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: shouldRetry, staleTime: 30_000 } },
      }),
  );

  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
