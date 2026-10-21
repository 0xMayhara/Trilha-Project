"use client";

import dynamic from "next/dynamic";

// Browser only: the form reads uid and token from the URL fragment, which servers never see.
export const SetPasswordLoader = dynamic(() => import("@/components/set-password-form"), {
  ssr: false,
});
