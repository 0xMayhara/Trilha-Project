"use client";

import { useEffect, useId, useRef, type ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Native modal `<dialog>`, used only to ask for the password again before an administrative change.
 * The page behind goes inert, Escape calls `onCancel`, and focus returns to the opener.
 * `modal={false}` renders it open in place, for previews and mocks.
 */
export function Dialog({
  title,
  onCancel,
  modal = true,
  className,
  children,
}: {
  title: ReactNode;
  onCancel?: () => void;
  modal?: boolean;
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    if (!modal) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const element = ref.current;
    element?.showModal();
    return () => {
      element?.close();
      opener?.focus();
    };
  }, [modal]);

  return (
    <dialog
      ref={ref}
      open={modal ? undefined : true}
      aria-labelledby={titleId}
      onCancel={(event) => {
        event.preventDefault();
        onCancel?.();
      }}
      className={cn(
        "m-auto w-full max-w-sm rounded-md border border-border-strong bg-surface p-4 text-ui text-ink backdrop:bg-ink/55",
        !modal && "static m-0",
        className,
      )}
    >
      <div className="flex flex-col gap-3">
        <h2 id={titleId} className="m-0 text-heading">
          {title}
        </h2>
        {children}
      </div>
    </dialog>
  );
}
