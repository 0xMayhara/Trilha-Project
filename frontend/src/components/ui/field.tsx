import {
  cloneElement,
  forwardRef,
  isValidElement,
  useId,
  type InputHTMLAttributes,
  type ReactElement,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";

import { cn } from "@/lib/utils";

const CONTROL =
  "min-w-0 rounded-sm border border-border-strong bg-surface px-2.5 py-[5px] text-body font-normal text-ink [&[readonly]]:bg-surface-sunken aria-[invalid=true]:border-2 aria-[invalid=true]:border-danger aria-[invalid=true]:px-[9px] aria-[invalid=true]:py-[4px]";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input(
  { className, ...props },
  ref,
) {
  return <input ref={ref} className={cn(CONTROL, className)} {...props} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select(
  { className, ...props },
  ref,
) {
  return <select ref={ref} className={cn(CONTROL, className)} {...props} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea(
  { className, ...props },
  ref,
) {
  return <textarea ref={ref} className={cn(CONTROL, "resize-y", className)} {...props} />;
});

type Described = { "aria-invalid"?: boolean; "aria-describedby"?: string };

/** Label above, control below, help and error last. The label wraps the control, so it is always visible. */
export function Field({
  label,
  help,
  error,
  className,
  children,
}: {
  label: ReactNode;
  help?: ReactNode;
  /** The server's message, starting with the field name: `Hostname: Enter a valid DNS name.` */
  error?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const id = useId();
  const ids = [help ? `${id}-help` : null, error ? `${id}-error` : null].filter(Boolean).join(" ");
  const control = isValidElement<Described>(children)
    ? cloneElement(children as ReactElement<Described>, {
        "aria-invalid": error ? true : children.props["aria-invalid"],
        "aria-describedby": ids || undefined,
      })
    : children;
  return (
    <label className={cn("flex flex-col gap-1 text-label", className)}>
      {label}
      {control}
      {help ? (
        <span id={`${id}-help`} className="text-small font-normal text-ink-muted">
          {help}
        </span>
      ) : null}
      {error ? (
        <span id={`${id}-error`} className="text-small font-semibold text-danger">
          {error}
        </span>
      ) : null}
    </label>
  );
}

/** A native form: fields stacked, 576px at most. The server validates; this only lays out. */
export function Form({ className, ...props }: React.FormHTMLAttributes<HTMLFormElement>) {
  return <form className={cn("flex max-w-xl flex-col gap-3", className)} {...props} />;
}
