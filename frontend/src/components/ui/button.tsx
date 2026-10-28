import { forwardRef, type ButtonHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export type ButtonVariant = "primary" | "secondary" | "link";

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    "inline-block cursor-pointer rounded-sm border border-brand bg-brand px-3 py-[5px] text-ui font-semibold text-on-brand no-underline hover:border-brand-strong hover:bg-brand-strong disabled:cursor-default disabled:opacity-55 disabled:hover:border-brand disabled:hover:bg-brand",
  secondary:
    "inline-block cursor-pointer rounded-sm border border-border-strong bg-surface px-3 py-[5px] text-ui font-semibold text-ink no-underline hover:bg-surface-sunken disabled:cursor-default disabled:opacity-55 disabled:hover:bg-surface",
  link: "cursor-pointer border-0 bg-transparent p-0 text-brand underline disabled:cursor-default disabled:no-underline disabled:opacity-55",
};

/** Classes of a button, for a `<Link>` or `<a>` that must look like one: `<Link className={buttonClasses("primary")}>`. */
export function buttonClasses(variant: ButtonVariant = "secondary", className?: string) {
  return cn(VARIANTS[variant], className);
}

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant };

/** One `primary` per form or confirmation. Destructive actions stay `secondary` and ask for confirmation in a `Notice`. */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", type = "button", className, ...props },
  ref,
) {
  return <button ref={ref} type={type} className={buttonClasses(variant, className)} {...props} />;
});
