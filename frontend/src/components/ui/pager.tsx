import { Button } from "./button";

/** Previous, `Page N (total label)`, Next. The buttons stay and disable at the ends. */
export function Pager({
  label,
  page,
  count,
  hasPrevious,
  hasNext,
  onPage,
}: {
  label: string;
  page: number;
  count: number;
  hasPrevious: boolean;
  hasNext: boolean;
  onPage?: (page: number) => void;
}) {
  return (
    <nav className="flex items-center gap-4 text-small" aria-label={`${label} pages`}>
      <Button variant="link" disabled={!hasPrevious} onClick={() => onPage?.(page - 1)}>
        Previous
      </Button>
      <span>
        Page {page} ({count} {label})
      </span>
      <Button variant="link" disabled={!hasNext} onClick={() => onPage?.(page + 1)}>
        Next
      </Button>
    </nav>
  );
}
