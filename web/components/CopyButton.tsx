"use client";

import { useCallback, useRef, useState } from "react";
import { CheckIcon, CopyIcon } from "./icons";

type CopyButtonProps = {
  value: string;
  label?: string;
  title?: string;
  className?: string;
  /** When true, render text label beside the icon. */
  withText?: boolean;
};

export default function CopyButton({
  value,
  label = "Copy",
  title,
  className = "",
  withText = false,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1400);
    } catch {
      /* clipboard unavailable — no-op */
    }
  }, [value]);

  return (
    <button
      type="button"
      onClick={onCopy}
      title={title ?? label}
      aria-label={title ?? label}
      className={`inline-flex items-center gap-1.5 transition-colors ${
        copied ? "text-live" : "text-fg-faint hover:text-accent"
      } ${className}`}
    >
      {copied ? (
        <CheckIcon className="h-4 w-4" />
      ) : (
        <CopyIcon className="h-4 w-4" />
      )}
      {withText && (
        <span className="text-xs font-medium">
          {copied ? "Copied" : label}
        </span>
      )}
    </button>
  );
}
