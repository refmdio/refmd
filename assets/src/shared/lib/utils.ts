import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const omniMonoText = {
  compact: "font-mono text-[10px] uppercase tracking-[0.24em]",
  base: "font-mono text-[10px] uppercase tracking-[0.28em]",
  wide: "font-mono text-[10px] uppercase tracking-[0.32em]",
  section: "font-mono text-xs uppercase tracking-[0.32em]",
  menu: "font-mono text-[11px] uppercase tracking-[0.28em]",
} as const;
