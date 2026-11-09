export function utc(iso: string | null): string {
  if (!iso) return "unknown";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : `${date.toISOString().replace("T", " ").slice(0, 19)} UTC`;
}

export const bytes = (count: number): string => `${count.toLocaleString("en-GB")} bytes`;
