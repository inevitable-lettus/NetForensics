// Small stroke icons drawn inline (no icon dependency). 1.5px stroke throughout.
type Props = { className?: string };
const base = { width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
  strokeWidth: 1.5, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };

export const CheckIcon = ({ className }: Props) => (
  <svg {...base} className={className}><path d="M5 12.5l4.5 4.5L19 7.5" /></svg>
);
export const CrossIcon = ({ className }: Props) => (
  <svg {...base} className={className}><path d="M6.5 6.5l11 11M17.5 6.5l-11 11" /></svg>
);
export const ClockIcon = ({ className }: Props) => (
  <svg {...base} className={className}><circle cx="12" cy="12" r="8.5" /><path d="M12 7.5V12l3 2" /></svg>
);
export const ShieldIcon = ({ className }: Props) => (
  <svg {...base} className={className}><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6L12 3z" /></svg>
);
export const UploadIcon = ({ className }: Props) => (
  <svg {...base} className={className}><path d="M12 16V4.5M7.5 9L12 4.5 16.5 9M4.5 15v3.5a1 1 0 001 1h13a1 1 0 001-1V15" /></svg>
);
export const FileIcon = ({ className }: Props) => (
  <svg {...base} className={className}><path d="M14 3.5H7a1.5 1.5 0 00-1.5 1.5v14A1.5 1.5 0 007 20.5h10a1.5 1.5 0 001.5-1.5V8L14 3.5z" /><path d="M14 3.5V8h4.5" /></svg>
);
