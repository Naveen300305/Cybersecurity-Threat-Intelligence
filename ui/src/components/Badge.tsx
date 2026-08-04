import type { ReactNode } from 'react'

const SEVERITY_STYLES: Record<string, string> = {
  Critical: 'bg-danger/10 text-danger border-danger/30',
  High: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
  Medium: 'bg-warn/10 text-warn border-warn/30',
  Low: 'bg-accent-2/10 text-accent-2 border-accent-2/30',
  Unknown: 'bg-gray-500/10 text-gray-400 border-gray-500/30',
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  const key = severity ?? 'Unknown'
  const style = SEVERITY_STYLES[key] ?? SEVERITY_STYLES.Unknown
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-mono font-medium ${style}`}
    >
      {key}
    </span>
  )
}

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-mono text-gray-300">
      {children}
    </span>
  )
}
