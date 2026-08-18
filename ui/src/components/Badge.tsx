import type { ReactNode } from 'react'
import type { AssetAlert } from '../api'

// ─── Generic Tag chip ─────────────────────────────────────────────────────────

export function Tag({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-md border border-border bg-panel-2 px-2 py-0.5 text-xs font-mono text-gray-400">
      {children}
    </span>
  )
}



// ─── Severity / Tier Badges ──────────────────────────────────────────────────

interface BadgeProps {
  severity: string | null | undefined
}

export function SeverityBadge({ severity }: BadgeProps) {
  const s = severity?.toUpperCase() ?? 'UNKNOWN'
  const styles: Record<string, string> = {
    CRITICAL: 'border-danger/40 bg-danger/10 text-danger',
    HIGH: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
    MEDIUM: 'border-warn/40 bg-warn/10 text-warn',
    LOW: 'border-accent-2/40 bg-accent-2/10 text-accent-2',
    UNKNOWN: 'border-gray-600 bg-gray-800 text-gray-500',
    NONE: 'border-gray-600 bg-gray-800 text-gray-500',
  }
  const cls = styles[s] ?? styles.UNKNOWN
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-mono font-semibold ${cls}`}>
      {s}
    </span>
  )
}

// Alias for alert tier — same visual mapping as severity
export function TierBadge({ tier }: { tier: AssetAlert['alert_tier'] }) {
  return <SeverityBadge severity={tier} />
}
