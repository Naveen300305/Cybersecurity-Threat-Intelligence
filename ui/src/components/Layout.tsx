import { useEffect, useState, type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'
import { Network, ShieldAlert, Terminal, Radio, Monitor } from 'lucide-react'
import { api } from '../api'

const NAV_ITEMS = [
  { to: '/query', label: 'Query', icon: Terminal },
  { to: '/actors', label: 'Threat Actors', icon: Network },
  { to: '/cves', label: 'CVE Lookup', icon: ShieldAlert },
  { to: '/assets', label: 'My Assets', icon: Monitor },
]

function HealthIndicator() {
  const [online, setOnline] = useState<boolean | null>(null)

  useEffect(() => {
    let cancelled = false
    const check = () => api.health().then((ok) => !cancelled && setOnline(ok))
    check()
    const id = setInterval(check, 15000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [])

  const color =
    online === null ? 'bg-gray-500' : online ? 'bg-accent-2' : 'bg-danger'
  const label =
    online === null ? 'Checking...' : online ? 'API online' : 'API unreachable'

  return (
    <div className="flex items-center gap-2 text-xs text-gray-400 font-mono">
      <Radio size={13} className={online ? 'text-accent-2' : 'text-danger'} />
      <span
        className={`h-1.5 w-1.5 rounded-full ${color} ${online ? 'animate-pulse-glow' : ''}`}
      />
      {label}
    </div>
  )
}

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <aside className="w-64 shrink-0 border-r border-border bg-panel/60 backdrop-blur-sm flex flex-col">
        <div className="px-6 py-6 border-b border-border">
          <div className="flex items-center gap-2">
            <div className="relative">
              <Network className="text-accent" size={22} />
              <span className="absolute inset-0 blur-md text-accent opacity-60">
                <Network size={22} />
              </span>
            </div>
            <span className="font-mono font-semibold tracking-tight text-gray-100">
              Cyber<span className="text-accent">Graph</span>
            </span>
          </div>
          <p className="mt-1 text-[11px] text-gray-500 font-mono">
            Graph RAG Threat Intelligence
          </p>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent border border-accent/30'
                    : 'text-gray-400 hover:text-gray-100 hover:bg-white/5 border border-transparent'
                }`
              }
            >
              <Icon size={16} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-4 py-4 border-t border-border">
          <HealthIndicator />
        </div>
      </aside>

      <main className="flex-1 min-w-0">
        <div className="mx-auto max-w-5xl px-8 py-10">{children}</div>
      </main>
    </div>
  )
}
