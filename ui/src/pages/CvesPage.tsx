import { useState } from 'react'
import { ShieldAlert, Search, Loader2, AlertTriangle, Flame } from 'lucide-react'
import { api, ApiError, type CVESummary } from '../api'
import { SeverityBadge } from '../components/Badge'

export default function CvesPage() {
  const [input, setInput] = useState('')
  const [cve, setCve] = useState<CVESummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    const id = input.trim()
    if (!id || loading) return
    setLoading(true)
    setError(null)
    setCve(null)
    try {
      setCve(await api.getCve(id))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Request failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-100 flex items-center gap-2">
          <ShieldAlert className="text-accent" size={22} />
          CVE Lookup
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Look up a CVE by ID for CVSS score, severity, and KEV status.
        </p>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit()
        }}
        className="flex gap-3"
      >
        <div className="relative flex-1">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="CVE-2021-44228"
            className="w-full rounded-lg border border-border bg-panel-2 py-2.5 pl-9 pr-4 text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-accent/50 font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !input.trim()}
          className="flex items-center gap-2 rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-black disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
        >
          {loading && <Loader2 size={15} className="animate-spin" />}
          {loading ? 'Looking up...' : 'Lookup'}
        </button>
      </form>

      {error && (
        <div className="mt-6 flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {cve && (
        <div className="mt-6 rounded-xl border border-border bg-panel p-5">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="font-mono text-lg font-semibold text-gray-100">{cve.id}</h2>
            <SeverityBadge severity={cve.severity} />
            {cve.is_kev && (
              <span className="inline-flex items-center gap-1 rounded-full border border-danger/30 bg-danger/10 px-2.5 py-0.5 text-xs font-mono font-medium text-danger">
                <Flame size={12} /> CISA KEV
              </span>
            )}
            {cve.cvss_v3_score != null && (
              <span className="font-mono text-xs text-gray-500">
                CVSS v3: <span className="text-gray-300">{cve.cvss_v3_score.toFixed(1)}</span>
              </span>
            )}
          </div>
          {cve.description && (
            <p className="mt-4 text-sm text-gray-400 leading-relaxed">{cve.description}</p>
          )}
        </div>
      )}
    </div>
  )
}
