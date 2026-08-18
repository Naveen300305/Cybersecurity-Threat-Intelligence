import { useState, useEffect, useCallback } from 'react'
import {
  Monitor, Plus, Trash2, RefreshCw, AlertTriangle, Flame,
  ChevronDown, ChevronUp, Loader2, Shield, Brain, X,
  Clock, Activity, Users, Bug, CheckSquare
} from 'lucide-react'
import { api, ApiError, type MonitoredAsset, type AssetAlert } from '../api'
import { TierBadge, SeverityBadge } from '../components/Badge'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 75 ? '#ef4444' : score >= 50 ? '#f97316' : score >= 25 ? '#fbbf24' : '#4ade80'
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 flex-1 rounded-full bg-white/5 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }}
        />
      </div>
      <span className="font-mono text-xs text-gray-400 w-10 text-right">{score.toFixed(0)}/100</span>
    </div>
  )
}

// ─── Add Asset Modal ──────────────────────────────────────────────────────────

function AddAssetModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ name: '', vendor: '', product: '', version_range: '', owner: '' })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name || !form.vendor || !form.product || !form.version_range) return
    setLoading(true); setError(null)
    try {
      await api.createAsset(form)
      onCreated()
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to create asset')
    } finally {
      setLoading(false)
    }
  }

  const field = (key: keyof typeof form, label: string, placeholder: string) => (
    <div>
      <label className="block text-xs font-mono text-gray-400 mb-1">{label}</label>
      <input
        value={form[key]}
        onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))}
        placeholder={placeholder}
        className="w-full rounded-lg border border-border bg-panel-2 px-3 py-2 text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-accent/50 font-mono"
      />
    </div>
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-2xl border border-border bg-panel shadow-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
            <Monitor size={17} className="text-accent" /> Register Asset
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3">
          {field('name', 'Label *', 'Production Apache')}
          <div className="grid grid-cols-2 gap-3">
            {field('vendor', 'Vendor *', 'apache')}
            {field('product', 'Product *', 'http_server')}
          </div>
          {field('version_range', 'Version Range *', 'Apache 2.4.x below 2.4.58')}
          {field('owner', 'Owner / Team', 'Platform SRE')}

          {error && (
            <div className="flex items-center gap-2 rounded-lg border border-danger/30 bg-danger/5 px-3 py-2 text-xs text-danger font-mono">
              <AlertTriangle size={13} /> {error}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="rounded-lg border border-border px-4 py-2 text-sm text-gray-400 hover:text-gray-200 transition-colors">
              Cancel
            </button>
            <button type="submit" disabled={loading}
              className="flex items-center gap-2 rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-black disabled:opacity-40 hover:brightness-110 transition">
              {loading && <Loader2 size={14} className="animate-spin" />}
              {loading ? 'Registering…' : 'Register & Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Alert Detail Panel ───────────────────────────────────────────────────────

function AlertDetail({ alert, onClose }: { alert: AssetAlert; onClose: () => void }) {
  const [mitigation, setMitigation] = useState(alert.mitigation_checklist)
  const [loadingMit, setLoadingMit] = useState(false)
  const [mitError, setMitError] = useState<string | null>(null)

  async function fetchMitigation() {
    setLoadingMit(true); setMitError(null)
    try {
      const res = await api.getMitigation(alert.alert_id)
      setMitigation(res.checklist)
    } catch (err) {
      setMitError(err instanceof ApiError ? err.message : 'Failed to generate checklist')
    } finally {
      setLoadingMit(false)
    }
  }

  const tierColors: Record<string, string> = {
    CRITICAL: 'border-danger/40 shadow-danger/10',
    HIGH: 'border-orange-500/40 shadow-orange-500/10',
    MEDIUM: 'border-warn/40 shadow-warn/10',
    LOW: 'border-accent-2/40 shadow-accent-2/10',
  }
  const borderCls = tierColors[alert.alert_tier] ?? 'border-border'

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-black/60 backdrop-blur-sm">
      <div className={`h-full w-full max-w-2xl overflow-y-auto border-l ${borderCls} bg-panel shadow-2xl`}>
        {/* Header */}
        <div className="sticky top-0 z-10 border-b border-border bg-panel/95 backdrop-blur px-6 py-4 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <TierBadge tier={alert.alert_tier} />
              {alert.is_kev && (
                <span className="inline-flex items-center gap-1 rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-xs font-mono text-danger">
                  <Flame size={11} /> CISA KEV
                </span>
              )}
              <span className="font-mono text-sm text-gray-300">{alert.cve_id}</span>
            </div>
            <p className="mt-1 text-xs text-gray-500 font-mono">{alert.asset_name}</p>
          </div>
          <button onClick={onClose} className="ml-4 text-gray-500 hover:text-gray-300 transition-colors shrink-0">
            <X size={20} />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Scores */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'ThreatPriority', value: `${alert.threat_priority_score.toFixed(0)}/100` },
              { label: 'CVSS v3', value: alert.cvss_v3_score?.toFixed(1) ?? 'N/A' },
              { label: 'EPSS', value: alert.epss_score != null ? `${(alert.epss_score * 100).toFixed(1)}%` : 'N/A' },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl border border-border bg-panel-2 p-3 text-center">
                <div className="text-xs text-gray-500 font-mono mb-1">{label}</div>
                <div className="text-lg font-semibold text-gray-100 font-mono">{value}</div>
              </div>
            ))}
          </div>
          <ScoreBar score={alert.threat_priority_score} />

          {/* Threat Chain */}
          {(alert.deploying_actors.length > 0 || alert.exploiting_malware.length > 0) && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-gray-500 flex items-center gap-2">
                <Activity size={12} /> Threat Chain
              </h3>
              <div className="grid grid-cols-2 gap-3">
                {alert.deploying_actors.length > 0 && (
                  <div className="rounded-xl border border-border bg-panel-2 p-3">
                    <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono mb-2">
                      <Users size={11} /> Threat Actors
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {alert.deploying_actors.map(a => (
                        <span key={a} className="rounded-md border border-accent/20 bg-accent/5 px-2 py-0.5 text-xs text-accent font-mono">{a}</span>
                      ))}
                    </div>
                  </div>
                )}
                {alert.exploiting_malware.length > 0 && (
                  <div className="rounded-xl border border-border bg-panel-2 p-3">
                    <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono mb-2">
                      <Bug size={11} /> Exploiting Malware
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {alert.exploiting_malware.map(m => (
                        <span key={m} className="rounded-md border border-danger/20 bg-danger/5 px-2 py-0.5 text-xs text-danger font-mono">{m}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Narrative */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-gray-500 flex items-center gap-2 mb-3">
              <Brain size={12} /> Graph RAG Narrative
            </h3>
            <div className="rounded-xl border border-accent/20 bg-accent/5 p-4 text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
              {alert.narrative || (
                <span className="italic text-gray-600">
                  Narrative is being generated in the background — refresh in a moment.
                </span>
              )}
            </div>
          </div>

          {/* Mitigation */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-gray-500 flex items-center gap-2">
                <CheckSquare size={12} /> Mitigation Checklist
              </h3>
              {!mitigation && (
                <button
                  onClick={fetchMitigation}
                  disabled={loadingMit}
                  className="flex items-center gap-1.5 rounded-lg border border-accent-2/30 bg-accent-2/10 px-3 py-1.5 text-xs font-mono text-accent-2 hover:bg-accent-2/20 transition disabled:opacity-50">
                  {loadingMit ? <Loader2 size={11} className="animate-spin" /> : <Shield size={11} />}
                  {loadingMit ? 'Generating…' : 'Generate Checklist'}
                </button>
              )}
            </div>
            {mitError && (
              <div className="text-xs text-danger font-mono mb-2">{mitError}</div>
            )}
            {mitigation ? (
              <div className="rounded-xl border border-accent-2/20 bg-accent-2/5 p-4 text-sm text-gray-300 leading-relaxed whitespace-pre-wrap font-mono text-xs">
                {mitigation}
              </div>
            ) : (
              <div className="rounded-xl border border-border bg-panel-2 p-4 text-xs text-gray-600 font-mono italic">
                Click "Generate Checklist" to get an AI-powered remediation plan using graph data.
              </div>
            )}
          </div>

          {/* Metadata */}
          <div className="text-xs text-gray-600 font-mono space-y-1 pt-2 border-t border-border">
            <div className="flex items-center gap-2"><Clock size={11} /> First seen: {formatDate(alert.first_seen)}</div>
            <div>Alert ID: {alert.alert_id}</div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Alert Row ────────────────────────────────────────────────────────────────

function AlertRow({ alert, onClick }: { alert: AssetAlert; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-xl border border-border bg-panel-2 hover:border-accent/30 hover:bg-panel transition-all p-4 group"
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <TierBadge tier={alert.alert_tier} />
          {alert.is_kev && (
            <span className="inline-flex items-center gap-1 rounded-full border border-danger/30 bg-danger/10 px-2 py-0.5 text-xs font-mono text-danger">
              <Flame size={10} /> KEV
            </span>
          )}
          <span className="font-mono text-sm font-medium text-gray-200 group-hover:text-accent transition-colors">{alert.cve_id}</span>
          <span className="text-xs text-gray-500">on</span>
          <span className="text-xs text-gray-400 font-mono">{alert.asset_name}</span>
        </div>
        <div className="text-right shrink-0">
          <div className="text-xs font-mono text-gray-400">{alert.cvss_v3_score?.toFixed(1) ?? 'N/A'}</div>
          <div className="text-[10px] text-gray-600">CVSS</div>
        </div>
      </div>
      <div className="mt-2">
        <ScoreBar score={alert.threat_priority_score} />
      </div>
      {(alert.deploying_actors.length > 0 || alert.exploiting_malware.length > 0) && (
        <div className="mt-2 flex gap-3 text-xs text-gray-600 font-mono">
          {alert.deploying_actors.length > 0 && (
            <span><Users size={10} className="inline mr-1" />{alert.deploying_actors.slice(0, 2).join(', ')}{alert.deploying_actors.length > 2 ? `+${alert.deploying_actors.length - 2}` : ''}</span>
          )}
          {alert.exploiting_malware.length > 0 && (
            <span><Bug size={10} className="inline mr-1" />{alert.exploiting_malware.slice(0, 2).join(', ')}{alert.exploiting_malware.length > 2 ? `+${alert.exploiting_malware.length - 2}` : ''}</span>
          )}
        </div>
      )}
    </button>
  )
}

// ─── Asset Card ───────────────────────────────────────────────────────────────

function AssetCard({
  asset, alerts, onDelete, onSelectAlert,
}: {
  asset: MonitoredAsset
  alerts: AssetAlert[]
  onDelete: () => void
  onSelectAlert: (a: AssetAlert) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const criticals = alerts.filter(a => a.alert_tier === 'CRITICAL').length
  const highs = alerts.filter(a => a.alert_tier === 'HIGH').length

  return (
    <div className="rounded-2xl border border-border bg-panel overflow-hidden">
      {/* Card header */}
      <div className="flex items-start justify-between p-5">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Monitor size={15} className="text-accent shrink-0" />
            <span className="font-semibold text-gray-100 text-sm">{asset.name}</span>
            {asset.owner && (
              <span className="rounded-full border border-border px-2 py-0.5 text-xs text-gray-500 font-mono">{asset.owner}</span>
            )}
          </div>
          <div className="mt-1 text-xs text-gray-500 font-mono">
            {asset.vendor} / {asset.product} · {asset.version_range}
          </div>
        </div>

        <div className="flex items-center gap-2 ml-3 shrink-0">
          {criticals > 0 && (
            <span className="rounded-full border border-danger/40 bg-danger/10 px-2.5 py-0.5 text-xs font-mono font-semibold text-danger flex items-center gap-1">
              <Flame size={10} /> {criticals} CRITICAL
            </span>
          )}
          {highs > 0 && (
            <span className="rounded-full border border-orange-500/40 bg-orange-500/10 px-2.5 py-0.5 text-xs font-mono font-semibold text-orange-400">
              {highs} HIGH
            </span>
          )}
          {alerts.length === 0 && (
            <span className="rounded-full border border-accent-2/30 bg-accent-2/10 px-2.5 py-0.5 text-xs font-mono text-accent-2">
              Clean
            </span>
          )}
          <button
            onClick={() => setExpanded(e => !e)}
            className="rounded-lg border border-border p-1.5 text-gray-500 hover:text-gray-300 transition-colors"
          >
            {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>
          <button
            onClick={onDelete}
            className="rounded-lg border border-danger/20 bg-danger/5 p-1.5 text-danger/60 hover:text-danger transition-colors"
            title="Remove asset"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Alert list */}
      {expanded && (
        <div className="border-t border-border px-5 pb-5 pt-4 space-y-2">
          {alerts.length === 0 ? (
            <p className="text-xs text-gray-600 font-mono italic">No alerts for this asset.</p>
          ) : (
            alerts.map(alert => (
              <AlertRow key={alert.alert_id} alert={alert} onClick={() => onSelectAlert(alert)} />
            ))
          )}
        </div>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const [assets, setAssets] = useState<MonitoredAsset[]>([])
  const [alerts, setAlerts] = useState<AssetAlert[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [selectedAlert, setSelectedAlert] = useState<AssetAlert | null>(null)
  const [scanning, setScanning] = useState(false)
  const [tierFilter, setTierFilter] = useState<string>('ALL')

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const [assetList, alertList] = await Promise.all([
        api.listAssets(),
        api.listAlerts({ limit: 200 }),
      ])
      setAssets(assetList)
      setAlerts(alertList.alerts)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function triggerScan() {
    setScanning(true)
    try {
      await api.triggerScan()
      setTimeout(load, 3000)
    } catch {
      // best-effort
    } finally {
      setTimeout(() => setScanning(false), 3000)
    }
  }

  async function deleteAsset(id: string) {
    try {
      await api.deleteAsset(id)
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed')
    }
  }

  const tiers = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  const filteredAlerts = tierFilter === 'ALL' ? alerts : alerts.filter(a => a.alert_tier === tierFilter)

  const critCount = alerts.filter(a => a.alert_tier === 'CRITICAL').length
  const highCount = alerts.filter(a => a.alert_tier === 'HIGH').length
  const kevCount = alerts.filter(a => a.is_kev).length

  return (
    <div>
      {/* Page header */}
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-100 flex items-center gap-2">
          <Monitor className="text-accent" size={22} />
          My Assets
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Register software you protect — CyberGraph watches for new CVEs and explains the full threat chain.
        </p>
      </header>

      {/* Summary banner */}
      {alerts.length > 0 && (
        <div className="mb-6 grid grid-cols-3 gap-3">
          {[
            { label: 'Critical', value: critCount, color: 'text-danger border-danger/30 bg-danger/5' },
            { label: 'High', value: highCount, color: 'text-orange-400 border-orange-500/30 bg-orange-500/5' },
            { label: 'CISA KEV', value: kevCount, color: 'text-danger border-danger/30 bg-danger/5' },
          ].map(({ label, value, color }) => (
            <div key={label} className={`rounded-xl border p-4 ${color}`}>
              <div className="text-2xl font-bold font-mono">{value}</div>
              <div className="text-xs mt-0.5 opacity-70 font-mono">{label} alerts</div>
            </div>
          ))}
        </div>
      )}

      {/* Toolbar */}
      <div className="mb-6 flex items-center gap-3 flex-wrap">
        <button
          onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-black hover:brightness-110 transition"
        >
          <Plus size={15} /> Add Asset
        </button>
        <button
          onClick={triggerScan}
          disabled={scanning}
          className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-gray-300 hover:text-gray-100 hover:border-accent/30 transition disabled:opacity-50"
        >
          <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
          {scanning ? 'Scanning…' : 'Scan Now'}
        </button>
        {/* Tier filter */}
        <div className="ml-auto flex gap-1">
          {tiers.map(t => (
            <button
              key={t}
              onClick={() => setTierFilter(t)}
              className={`rounded-lg border px-3 py-1.5 text-xs font-mono transition ${
                tierFilter === t
                  ? 'border-accent/40 bg-accent/10 text-accent'
                  : 'border-border text-gray-500 hover:text-gray-300'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-4 flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <Loader2 size={28} className="animate-spin text-accent" />
        </div>
      ) : assets.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-border bg-panel-2/50 p-12 text-center">
          <Monitor size={36} className="mx-auto mb-3 text-gray-600" />
          <p className="text-gray-400 font-medium">No assets registered yet</p>
          <p className="text-sm text-gray-600 mt-1 mb-5">Add your first asset to start monitoring for threats.</p>
          <button
            onClick={() => setShowAdd(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-black hover:brightness-110 transition"
          >
            <Plus size={15} /> Register Asset
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {assets.map(asset => {
            const assetAlerts = filteredAlerts.filter(a => a.asset_id === asset.id)
            return (
              <AssetCard
                key={asset.id}
                asset={asset}
                alerts={assetAlerts}
                onDelete={() => deleteAsset(asset.id)}
                onSelectAlert={setSelectedAlert}
              />
            )
          })}
        </div>
      )}

      {/* Modals */}
      {showAdd && <AddAssetModal onClose={() => setShowAdd(false)} onCreated={load} />}
      {selectedAlert && <AlertDetail alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  )
}
