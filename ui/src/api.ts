export interface QueryResponse {
  answer: string
  cypher_query: string | null
}

export interface ActorProfile {
  id: string
  name: string
  aliases: string[]
  description: string
  techniques: string[]
  malware: string[]
}

export interface CVESummary {
  id: string
  description: string
  cvss_v3_score: number | null
  severity: string | null
  is_kev: boolean
}

// Module 11: Asset Monitoring & Alerting
export interface MonitoredAsset {
  id: string
  name: string
  vendor: string
  product: string
  version_range: string
  owner: string
  version_min: string | null
  version_max: string | null
  created_at: string
}

export interface MonitoredAssetCreate {
  name: string
  vendor: string
  product: string
  version_range: string
  owner?: string
  version_min?: string
  version_max?: string
}

export interface AssetAlert {
  alert_id: string
  asset_id: string
  asset_name: string
  cve_id: string
  cvss_v3_score: number | null
  severity: string | null
  is_kev: boolean
  epss_score: number | null
  threat_priority_score: number
  alert_tier: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  first_seen: string
  notified_at: string | null
  exploiting_malware: string[]
  deploying_actors: string[]
  targeted_sectors: string[]
  narrative: string
  mitigation_checklist: string
}

export interface AlertListResponse {
  alerts: AssetAlert[]
  total: number
}

export interface MitigationResponse {
  alert_id: string
  cve_id: string
  checklist: string
}

class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new ApiError(res.status, body.detail ?? res.statusText)
  }
  return res.json() as Promise<T>
}

export const api = {
  query: (question: string) =>
    request<QueryResponse>('/query', {
      method: 'POST',
      body: JSON.stringify({ question }),
    }),

  listActors: (limit = 50) =>
    request<ActorProfile[]>(`/actors?limit=${limit}`),

  getActor: (name: string) =>
    request<ActorProfile>(`/actors/${encodeURIComponent(name)}`),

  getCve: (id: string) => request<CVESummary>(`/cves/${encodeURIComponent(id)}`),

  /** Fetch a CVE from NVD by ID, persist it in Neo4j, and return it. */
  ingestCve: (id: string) =>
    request<CVESummary>(`/cves/ingest?cve_id=${encodeURIComponent(id)}`, { method: 'POST' }),

  health: () => fetch('/health').then((r) => r.ok),

  // Module 11
  listAssets: () => request<MonitoredAsset[]>('/assets'),
  createAsset: (payload: MonitoredAssetCreate) =>
    request<MonitoredAsset>('/assets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  deleteAsset: (assetId: string) =>
    request<void>(`/assets/${encodeURIComponent(assetId)}`, { method: 'DELETE' }),

  listAlerts: (params?: { asset_id?: string; tier?: string; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.asset_id) qs.set('asset_id', params.asset_id)
    if (params?.tier) qs.set('tier', params.tier)
    if (params?.limit) qs.set('limit', String(params.limit))
    return request<AlertListResponse>(`/alerts?${qs}`)
  },
  getAlert: (alertId: string) =>
    request<AssetAlert>(`/alerts/${encodeURIComponent(alertId)}`),
  getMitigation: (alertId: string) =>
    request<MitigationResponse>(`/alerts/${encodeURIComponent(alertId)}/mitigate`, {
      method: 'POST',
    }),
  triggerScan: () =>
    request<{ message: string; status: string }>('/assets/scan', { method: 'POST' }),
}

export { ApiError }
