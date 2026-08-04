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

  health: () => fetch('/health').then((r) => r.ok),
}

export { ApiError }
