import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Network, Search, Loader2, AlertTriangle } from 'lucide-react'
import { api, ApiError, type ActorProfile } from '../api'

export default function ActorsPage() {
  const [actors, setActors] = useState<ActorProfile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  useEffect(() => {
    api
      .listActors(200)
      .then(setActors)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load actors'))
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return actors
    return actors.filter(
      (a) =>
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((alias) => alias.toLowerCase().includes(q)),
    )
  }, [actors, search])

  return (
    <div>
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-100 flex items-center gap-2">
          <Network className="text-accent" size={22} />
          Threat Actors
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Groups tracked in MITRE ATT&amp;CK, with their techniques and malware.
        </p>
      </header>

      <div className="relative mb-6">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name or alias..."
          className="w-full rounded-lg border border-border bg-panel-2 py-2.5 pl-9 pr-4 text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-accent/50"
        />
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <Loader2 size={15} className="animate-spin" /> Loading actors...
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {!loading && !error && (
        <>
          <p className="mb-3 text-xs font-mono text-gray-600">
            {filtered.length} of {actors.length} actors
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {filtered.map((actor) => (
              <Link
                key={actor.id}
                to={`/actors/${encodeURIComponent(actor.name)}`}
                className="group rounded-xl border border-border bg-panel p-4 hover:border-accent/40 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-gray-100 group-hover:text-accent transition-colors">
                    {actor.name}
                  </h3>
                  <span className="font-mono text-[11px] text-gray-600">{actor.id}</span>
                </div>
                {actor.aliases.length > 0 && (
                  <p className="mt-1 text-xs text-gray-500 truncate">
                    {actor.aliases.slice(0, 3).join(', ')}
                  </p>
                )}
                <p className="mt-2 text-xs text-gray-500 line-clamp-2">{actor.description}</p>
              </Link>
            ))}
          </div>
          {filtered.length === 0 && (
            <p className="text-sm text-gray-600 mt-4">No actors match "{search}".</p>
          )}
        </>
      )}
    </div>
  )
}
