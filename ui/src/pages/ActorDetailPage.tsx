import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, Crosshair, Bug, Loader2, AlertTriangle } from 'lucide-react'
import { api, ApiError, type ActorProfile } from '../api'
import { Tag } from '../components/Badge'

export default function ActorDetailPage() {
  const { name = '' } = useParams()
  const [actor, setActor] = useState<ActorProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setLoading(true)
    setActor(null)
    setError(null)
    api
      .getActor(name)
      .then(setActor)
      .catch((err) => setError(err instanceof ApiError ? err.message : 'Failed to load actor'))
      .finally(() => setLoading(false))
  }, [name])

  return (
    <div>
      <Link
        to="/actors"
        className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-accent mb-6 transition-colors"
      >
        <ArrowLeft size={14} /> Back to actors
      </Link>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <Loader2 size={15} className="animate-spin" /> Loading profile...
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {actor && (
        <>
          <header className="mb-6">
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold text-gray-100">{actor.name}</h1>
              <span className="font-mono text-xs text-gray-600 border border-border rounded px-2 py-0.5">
                {actor.id}
              </span>
            </div>
            {actor.aliases.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {actor.aliases.map((alias) => (
                  <Tag key={alias}>{alias}</Tag>
                ))}
              </div>
            )}
            {actor.description && (
              <p className="mt-4 text-sm text-gray-400 leading-relaxed max-w-2xl">
                {actor.description}
              </p>
            )}
          </header>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <section className="rounded-xl border border-border bg-panel p-5">
              <h2 className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-gray-500 mb-3">
                <Crosshair size={13} />
                Techniques ({actor.techniques.length})
              </h2>
              {actor.techniques.length === 0 ? (
                <p className="text-sm text-gray-600">No techniques mapped.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {actor.techniques.map((t) => (
                    <Tag key={t}>{t}</Tag>
                  ))}
                </div>
              )}
            </section>

            <section className="rounded-xl border border-border bg-panel p-5">
              <h2 className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-gray-500 mb-3">
                <Bug size={13} />
                Malware &amp; Tools ({actor.malware.length})
              </h2>
              {actor.malware.length === 0 ? (
                <p className="text-sm text-gray-600">No malware mapped.</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {actor.malware.map((m) => (
                    <Tag key={m}>{m}</Tag>
                  ))}
                </div>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  )
}
