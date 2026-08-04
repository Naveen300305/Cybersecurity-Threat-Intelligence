import { useState } from 'react'
import { Sparkles, Loader2, Terminal, AlertTriangle } from 'lucide-react'
import { api, ApiError, type QueryResponse } from '../api'

const EXAMPLES = [
  'What techniques does APT29 use?',
  'Which threat actors deploy Cobalt Strike?',
  'What malware uses spearphishing techniques?',
]

export default function QueryPage() {
  const [question, setQuestion] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<QueryResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function submit(q: string) {
    if (!q.trim() || loading) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      setResult(await api.query(q))
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
          <Sparkles className="text-accent" size={22} />
          Graph RAG Query
        </h1>
        <p className="mt-1 text-sm text-gray-500">
          Ask a natural-language question. It's converted to Cypher, traversed against
          the graph, and synthesized into an analyst-ready answer.
        </p>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault()
          submit(question)
        }}
        className="rounded-xl border border-border bg-panel p-4"
      >
        <textarea
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="e.g. What CVEs are exploited by malware used by Russian threat actors?"
          rows={3}
          className="w-full resize-none rounded-lg border border-border bg-panel-2 px-4 py-3 text-sm text-gray-100 placeholder-gray-600 outline-none focus:border-accent/50 font-mono"
        />
        <div className="mt-3 flex items-center justify-between">
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                type="button"
                onClick={() => {
                  setQuestion(ex)
                  submit(ex)
                }}
                className="rounded-full border border-border px-3 py-1 text-xs text-gray-400 hover:border-accent/40 hover:text-accent transition-colors"
              >
                {ex}
              </button>
            ))}
          </div>
          <button
            type="submit"
            disabled={loading || !question.trim()}
            className="flex items-center gap-2 rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-black disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition"
          >
            {loading && <Loader2 size={15} className="animate-spin" />}
            {loading ? 'Reasoning...' : 'Ask'}
          </button>
        </div>
      </form>

      {error && (
        <div className="mt-6 flex items-start gap-3 rounded-xl border border-danger/30 bg-danger/5 p-4 text-sm text-danger">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" />
          <span className="font-mono">{error}</span>
        </div>
      )}

      {result && (
        <div className="mt-6 space-y-4">
          <div className="rounded-xl border border-border bg-panel p-5">
            <h2 className="text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">
              Answer
            </h2>
            <p className="text-gray-200 leading-relaxed whitespace-pre-wrap">
              {result.answer}
            </p>
          </div>

          {result.cypher_query && (
            <div className="rounded-xl border border-border bg-panel-2 p-5">
              <h2 className="flex items-center gap-2 text-xs font-mono uppercase tracking-wider text-gray-500 mb-2">
                <Terminal size={13} />
                Generated Cypher
              </h2>
              <pre className="overflow-x-auto rounded-lg bg-black/40 p-3 text-xs text-accent-2 font-mono">
                {result.cypher_query}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
