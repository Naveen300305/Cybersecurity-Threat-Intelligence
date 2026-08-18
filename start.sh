#!/bin/bash
# CyberGraph — one-command startup script
# Usage: ./start.sh [--ingest]
#   --ingest  also run data ingestion (first-time setup)

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CyberGraph Intelligence Platform"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Neo4j
echo ""
echo "▶ Starting Neo4j..."
docker start cybergraph-neo4j 2>/dev/null || \
  docker run -d --name cybergraph-neo4j \
    -p 7474:7474 -p 7687:7687 \
    -e NEO4J_AUTH=neo4j/changeme-please \
    neo4j:5.20-community

echo "  Waiting for Neo4j to be ready..."
for i in $(seq 1 30); do
  if curl -s http://localhost:7474 > /dev/null 2>&1; then
    echo "  ✅ Neo4j ready"
    break
  fi
  sleep 1
done

# 2. Backend
echo ""
echo "▶ Starting FastAPI backend on :8000..."
fuser -k 8000/tcp 2>/dev/null || true
sleep 0.5
source .venv/bin/activate
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!
echo "  ✅ Backend PID $BACKEND_PID"

# 3. Optional ingestion
if [[ "$1" == "--ingest" ]]; then
  echo ""
  echo "▶ Running data ingestion (this takes a few minutes)..."
  python -m ingestion.run_ingest
  echo "  ✅ Ingestion complete"
fi

# 4. Frontend
echo ""
echo "▶ Starting Vite frontend on :5173..."
npm run dev &
FRONTEND_PID=$!
echo "  ✅ Frontend PID $FRONTEND_PID"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ All services running!"
echo ""
echo "  Frontend  → http://localhost:5173"
echo "  API docs  → http://localhost:8000/docs"
echo "  Neo4j     → http://localhost:7474"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Press Ctrl+C to stop all services."

# Wait and cleanup on exit
trap "echo ''; echo 'Stopping...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; docker stop cybergraph-neo4j 2>/dev/null; echo 'Done.'" EXIT
wait
