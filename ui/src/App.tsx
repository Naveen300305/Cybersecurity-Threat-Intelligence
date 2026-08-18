import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import QueryPage from './pages/QueryPage'
import ActorsPage from './pages/ActorsPage'
import ActorDetailPage from './pages/ActorDetailPage'
import CvesPage from './pages/CvesPage'
import AssetsPage from './pages/AssetsPage'

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/query" replace />} />
        <Route path="/query" element={<QueryPage />} />
        <Route path="/actors" element={<ActorsPage />} />
        <Route path="/actors/:name" element={<ActorDetailPage />} />
        <Route path="/cves" element={<CvesPage />} />
        <Route path="/assets" element={<AssetsPage />} />
      </Routes>
    </Layout>
  )
}

export default App
