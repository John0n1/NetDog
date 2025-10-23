import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import ScanDevicesPage from './pages/ScanDevicesPage'
import DisruptorPage from './pages/DisruptorPage'
import VulnerabilitiesPage from './pages/VulnerabilitiesPage'
import NetUtilPage from './pages/NetUtilPage'
import LoginPage from './pages/LoginPage'
import { useAuthStore } from './store/authStore'

function App() {
  const { token } = useAuthStore()

  if (!token) {
    return <LoginPage />
  }

  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<ScanDevicesPage />} />
          <Route path="/scan" element={<ScanDevicesPage />} />
          <Route path="/disruptor" element={<DisruptorPage />} />
          <Route path="/netutil" element={<NetUtilPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        </Routes>
      </Layout>
    </Router>
  )
}

export default App
