import { useState } from 'react'
import { Zap, AlertTriangle } from 'lucide-react'
import { netutil } from '../api'

const DisruptorPage = () => {
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [formData, setFormData] = useState({
    target: '',
    method: 'syn_flood',
    duration: 10,
  })

  const handleSubmit = async (e) => {
    e.preventDefault()
  const humanMethod = formData.method.replace(/_/g, ' ')
  const confirmationMessage = `Run ${humanMethod} against ${formData.target} for ${formData.duration}s?`
    const confirmed = window.confirm(confirmationMessage)
    if (!confirmed) {
      return
    }
    setLoading(true)
    setResult(null)
    
    try {
      const response = await netutil.disruptor({
        ...formData,
        consent: { 
          approved: true, 
          by: 'user', 
          reason: 'Authorized network stress testing' 
        }
      })
      setResult({ type: 'success', data: response.data })
    } catch (error) {
      setResult({
        type: 'error',
        message: error.response?.data?.detail || error.message
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">Network Disruptor</h1>
        <p className="text-gray-400">Controlled network stress testing and resilience validation</p>
      </div>

      {/* Warning Banner */}
      <div className="bg-red-900 border border-red-600 rounded-lg p-4 mb-6">
        <div className="flex items-start space-x-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h2 className="font-bold text-red-200 mb-1">⚠️ AUTHORIZED USE ONLY</h2>
            <p className="text-sm text-red-200">
              Only use on networks you own or have explicit written authorization to test. 
              Unauthorized use is illegal and may result in criminal prosecution.
            </p>
          </div>
        </div>
      </div>

      {/* Main Card */}
      <div className="card mb-6">
        <h2 className="text-xl font-semibold mb-4">Configure Disruptor Test</h2>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-semibold mb-2">Target Host</label>
            <input
              type="text"
              value={formData.target}
              onChange={(e) => setFormData({ ...formData, target: e.target.value })}
              className="input w-full"
              placeholder="192.168.1.1 or example.com"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-semibold mb-2">Attack Method</label>
            <select
              value={formData.method}
              onChange={(e) => setFormData({ ...formData, method: e.target.value })}
              className="input w-full"
            >
              <option value="syn_flood">SYN Flood</option>
              <option value="udp_flood">UDP Flood</option>
              <option value="icmp_flood">ICMP Flood</option>
              <option value="slowloris">Slowloris (HTTP)</option>
              <option value="dns_amplification">DNS Amplification</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-semibold mb-2">Duration (seconds)</label>
            <input
              type="number"
              value={formData.duration}
              onChange={(e) => setFormData({ ...formData, duration: parseInt(e.target.value) })}
              className="input w-full"
              min="1"
              max="60"
              required
            />
            <p className="text-xs text-gray-500 mt-1">Maximum 60 seconds for safety</p>
          </div>

          <button type="submit" disabled={loading} className="btn-primary">
            {loading ? 'Starting Test...' : 'Start Disruptor Test'}
          </button>
        </form>
      </div>

      {/* Results */}
      {result && (
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Results</h2>
          
          {result.type === 'error' ? (
            <div className="bg-red-900 text-red-200 px-4 py-3 rounded">
              {result.message}
            </div>
          ) : result.type === 'success' ? (
            <div className="space-y-3">
              <div className="bg-green-900 text-green-200 px-4 py-3 rounded">
                <div className="font-semibold mb-1">✓ Test Queued Successfully</div>
                <div className="text-sm">{result.data.message}</div>
              </div>
              
              <div className="bg-dark-bg p-4 rounded space-y-2 text-sm">
                <div>
                  <span className="text-gray-500">Task ID:</span>
                  <span className="ml-2 font-mono text-blue-accent">{result.data.task_id}</span>
                </div>
                <div>
                  <span className="text-gray-500">Status:</span>
                  <span className="ml-2 text-yellow-400">{result.data.status}</span>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* Info Card */}
      <div className="card mt-6 bg-blue-900 bg-opacity-20 border border-blue-700">
        <h3 className="font-semibold text-blue-300 mb-2">About Network Disruption Testing</h3>
        <p className="text-sm text-blue-200">
          Network disruption testing validates how systems respond under stress conditions such as DDoS attacks.
          This helps identify weaknesses in infrastructure, load balancers, and failover mechanisms before
          real attacks occur. Always test in controlled environments with proper approvals.
        </p>
      </div>
    </div>
  )
}

export default DisruptorPage
