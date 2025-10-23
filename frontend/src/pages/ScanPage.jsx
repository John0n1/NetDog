import { useEffect, useMemo, useState } from 'react'
import { Play, Clock, CheckCircle, AlertCircle, Trash2, Wifi, Activity } from 'lucide-react'
import { scans, netutil } from '../api'
import { formatDistanceToNow } from 'date-fns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

const ScanPage = () => {
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    targets: '',
    mode: 'normal',
  })
  const queryClient = useQueryClient()

  const { data: scanList = [], isFetching: scansFetching } = useQuery({
    queryKey: ['scans', 'list', { limit: 20 }],
    queryFn: async () => {
      const response = await scans.list({ limit: 20 })
      return response.data
    },
    refetchInterval: 5_000,
  })

  const { data: myNetwork } = useQuery({
    queryKey: ['netutil', 'my-network'],
    queryFn: async () => {
      const response = await netutil.getMyNetwork()
      return response.data
    },
    staleTime: 60_000,
  })

  const suggestedNetwork = useMemo(() => myNetwork?.suggested_network || '', [myNetwork])

  useEffect(() => {
    if (suggestedNetwork && !formData.targets) {
      setFormData((prev) => ({ ...prev, targets: suggestedNetwork }))
    }
  }, [suggestedNetwork, formData.targets])

  const createScan = useMutation({
    mutationFn: async (payload) => {
      const response = await scans.create(payload)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      setShowForm(false)
      setFormData({ targets: suggestedNetwork, mode: 'normal' })
    },
    onError: (error) => {
      alert('Failed to start scan: ' + (error.response?.data?.detail || error.message))
    },
  })

  const deleteScan = useMutation({
    mutationFn: async (scanId) => scans.delete(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
    onError: () => {
      alert('Failed to delete scan')
    },
  })

  const deletingId = deleteScan.variables

  const handleSubmit = (e) => {
    e.preventDefault()
    const targets = formData.targets.split('\n').map((t) => t.trim()).filter(Boolean)
    if (targets.length === 0) {
      alert('Please provide at least one target')
      return
    }
    createScan.mutate({
      targets,
      mode: formData.mode,
      consent: {
        approved: true,
        by: 'user',
        reason: 'Network scan',
      },
    })
  }

  const handleDelete = (scanId) => {
    if (!confirm('Are you sure you want to delete this scan?')) return
    deleteScan.mutate(scanId)
  }
  
  const getStatusIcon = (status) => {
    switch (status) {
      case 'running':
      case 'discovering':
        return <Clock className="w-5 h-5 text-blue-accent animate-spin" />
      case 'profiling':
        return <Activity className="w-5 h-5 text-yellow-400 animate-pulse" />
      case 'done':
        return <CheckCircle className="w-5 h-5 text-green-500" />
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-500" />
      default:
        return <Clock className="w-5 h-5 text-gray-500" />
    }
  }
  
  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold mb-2">Network Scan</h1>
          <p className="text-gray-400">Discover devices and vulnerabilities on your network</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary"
        >
          <Play className="w-4 h-4 mr-2 inline" />
          New Scan
        </button>
      </div>
      
      {/* New Scan Form */}
      {showForm && (
        <div className="card mb-6">
          <h2 className="text-xl font-semibold mb-4">Configure Scan</h2>
          
          {/* Network Info */}
          {myNetwork && (
            <div className="bg-blue-900 bg-opacity-20 border border-blue-700 rounded p-3 mb-4">
              <div className="flex items-center space-x-2 text-blue-300">
                <Wifi className="w-4 h-4" />
                <span className="text-sm">
                  Your network: <span className="font-mono font-semibold">{myNetwork.local_ip}</span>
                  {' → '}
                  <span className="font-mono font-semibold">{myNetwork.suggested_network}</span>
                </span>
              </div>
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="block text-sm font-semibold">
                  Targets (one per line)
                </label>
                {myNetwork && (
                  <button
                    type="button"
                    onClick={() => setFormData({ ...formData, targets: myNetwork.suggested_network })}
                    className="text-xs text-blue-accent hover:text-blue-300 px-2 py-1 rounded border border-blue-accent hover:bg-blue-accent hover:bg-opacity-10"
                  >
                    Use My Network
                  </button>
                )}
              </div>
              <textarea
                value={formData.targets}
                onChange={(e) => setFormData({ ...formData, targets: e.target.value })}
                className="input w-full h-24 font-mono text-sm"
                placeholder={myNetwork ? `${myNetwork.suggested_network}` : "192.168.1.0/24&#10;10.0.0.1&#10;scanme.nmap.org"}
                required
              />
              <p className="text-xs text-gray-500 mt-1">
                IP addresses, CIDR ranges, or hostnames
              </p>
            </div>
            
            <div>
              <label className="block text-sm font-semibold mb-2">Scan Mode</label>
              <select
                value={formData.mode}
                onChange={(e) => setFormData({ ...formData, mode: e.target.value })}
                className="input w-full"
              >
                <option value="slow">Slow (Stealthy, top 50 ports + OS detection)</option>
                <option value="stealthy">Stealthy (Quiet, top 200 ports + OS detection)</option>
                <option value="medium">Medium (Service detection, top 1000 ports + OS)</option>
                <option value="normal">Normal (Full TCP sweep + OS fingerprint)</option>
                <option value="aggressive">Aggressive (TCP/UDP + OS + Scripts)</option>
                <option value="offensive">Offensive (Deep probe + vulnerabilities + auth)</option>
                <option value="intrusive">Intrusive (Full intrusive + exploit scripts)</option>
              </select>
            </div>
            
            <div className="flex space-x-2">
              <button type="submit" disabled={createScan.isPending} className="btn-primary">
                {createScan.isPending ? 'Starting...' : 'Start Scan'}
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}
      
      {/* Scan List */}
      <div className="space-y-3">
        <h2 className="text-xl font-semibold">Recent Scans</h2>
        {scansFetching && scanList.length === 0 ? (
          <div className="card text-center text-gray-500 py-12">Loading scans...</div>
        ) : scanList.length === 0 ? (
          <div className="card text-center text-gray-500 py-12">
            No scans yet. Start your first scan above.
          </div>
        ) : (
          scanList.map((scan) => (
            <div key={scan.id} className="card hover:bg-dark-hover transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3 flex-1">
                  <div className="mt-1">
                    {getStatusIcon(scan.status)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="font-semibold">{scan.targets.join(', ')}</span>
                      <span className="badge badge-info">{scan.mode}</span>
                    </div>
                    <div className="text-sm text-gray-500">
                      Started {formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })}
                    </div>
                    {scan.result_summary && (
                      <div className="text-sm mt-2 space-x-4">
                        <span className="text-green-400">
                          {scan.result_summary.hosts_found} hosts
                        </span>
                        <span className="text-orange-400">
                          {scan.result_summary.vulns_found} vulnerabilities
                        </span>
                      </div>
                    )}
                  </div>
                </div>
                <button
                  onClick={() => handleDelete(scan.id)}
                  disabled={deleteScan.isPending && deletingId === scan.id}
                  className="text-gray-500 hover:text-red-500 disabled:text-gray-700 disabled:cursor-not-allowed"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

export default ScanPage
