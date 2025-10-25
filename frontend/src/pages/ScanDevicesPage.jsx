import { useState } from 'react'
import { Play, Clock, CheckCircle, AlertCircle, Trash2, Wifi, Activity, Monitor, Smartphone, Tv, Router, Server, HardDrive, Loader, ShieldAlert, BarChart3, Users, Gauge } from 'lucide-react'
import { scans, netutil, devices, metrics } from '../api'
import { formatDistanceToNow } from 'date-fns'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

const DeviceCard = ({ device, isScanning }) => {
  const getDeviceIcon = (deviceType) => {
    const type = deviceType?.toLowerCase() || ''
    if (type.includes('phone') || type.includes('android') || type.includes('iphone')) {
      return <Smartphone className="w-6 h-6" />
    }
    if (type.includes('tv') || type.includes('roku') || type.includes('chromecast')) {
      return <Tv className="w-6 h-6" />
    }
    if (type.includes('router') || type.includes('gateway') || type.includes('access point')) {
      return <Router className="w-6 h-6" />
    }
    if (type.includes('server')) {
      return <Server className="w-6 h-6" />
    }
    if (type.includes('nas') || type.includes('storage')) {
      return <HardDrive className="w-6 h-6" />
    }
    return <Monitor className="w-6 h-6" />
  }

  const getRiskColor = (score) => {
    if (score >= 7) return 'text-red-400 bg-red-900'
    if (score >= 4) return 'text-orange-400 bg-orange-900'
    if (score >= 2) return 'text-yellow-400 bg-yellow-900'
    return 'text-green-400 bg-green-900'
  }

  const getOsDisplay = () => {
    if (device.os_guess) return device.os_guess
    if (device.vendor) return `Likely ${device.vendor}`
    if (isScanning) return 'Fingerprinting...'
    return 'Unknown'
  }

  const isEnriching = isScanning && (!device.os_guess || !device.open_ports || device.open_ports.length === 0)
  const osDisplay = getOsDisplay()
  const osIsFallback = !device.os_guess
  const osIsInferred = osDisplay.toLowerCase().includes('fingerprint')

  return (
    <div className="card hover:bg-dark-hover transition-all duration-200 relative">
      {/* Scanning overlay */}
      {isEnriching && (
        <div className="absolute inset-0 bg-blue-500 bg-opacity-5 rounded-lg flex items-center justify-center">
          <Loader className="w-8 h-8 text-blue-accent animate-spin" />
        </div>
      )}
      
      <div className="flex items-start space-x-4">
        {/* Device Icon */}
        <div className={`p-3 rounded-lg ${isEnriching ? 'opacity-50' : ''} ${
          device.device_type?.includes('Unknown') ? 'bg-gray-700 text-gray-400' : 'bg-blue-900 text-blue-300'
        }`}>
          {getDeviceIcon(device.device_type)}
        </div>

        {/* Device Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center space-x-2">
              <h3 className="font-semibold text-lg">{device.hostname || device.ip}</h3>
              {device.hostname && (
                <span className="text-sm text-gray-500 font-mono">{device.ip}</span>
              )}
            </div>
            <div className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(device.risk_score || 0)}`}>
              Risk: {(device.risk_score || 0).toFixed(1)}
            </div>
          </div>

          {/* Device Details */}
          <div className="space-y-1 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Type:</span>
              <span className={isEnriching && !device.device_type ? 'animate-pulse' : ''}>
                {device.device_type || 'Detecting...'}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="text-gray-400">OS:</span>
              <div className="flex items-center space-x-2">
                <span
                  className={`truncate max-w-48 ${osIsFallback ? 'italic text-gray-400' : ''} ${
                    isEnriching && osIsFallback ? 'animate-pulse' : ''
                  }`}
                >
                  {osDisplay}
                </span>
                {osIsInferred && (
                  <span className="text-[10px] uppercase tracking-wide text-blue-300">Inferred</span>
                )}
              </div>
            </div>

            {device.mac_address && (
              <div className="flex items-center justify-between">
                <span className="text-gray-400">MAC:</span>
                <span className="font-mono text-xs">{device.mac_address}</span>
              </div>
            )}
            
            {device.vendor && (
              <div className="flex items-center justify-between">
                <span className="text-gray-400">Vendor:</span>
                <span>{device.vendor}</span>
              </div>
            )}
            
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Ports:</span>
              <span className={isEnriching && (!device.open_ports || device.open_ports.length === 0) ? 'animate-pulse' : ''}>
                {device.open_ports && device.open_ports.length > 0 
                  ? `${device.open_ports.length} open` 
                  : (isEnriching ? 'Scanning...' : 'None detected')
                }
              </span>
            </div>
          </div>

          {/* Open Ports Summary */}
          {device.open_ports && device.open_ports.length > 0 && (
            <div className="mt-3 pt-2 border-t border-dark-border">
              <div className="flex flex-wrap gap-1">
                {device.open_ports.slice(0, 6).map((port, idx) => (
                  <span key={idx} className="px-2 py-1 bg-dark-bg rounded text-xs font-mono">
                    {port.port}/{port.protocol}
                  </span>
                ))}
                {device.open_ports.length > 6 && (
                  <span className="px-2 py-1 bg-dark-bg rounded text-xs">
                    +{device.open_ports.length - 6} more
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

const ScanDevicesPage = () => {
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    targets: '',
    mode: 'normal',
  })
  const [deletingId, setDeletingId] = useState(null)

  const queryClient = useQueryClient()

  const { data: overviewMetrics = null, isFetching: metricsLoading } = useQuery({
    queryKey: ['metrics', 'overview'],
    queryFn: async () => {
      const response = await metrics.overview()
      return response.data
    },
    refetchInterval: 10000,
  })

  // Get network info
  const { data: myNetwork } = useQuery({
    queryKey: ['my-network'],
    queryFn: async () => {
      const response = await netutil.getMyNetwork()
      return response.data
    },
  })

  // Get scans list
  const { data: scanList = [], isFetching: scansFetching } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const response = await scans.list({ limit: 10 })
      return response.data
    },
    refetchInterval: 2000,
  })

  // Get devices for the most recent scan
  const mostRecentScan = scanList.find(scan => scan.status === 'running' || scan.status === 'discovering' || scan.status === 'profiling') || scanList[0]
  
  const { data: devicesList = [], isFetching: devicesFetching } = useQuery({
    queryKey: ['devices', mostRecentScan?.id],
    queryFn: async () => {
      if (!mostRecentScan?.id) return []
      const response = await devices.list({ scan_id: mostRecentScan.id, limit: 100 })
      return response.data
    },
    enabled: !!mostRecentScan?.id,
    refetchInterval: mostRecentScan?.status === 'running' || mostRecentScan?.status === 'discovering' || mostRecentScan?.status === 'profiling' ? 1000 : 5000,
  })

  const isActiveScanning = mostRecentScan?.status === 'running' || mostRecentScan?.status === 'discovering' || mostRecentScan?.status === 'profiling'

  const riskDistribution = overviewMetrics?.risk_distribution ?? {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  }

  const totalRiskDevices = Object.values(riskDistribution).reduce((sum, value) => sum + value, 0)

  const renderMetricValue = (value, { precision = 0, suffix = '' } = {}) => {
    if (metricsLoading && !overviewMetrics) {
      return <div className="h-6 bg-dark-bg animate-pulse rounded w-16" />
    }

    if (value === null || value === undefined) {
      return <span className="text-gray-500">—</span>
    }

    const formatted =
      typeof value === 'number' && precision > 0
        ? value.toFixed(precision)
        : value

    return (
      <span className="text-2xl font-semibold text-white">
        {formatted}
        {suffix}
      </span>
    )
  }

  // Create scan mutation
  const createScan = useMutation({
    mutationFn: async (data) => {
      const response = await scans.create(data)
      return response.data
    },
    onSuccess: () => {
      setShowForm(false)
      setFormData({ targets: '', mode: 'normal' })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  // Delete scan mutation
  const deleteScan = useMutation({
    mutationFn: async (scanId) => {
      setDeletingId(scanId)
      await scans.delete(scanId)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      queryClient.invalidateQueries({ queryKey: ['devices'] })
      setDeletingId(null)
    },
  })

  const handleSubmit = (e) => {
    e.preventDefault()
    const targetList = formData.targets.split('\n').filter(t => t.trim())
    
    createScan.mutate({
      targets: targetList,
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
    <div className="max-w-7xl mx-auto">
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <div className="card relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Total Scans</p>
              {renderMetricValue(overviewMetrics?.total_scans)}
            </div>
            <BarChart3 className="w-10 h-10 text-blue-accent opacity-70" />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            {overviewMetrics?.completed_scans || 0} completed scans in history
          </p>
        </div>

        <div className="card relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Active Scans</p>
              {renderMetricValue(overviewMetrics?.active_scans)}
            </div>
            <Activity className={`w-10 h-10 ${overviewMetrics?.active_scans ? 'text-green-400 animate-pulse' : 'text-gray-500'}`} />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Monitoring {overviewMetrics?.recent_scan?.targets?.[0] ? overviewMetrics.recent_scan.targets.slice(0, 2).join(', ') : 'network targets'}
          </p>
        </div>

        <div className="card relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">Monitored Devices</p>
              {renderMetricValue(overviewMetrics?.total_devices)}
            </div>
            <Users className="w-10 h-10 text-purple-300 opacity-70" />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            {overviewMetrics?.new_devices_24h || 0} new devices seen in last 24h
          </p>
        </div>

        <div className="card relative overflow-hidden">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-400">High Risk Devices</p>
              {renderMetricValue(overviewMetrics?.high_risk_devices)}
            </div>
            <ShieldAlert className="w-10 h-10 text-red-400 opacity-70" />
          </div>
          <p className="mt-2 text-xs text-gray-500">
            {overviewMetrics?.critical_vulnerabilities || 0} critical vulnerabilities tracked
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="card lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold">Risk Distribution</h2>
            {overviewMetrics?.last_updated && (
              <span className="text-xs text-gray-500">
                Updated {formatDistanceToNow(new Date(overviewMetrics.last_updated), { addSuffix: true })}
              </span>
            )}
          </div>

          {totalRiskDevices === 0 ? (
            <p className="text-sm text-gray-500">No device risk data yet. Start a scan to build your inventory.</p>
          ) : (
            <div>
              <div className="flex h-3 overflow-hidden rounded bg-dark-bg">
                {[
                  { key: 'critical', color: 'bg-red-500' },
                  { key: 'high', color: 'bg-orange-400' },
                  { key: 'medium', color: 'bg-yellow-400' },
                  { key: 'low', color: 'bg-green-400' },
                  { key: 'unknown', color: 'bg-gray-500' },
                ].map(({ key, color }) => {
                  const value = riskDistribution[key]
                  if (!value) return null
                  const width = `${Math.max((value / totalRiskDevices) * 100, 3)}%`
                  return <div key={key} className={`${color} transition-all duration-500`} style={{ width }} />
                })}
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-4 text-sm">
                {[
                  { label: 'Critical', key: 'critical', color: 'text-red-300' },
                  { label: 'High', key: 'high', color: 'text-orange-300' },
                  { label: 'Medium', key: 'medium', color: 'text-yellow-300' },
                  { label: 'Low', key: 'low', color: 'text-green-300' },
                  { label: 'Unknown', key: 'unknown', color: 'text-gray-400' },
                ].map(({ label, key, color }) => (
                  <div key={key} className="flex items-center space-x-2">
                    <span className={`inline-flex h-2 w-2 rounded-full ${color.replace('text', 'bg')}`} />
                    <span className="text-gray-400">{label}</span>
                    <span className="font-mono text-sm text-white">{riskDistribution[key]}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="card space-y-4">
          <div>
            <p className="text-sm text-gray-400">Average Risk Score</p>
            <div className="flex items-center space-x-3 mt-2">
              {metricsLoading && !overviewMetrics ? (
                <div className="h-10 w-10 rounded-full bg-dark-bg animate-pulse" />
              ) : (
                <div className="p-2 rounded-full bg-dark-bg">
                  <Gauge className="w-6 h-6 text-blue-accent" />
                </div>
              )}
              <div>
                <div className="text-2xl font-semibold">
                  {overviewMetrics?.average_risk_score !== undefined && overviewMetrics?.average_risk_score !== null
                    ? overviewMetrics.average_risk_score.toFixed(1)
                    : '—'}
                </div>
                <p className="text-xs text-gray-500">Scaled 0 - 10</p>
              </div>
            </div>
          </div>

          {overviewMetrics?.recent_scan ? (
            <div className="border border-dark-border rounded-lg p-3">
              <p className="text-sm text-gray-400 mb-1">Most Recent Scan</p>
              <p className="font-semibold text-white truncate">{overviewMetrics.recent_scan.targets.join(', ')}</p>
              <p className="text-xs text-gray-500 mt-1">
                {formatDistanceToNow(new Date(overviewMetrics.recent_scan.started_at), { addSuffix: true })}
                {' • '}
                Mode: <span className="uppercase">{overviewMetrics.recent_scan.mode}</span>
              </p>
              {overviewMetrics.recent_scan.result_summary && (
                <p className="text-xs text-gray-500 mt-1">
                  {overviewMetrics.recent_scan.result_summary?.hosts_found || 0} hosts · {overviewMetrics.recent_scan.result_summary?.vulns_found || 0} vulns
                </p>
              )}
            </div>
          ) : (
            <div className="border border-dashed border-dark-border rounded-lg p-3 text-sm text-gray-500">
              No scans yet. Launch your first scan to populate insights.
            </div>
          )}
        </div>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold mb-2">Network Scan & Devices</h1>
          <p className="text-gray-400">Discover and monitor devices on your network</p>
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
                placeholder={myNetwork ? `${myNetwork.suggested_network}` : "192.168.1.0/24\n10.0.0.1\nscanme.nmap.org"}
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Devices Grid */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-semibold">
              Discovered Devices
              {mostRecentScan && (
                <span className="ml-2 text-sm text-gray-500">
                  ({devicesList.length} found)
                </span>
              )}
            </h2>
            {isActiveScanning && (
              <div className="flex items-center space-x-2 text-blue-accent">
                <Activity className="w-4 h-4 animate-spin" />
                <span className="text-sm">Scanning...</span>
              </div>
            )}
          </div>

          {devicesFetching && devicesList.length === 0 ? (
            <div className="card text-center text-gray-500 py-12">
              <Loader className="w-8 h-8 mx-auto mb-4 animate-spin" />
              Loading devices...
            </div>
          ) : devicesList.length === 0 ? (
            <div className="card text-center text-gray-500 py-12">
              No devices found. Start a scan to discover devices on your network.
            </div>
          ) : (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {devicesList.map((device) => (
                <DeviceCard 
                  key={device.id} 
                  device={device} 
                  isScanning={isActiveScanning}
                />
              ))}
            </div>
          )}
        </div>

        {/* Scan History Sidebar */}
        <div className="lg:col-span-1">
          <h2 className="text-xl font-semibold mb-4">Scan History</h2>
          <div className="space-y-3">
            {scansFetching && scanList.length === 0 ? (
              <div className="card text-center text-gray-500 py-8">Loading scans...</div>
            ) : scanList.length === 0 ? (
              <div className="card text-center text-gray-500 py-8">
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
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center space-x-2 mb-1">
                          <span className="font-semibold text-sm truncate">{scan.targets.join(', ')}</span>
                          <span className="badge badge-info text-xs">{scan.mode}</span>
                        </div>
                        <div className="text-xs text-gray-500">
                          {formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })}
                        </div>
                        {scan.result_summary && (
                          <div className="text-xs mt-2 space-x-3">
                            <span className="text-green-400">
                              {scan.result_summary.hosts_found} hosts
                            </span>
                            <span className="text-orange-400">
                              {scan.result_summary.vulns_found} vulns
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
      </div>
    </div>
  )
}

export default ScanDevicesPage
