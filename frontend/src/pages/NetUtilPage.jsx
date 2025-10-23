import { useState } from 'react'
import { Send, Zap, Globe, Route, Scan } from 'lucide-react'
import { netutil } from '../api'

const NetUtilPage = () => {
  const [activeTab, setActiveTab] = useState('ping')
  const [loadingState, setLoadingState] = useState({ ping: false, speedtest: false, dns: false, traceroute: false, portscan: false })
  const [results, setResults] = useState({ ping: null, speedtest: null, dns: null, traceroute: null, portscan: null })
  const [errors, setErrors] = useState({ ping: null, speedtest: null, dns: null, traceroute: null, portscan: null })
  
  // Ping state
  const [pingData, setPingData] = useState({
    target: '',
    count: 4,
  })
  
  // DNS lookup state
  const [dnsHostname, setDnsHostname] = useState('')

  // Traceroute state
  const [tracerouteData, setTracerouteData] = useState({
    target: '',
    max_hops: 20,
    attempts: 3,
  })

  // Port scan state
  const [portScanData, setPortScanData] = useState({
    target: '',
    ports: '22,80,443,3389',
    timeout: 1.0,
  })

  const setLoading = (key, value) => {
    setLoadingState((prev) => ({ ...prev, [key]: value }))
  }
  const setResultFor = (key, payload) => {
    setResults((prev) => ({ ...prev, [key]: payload }))
  }
  const setErrorFor = (key, message) => {
    setErrors((prev) => ({ ...prev, [key]: message }))
  }
  
  const handlePing = async (e) => {
    e.preventDefault()
    setLoading('ping', true)
    setResultFor('ping', null)
    setErrorFor('ping', null)
    
    try {
      const response = await netutil.ping({
        ...pingData,
        consent: { approved: true, by: 'user', reason: 'network test' }
      })
      setResultFor('ping', response.data)
    } catch (error) {
      setErrorFor('ping', error.response?.data?.detail || error.message)
    } finally {
      setLoading('ping', false)
    }
  }
  
  const handleSpeedTest = async (e) => {
    e.preventDefault()
    setLoading('speedtest', true)
    setResultFor('speedtest', null)
    setErrorFor('speedtest', null)
    
    try {
      const response = await netutil.speedtest({
        consent: { approved: true, by: 'user', reason: 'speed test' }
      })
      setResultFor('speedtest', response.data)
    } catch (error) {
      setErrorFor('speedtest', error.response?.data?.detail || error.message)
    } finally {
      setLoading('speedtest', false)
    }
  }
  
  const handleDnsLookup = async (e) => {
    e.preventDefault()
    setLoading('dns', true)
    setResultFor('dns', null)
    setErrorFor('dns', null)
    
    try {
      const response = await netutil.dnsLookup(dnsHostname)
      setResultFor('dns', response.data)
    } catch (error) {
      setErrorFor('dns', error.response?.data?.detail || error.message)
    } finally {
      setLoading('dns', false)
    }
  }

  const handleTraceroute = async (e) => {
    e.preventDefault()
    const target = tracerouteData.target.trim()
    if (!target) {
      setErrorFor('traceroute', 'Target host is required')
      return
    }

    setLoading('traceroute', true)
    setResultFor('traceroute', null)
    setErrorFor('traceroute', null)

    try {
      const payload = {
        target,
        max_hops: Number(tracerouteData.max_hops) || 20,
        attempts: Number(tracerouteData.attempts) || 3,
      }
      const response = await netutil.traceroute(payload)
      setResultFor('traceroute', response.data)
    } catch (error) {
      setErrorFor('traceroute', error.response?.data?.detail || error.message)
    } finally {
      setLoading('traceroute', false)
    }
  }

  const handlePortScan = async (e) => {
    e.preventDefault()
    const target = portScanData.target.trim()
    if (!target) {
      setErrorFor('portscan', 'Target host is required')
      return
    }

    const ports = portScanData.ports
      .split(/[\s,]+/)
      .map((value) => parseInt(value, 10))
      .filter((value) => !Number.isNaN(value) && value > 0 && value <= 65535)

    if (ports.length === 0) {
      setErrorFor('portscan', 'Provide at least one valid port')
      return
    }

    setLoading('portscan', true)
    setResultFor('portscan', null)
    setErrorFor('portscan', null)

    try {
      const response = await netutil.portScan({
        target,
        ports,
        timeout: Number(portScanData.timeout) || 1.0,
      })
      setResultFor('portscan', response.data)
    } catch (error) {
      setErrorFor('portscan', error.response?.data?.detail || error.message)
    } finally {
      setLoading('portscan', false)
    }
  }

  const activeResult = results[activeTab]
  const activeError = errors[activeTab]
  const isLoading = loadingState[activeTab]
  const tabLabels = {
    ping: 'Ping test',
    speedtest: 'Speed test',
    dns: 'DNS lookup',
    traceroute: 'Traceroute',
    portscan: 'Port scan',
  }
  
  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold mb-2">Network Utilities</h1>
        <p className="text-gray-400">Diagnostic tools for network testing</p>
      </div>
      
      {/* Tabs */}
      <div className="card mb-6">
        <div className="flex space-x-1 mb-6 border-b border-dark-border">
          {[
            { id: 'ping', label: 'Ping', icon: Send },
            { id: 'speedtest', label: 'Speed Test', icon: Zap },
            { id: 'dns', label: 'DNS Lookup', icon: Globe },
            { id: 'traceroute', label: 'Traceroute', icon: Route },
            { id: 'portscan', label: 'Port Scan', icon: Scan },
          ].map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-2 font-semibold ${
                  activeTab === tab.id
                    ? 'text-blue-accent border-b-2 border-blue-accent'
                    : 'text-gray-500'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            )
          })}
        </div>
        
        {/* Ping Tab */}
        {activeTab === 'ping' && (
          <div>
            <h2 className="text-xl font-semibold mb-4">Ping Test</h2>
            <form onSubmit={handlePing} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Target Host</label>
                <input
                  type="text"
                  value={pingData.target}
                  onChange={(e) => setPingData({ ...pingData, target: e.target.value })}
                  className="input w-full"
                  placeholder="8.8.8.8 or google.com"
                  required
                />
              </div>
              
              <div>
                <label className="block text-sm font-semibold mb-2">Packet Count</label>
                <input
                  type="number"
                  value={pingData.count}
                  onChange={(e) => setPingData({ ...pingData, count: parseInt(e.target.value) })}
                  className="input w-full"
                  min="1"
                  max="100"
                  required
                />
              </div>
              
              <button type="submit" disabled={loadingState.ping} className="btn-primary">
                {loadingState.ping ? 'Running...' : 'Run Ping'}
              </button>
            </form>
          </div>
        )}
        
        {/* Speed Test Tab */}
        {activeTab === 'speedtest' && (
          <div>
            <h2 className="text-xl font-semibold mb-4">Internet Speed Test</h2>
            <p className="text-gray-400 mb-4">
              Test your internet connection speed. This may take up to 60 seconds.
            </p>
            
            <form onSubmit={handleSpeedTest} className="space-y-4">
              <button type="submit" disabled={loadingState.speedtest} className="btn-primary">
                {loadingState.speedtest ? 'Testing... (this may take a minute)' : 'Start Speed Test'}
              </button>
            </form>
          </div>
        )}
        
        {/* DNS Lookup Tab */}
        {activeTab === 'dns' && (
          <div>
            <h2 className="text-xl font-semibold mb-4">DNS Lookup</h2>
            <form onSubmit={handleDnsLookup} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Hostname</label>
                <input
                  type="text"
                  value={dnsHostname}
                  onChange={(e) => setDnsHostname(e.target.value)}
                  className="input w-full"
                  placeholder="example.com"
                  required
                />
              </div>
              
              <button type="submit" disabled={loadingState.dns} className="btn-primary">
                {loadingState.dns ? 'Looking up...' : 'Lookup'}
              </button>
            </form>
          </div>
        )}

        {/* Traceroute Tab */}
        {activeTab === 'traceroute' && (
          <div>
            <h2 className="text-xl font-semibold mb-4">Traceroute</h2>
            <p className="text-gray-400 mb-4">
              Trace the path packets take to reach the destination. Useful for diagnosing routing issues.
            </p>
            <form onSubmit={handleTraceroute} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Target Host</label>
                <input
                  type="text"
                  value={tracerouteData.target}
                  onChange={(e) => setTracerouteData({ ...tracerouteData, target: e.target.value })}
                  className="input w-full"
                  placeholder="example.com"
                  required
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold mb-2">Max Hops</label>
                  <input
                    type="number"
                    min="1"
                    max="64"
                    value={tracerouteData.max_hops}
                    onChange={(e) => setTracerouteData({ ...tracerouteData, max_hops: parseInt(e.target.value, 10) })}
                    className="input w-full"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Attempts Per Hop</label>
                  <input
                    type="number"
                    min="1"
                    max="5"
                    value={tracerouteData.attempts}
                    onChange={(e) => setTracerouteData({ ...tracerouteData, attempts: parseInt(e.target.value, 10) })}
                    className="input w-full"
                  />
                </div>
              </div>
              <button type="submit" disabled={loadingState.traceroute} className="btn-primary">
                {loadingState.traceroute ? 'Tracing route...' : 'Run Traceroute'}
              </button>
            </form>
          </div>
        )}

        {/* Port Scan Tab */}
        {activeTab === 'portscan' && (
          <div>
            <h2 className="text-xl font-semibold mb-4">Quick Port Scan</h2>
            <p className="text-gray-400 mb-4">
              Probe a host for common open TCP ports to assess exposed services.
            </p>
            <form onSubmit={handlePortScan} className="space-y-4">
              <div>
                <label className="block text-sm font-semibold mb-2">Target Host</label>
                <input
                  type="text"
                  value={portScanData.target}
                  onChange={(e) => setPortScanData({ ...portScanData, target: e.target.value })}
                  className="input w-full"
                  placeholder="192.168.1.10"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Ports (comma or space separated)</label>
                <input
                  type="text"
                  value={portScanData.ports}
                  onChange={(e) => setPortScanData({ ...portScanData, ports: e.target.value })}
                  className="input w-full"
                  placeholder="22,80,443,3389"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-semibold mb-2">Timeout per Port (seconds)</label>
                <input
                  type="number"
                  min="0.1"
                  max="5"
                  step="0.1"
                  value={portScanData.timeout}
                  onChange={(e) => setPortScanData({ ...portScanData, timeout: parseFloat(e.target.value) })}
                  className="input w-full"
                />
              </div>
              <button type="submit" disabled={loadingState.portscan} className="btn-primary">
                {loadingState.portscan ? 'Scanning...' : 'Run Port Scan'}
              </button>
            </form>
          </div>
        )}
      </div>
      
      {/* Results */}
      {(activeResult || activeError || isLoading) && (
        <div className="card">
          <h2 className="text-xl font-semibold mb-4">Results</h2>
          
          {isLoading && (
            <div className="mb-4 text-sm text-blue-accent">
              Running {tabLabels[activeTab]}...
            </div>
          )}

          {activeError ? (
            <div className="bg-red-900 text-red-200 px-4 py-3 rounded">
              {activeError}
            </div>
          ) : activeTab === 'ping' && activeResult ? (
            <div className="space-y-2 font-mono text-sm">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-gray-500">Packets Sent:</span>
                  <span className="ml-2 text-blue-accent">{activeResult.packets_sent}</span>
                </div>
                <div>
                  <span className="text-gray-500">Packets Received:</span>
                  <span className="ml-2 text-green-400">{activeResult.packets_received}</span>
                </div>
                <div>
                  <span className="text-gray-500">Packet Loss:</span>
                  <span className="ml-2 text-red-400">{activeResult.packet_loss_percent}%</span>
                </div>
                <div>
                  <span className="text-gray-500">Avg RTT:</span>
                  <span className="ml-2 text-yellow-400">{activeResult.avg_rtt} ms</span>
                </div>
              </div>
              
              {activeResult.output && (
                <div className="mt-4 bg-dark-bg p-4 rounded overflow-x-auto">
                  <pre className="text-xs text-gray-400">{activeResult.output}</pre>
                </div>
              )}
            </div>
          ) : activeTab === 'speedtest' && activeResult ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="card bg-dark-bg">
                  <div className="text-gray-500 text-sm mb-1">Download</div>
                  <div className="text-2xl font-bold text-green-400">
                    {Number(activeResult.download_mbps).toFixed(2)} Mbps
                  </div>
                </div>
                <div className="card bg-dark-bg">
                  <div className="text-gray-500 text-sm mb-1">Upload</div>
                  <div className="text-2xl font-bold text-blue-accent">
                    {Number(activeResult.upload_mbps).toFixed(2)} Mbps
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 font-mono text-sm">
                <div>
                  <span className="text-gray-500">Ping:</span>
                  <span className="ml-2 text-yellow-400">{Number(activeResult.ping_ms).toFixed(2)} ms</span>
                </div>
                <div>
                  <span className="text-gray-500">Server:</span>
                  <span className="ml-2 text-gray-300">{activeResult.server}</span>
                </div>
                {activeResult.server_location && (
                  <div>
                    <span className="text-gray-500">Location:</span>
                    <span className="ml-2 text-gray-300">{activeResult.server_location}</span>
                  </div>
                )}
                {activeResult.isp && (
                  <div>
                    <span className="text-gray-500">ISP:</span>
                    <span className="ml-2 text-gray-300">{activeResult.isp}</span>
                  </div>
                )}
                <div>
                  <span className="text-gray-500">Timestamp:</span>
                  <span className="ml-2 text-gray-300">{new Date(activeResult.timestamp).toLocaleString()}</span>
                </div>
              </div>

              {activeResult.result_url && (
                <a
                  href={activeResult.result_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center text-sm text-blue-accent hover:underline"
                >
                  View full speedtest report
                </a>
              )}
            </div>
          ) : activeTab === 'dns' && activeResult ? (
            <div className="space-y-4 font-mono text-sm">
              <div>
                <span className="text-gray-500">Hostname:</span>
                <span className="ml-2 text-blue-accent">{activeResult.hostname}</span>
              </div>
              {activeResult.canonical_name && (
                <div>
                  <span className="text-gray-500">Canonical Name:</span>
                  <span className="ml-2 text-gray-300">{activeResult.canonical_name}</span>
                </div>
              )}
              {activeResult.aliases && activeResult.aliases.length > 0 && (
                <div>
                  <span className="text-gray-500">Aliases:</span>
                  <div className="mt-1 space-y-1">
                    {activeResult.aliases.map((alias) => (
                      <div key={alias} className="text-gray-300">{alias}</div>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <span className="text-gray-500">IPv4:</span>
                <div className="mt-1 space-y-1">
                  {!activeResult.ipv4_addresses || activeResult.ipv4_addresses.length === 0 ? (
                    <div className="text-gray-600">No IPv4 addresses returned</div>
                  ) : (
                    activeResult.ipv4_addresses.map((ip) => (
                      <div key={ip} className="text-green-400">{ip}</div>
                    ))
                  )}
                </div>
              </div>
              <div>
                <span className="text-gray-500">IPv6:</span>
                <div className="mt-1 space-y-1">
                  {!activeResult.ipv6_addresses || activeResult.ipv6_addresses.length === 0 ? (
                    <div className="text-gray-600">No IPv6 addresses returned</div>
                  ) : (
                    activeResult.ipv6_addresses.map((ip) => (
                      <div key={ip} className="text-green-400">{ip}</div>
                    ))
                  )}
                </div>
              </div>
              {activeResult.reverse_dns && (
                <div>
                  <span className="text-gray-500">Reverse DNS:</span>
                  <span className="ml-2 text-gray-300">{activeResult.reverse_dns}</span>
                </div>
              )}
              {activeResult.name_servers && activeResult.name_servers.length > 0 && (
                <div>
                  <span className="text-gray-500">Name Servers:</span>
                  <div className="mt-1 space-y-1">
                    {activeResult.name_servers.map((ns) => (
                      <div key={ns} className="text-gray-300">{ns}</div>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <span className="text-gray-500">Resolved:</span>
                <span className="ml-2 text-gray-300">{new Date(activeResult.resolved_at).toLocaleString()}</span>
              </div>
            </div>
          ) : activeTab === 'traceroute' && activeResult ? (
            <div className="space-y-4">
              <div className="text-sm text-gray-400">
                {activeResult.completed ? 'Route traced successfully.' : 'Route incomplete. Last reachable hop shown below.'}
              </div>
              <div className="overflow-auto max-h-80">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-gray-500 text-left">
                      <th className="pb-2">Hop</th>
                      <th className="pb-2">Host</th>
                      <th className="pb-2">IP</th>
                      <th className="pb-2 text-right">Avg RTT (ms)</th>
                    </tr>
                  </thead>
                  <tbody className="text-gray-300">
                    {(!activeResult.hops || activeResult.hops.length === 0) ? (
                      <tr>
                        <td colSpan={4} className="py-3 text-center text-gray-500">No hop data available.</td>
                      </tr>
                    ) : (
                      activeResult.hops.map((hop) => (
                        <tr key={hop.hop} className="border-t border-dark-border">
                          <td className="py-2">{hop.hop}</td>
                          <td className="py-2">{hop.host || '-'}</td>
                          <td className="py-2">{hop.ip || '-'}</td>
                          <td className="py-2 text-right">{hop.rtt_ms ? hop.rtt_ms.toFixed(2) : '—'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ) : activeTab === 'portscan' && activeResult ? (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-500">Target:</span>
                  <span className="ml-2 text-gray-300">{activeResult.target}</span>
                </div>
                <div>
                  <span className="text-gray-500">Duration:</span>
                  <span className="ml-2 text-gray-300">{activeResult.duration_ms.toFixed(0)} ms</span>
                </div>
              </div>
              <div className="space-y-1 text-sm font-mono">
                {(activeResult.results || []).map((entry) => (
                  <div
                    key={entry.port}
                    className={`flex items-center justify-between px-3 py-2 rounded ${
                      entry.status === 'open'
                        ? 'bg-green-900 text-green-200'
                        : entry.status === 'filtered'
                          ? 'bg-yellow-900 text-yellow-200'
                          : 'bg-dark-bg text-gray-300'
                    }`}
                  >
                    <span>Port {entry.port}</span>
                    <span className="uppercase text-xs tracking-wider">{entry.status}</span>
                    <span className="text-xs text-gray-200">
                      {entry.service_guess ? entry.service_guess : '—'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            !isLoading && (
              <div className="text-sm text-gray-500">No results yet.</div>
            )
          )}
        </div>
      )}
    </div>
  )
}

export default NetUtilPage
