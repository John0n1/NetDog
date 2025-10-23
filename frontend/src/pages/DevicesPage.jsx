import { useState, useEffect } from 'react'
import { Monitor, AlertTriangle, Activity } from 'lucide-react'
import { devices } from '../api'
import { formatDistanceToNow } from 'date-fns'

const DevicesPage = () => {
  const [deviceList, setDeviceList] = useState([])
  const [selectedDevice, setSelectedDevice] = useState(null)
  const [loading, setLoading] = useState(true)
  
  useEffect(() => {
    fetchDevices()
  }, [])
  
  const fetchDevices = async () => {
    try {
      const response = await devices.list({ limit: 100 })
      setDeviceList(response.data)
    } catch (error) {
      console.error('Failed to fetch devices:', error)
    } finally {
      setLoading(false)
    }
  }
  
  const fetchDeviceDetails = async (deviceId) => {
    try {
      const response = await devices.get(deviceId)
      setSelectedDevice(response.data)
    } catch (error) {
      console.error('Failed to fetch device details:', error)
    }
  }
  
  const getRiskColor = (score) => {
    if (score >= 75) return 'text-red-500'
    if (score >= 50) return 'text-orange-500'
    if (score >= 25) return 'text-yellow-500'
    return 'text-green-500'
  }
  
  return (
    <div className="max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Discovered Devices</h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device List */}
        <div className="space-y-3">
          {loading ? (
            <div className="card text-center py-12 text-gray-500">
              <Activity className="w-8 h-8 mx-auto mb-2 animate-spin" />
              Loading devices...
            </div>
          ) : deviceList.length === 0 ? (
            <div className="card text-center py-12 text-gray-500">
              No devices found. Run a scan to discover devices on your network.
            </div>
          ) : (
            deviceList.map((device) => (
              <div
                key={device.id}
                onClick={() => fetchDeviceDetails(device.id)}
                className="card hover:bg-dark-hover cursor-pointer transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <Monitor className="w-6 h-6 text-blue-accent mt-1" />
                    <div>
                      <div className="font-semibold">{device.ip}</div>
                      {device.hostname && (
                        <div className="text-sm text-gray-400">{device.hostname}</div>
                      )}
                      {device.device_type && (
                        <div className="inline-block mt-1">
                          <span className="px-2 py-1 text-xs font-semibold bg-blue-900 text-blue-200 rounded">
                            {device.device_type}
                          </span>
                        </div>
                      )}
                      {device.os_guess && !device.device_type && (
                        <div className="text-sm text-gray-500">{device.os_guess}</div>
                      )}
                      <div className="text-xs text-gray-600 mt-1">
                        Last seen {formatDistanceToNow(new Date(device.last_seen), { addSuffix: true })}
                      </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-lg font-bold ${getRiskColor(device.risk_score)}`}>
                      {device.risk_score.toFixed(1)}
                    </div>
                    <div className="text-xs text-gray-500">Risk Score</div>
                    {device.open_ports && device.open_ports.length > 0 && (
                      <div className="text-xs text-gray-500 mt-1">
                        {device.open_ports.length} open ports
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
        
        {/* Device Details */}
        <div className="lg:sticky lg:top-6 h-fit">
          {selectedDevice ? (
            <div className="card">
              <h2 className="text-xl font-semibold mb-4">Device Details</h2>
              
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-gray-500">IP Address</div>
                  <div className="font-mono">{selectedDevice.ip}</div>
                </div>
                
                {selectedDevice.hostname && (
                  <div>
                    <div className="text-sm text-gray-500">Hostname</div>
                    <div>{selectedDevice.hostname}</div>
                  </div>
                )}
                
                {selectedDevice.device_type && (
                  <div>
                    <div className="text-sm text-gray-500">Device Type</div>
                    <div className="inline-block">
                      <span className="px-3 py-1 text-sm font-semibold bg-blue-900 text-blue-200 rounded">
                        {selectedDevice.device_type}
                      </span>
                    </div>
                  </div>
                )}
                
                {selectedDevice.os_guess && (
                  <div>
                    <div className="text-sm text-gray-500">Operating System</div>
                    <div>{selectedDevice.os_guess}</div>
                  </div>
                )}
                
                {selectedDevice.vendor && (
                  <div>
                    <div className="text-sm text-gray-500">Vendor</div>
                    <div>{selectedDevice.vendor}</div>
                  </div>
                )}
                
                {selectedDevice.mac_address && (
                  <div>
                    <div className="text-sm text-gray-500">MAC Address</div>
                    <div className="font-mono">{selectedDevice.mac_address}</div>
                  </div>
                )}
                
                <div>
                  <div className="text-sm text-gray-500 mb-2">Risk Score</div>
                  <div className={`text-2xl font-bold ${getRiskColor(selectedDevice.risk_score)}`}>
                    {selectedDevice.risk_score.toFixed(1)} / 100
                  </div>
                </div>
                
                {/* Open Ports */}
                {selectedDevice.open_ports && selectedDevice.open_ports.length > 0 && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2">Open Ports</div>
                    <div className="space-y-1 max-h-64 overflow-auto">
                      {selectedDevice.open_ports.map((port, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between text-sm bg-dark-bg p-2 rounded"
                        >
                          <span className="font-mono">{port.port}/{port.protocol}</span>
                          <span className="text-gray-400">{port.service}</span>
                          {port.version && (
                            <span className="text-xs text-gray-600">{port.version}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Vulnerabilities */}
                {selectedDevice.vulnerabilities && selectedDevice.vulnerabilities.length > 0 && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2 flex items-center">
                      <AlertTriangle className="w-4 h-4 mr-1 text-orange-500" />
                      Vulnerabilities ({selectedDevice.vulnerabilities.length})
                    </div>
                    <div className="space-y-2 max-h-64 overflow-auto">
                      {selectedDevice.vulnerabilities.map((vuln) => (
                        <div key={vuln.id} className="bg-dark-bg p-3 rounded">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-mono text-sm">{vuln.cve}</span>
                            <span className={`badge badge-${vuln.severity.toLowerCase()}`}>
                              {vuln.severity}
                            </span>
                          </div>
                          <div className="text-xs text-gray-400 line-clamp-2">
                            {vuln.summary}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card text-center py-12 text-gray-500">
              Select a device to view details
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default DevicesPage
