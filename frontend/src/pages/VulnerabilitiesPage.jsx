import { useState, useEffect } from 'react'
import { AlertTriangle, ExternalLink, Shield } from 'lucide-react'
import { vulnerabilities } from '../api'
import { formatDistanceToNow } from 'date-fns'

const VulnerabilitiesPage = () => {
  const [vulnList, setVulnList] = useState([])
  const [stats, setStats] = useState(null)
  const [severityFilter, setSeverityFilter] = useState(null)
  const [selectedVuln, setSelectedVuln] = useState(null)
  const [loading, setLoading] = useState(true)
  
  useEffect(() => {
    fetchData()
  }, [severityFilter])
  
  const fetchData = async () => {
    try {
      const [vulnRes, statsRes] = await Promise.all([
        vulnerabilities.list({ severity: severityFilter, limit: 100 }),
        vulnerabilities.stats()
      ])
      setVulnList(vulnRes.data)
      setStats(statsRes.data)
    } catch (error) {
      console.error('Failed to fetch vulnerabilities:', error)
    } finally {
      setLoading(false)
    }
  }
  
  const fetchVulnDetails = async (vulnId) => {
    try {
      const response = await vulnerabilities.get(vulnId)
      setSelectedVuln(response.data)
    } catch (error) {
      console.error('Failed to fetch vulnerability details:', error)
    }
  }
  
  const getSeverityBadge = (severity) => {
    return (
      <span className={`badge badge-${severity.toLowerCase()}`}>
        {severity}
      </span>
    )
  }
  
  return (
    <div className="max-w-7xl mx-auto">
      <h1 className="text-3xl font-bold mb-6">Vulnerabilities</h1>
      
      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div
            onClick={() => setSeverityFilter(null)}
            className={`card cursor-pointer hover:bg-dark-hover transition-colors ${!severityFilter ? 'ring-2 ring-blue-accent' : ''}`}
          >
            <div className="text-2xl font-bold">{stats.total}</div>
            <div className="text-sm text-gray-500">Total</div>
          </div>
          <div
            onClick={() => setSeverityFilter('CRITICAL')}
            className={`card cursor-pointer hover:bg-dark-hover transition-colors ${severityFilter === 'CRITICAL' ? 'ring-2 ring-red-500' : ''}`}
          >
            <div className="text-2xl font-bold text-red-500">{stats.critical}</div>
            <div className="text-sm text-gray-500">Critical</div>
          </div>
          <div
            onClick={() => setSeverityFilter('HIGH')}
            className={`card cursor-pointer hover:bg-dark-hover transition-colors ${severityFilter === 'HIGH' ? 'ring-2 ring-orange-500' : ''}`}
          >
            <div className="text-2xl font-bold text-orange-500">{stats.high}</div>
            <div className="text-sm text-gray-500">High</div>
          </div>
          <div
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`card cursor-pointer hover:bg-dark-hover transition-colors ${severityFilter === 'MEDIUM' ? 'ring-2 ring-yellow-500' : ''}`}
          >
            <div className="text-2xl font-bold text-yellow-500">{stats.medium}</div>
            <div className="text-sm text-gray-500">Medium</div>
          </div>
          <div
            onClick={() => setSeverityFilter('LOW')}
            className={`card cursor-pointer hover:bg-dark-hover transition-colors ${severityFilter === 'LOW' ? 'ring-2 ring-blue-500' : ''}`}
          >
            <div className="text-2xl font-bold text-blue-500">{stats.low}</div>
            <div className="text-sm text-gray-500">Low</div>
          </div>
        </div>
      )}
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability List */}
        <div className="space-y-3">
          {loading ? (
            <div className="card text-center py-12 text-gray-500">
              Loading vulnerabilities...
            </div>
          ) : vulnList.length === 0 ? (
            <div className="card text-center py-12 text-gray-500">
              <Shield className="w-12 h-12 mx-auto mb-3 text-green-500" />
              No vulnerabilities found
              {severityFilter && ' with selected severity'}
            </div>
          ) : (
            vulnList.map((vuln) => (
              <div
                key={vuln.id}
                onClick={() => fetchVulnDetails(vuln.id)}
                className="card hover:bg-dark-hover cursor-pointer transition-colors"
              >
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="w-5 h-5 text-orange-500" />
                    <span className="font-mono font-semibold">{vuln.cve}</span>
                  </div>
                  {getSeverityBadge(vuln.severity)}
                </div>
                {vuln.cvss_score && (
                  <div className="text-sm mb-2">
                    <span className="text-gray-500">CVSS Score: </span>
                    <span className="font-semibold">{vuln.cvss_score.toFixed(1)}</span>
                  </div>
                )}
                <div className="text-sm text-gray-400 line-clamp-2 mb-2">
                  {vuln.summary}
                </div>
                <div className="text-xs text-gray-600">
                  Discovered {formatDistanceToNow(new Date(vuln.first_seen), { addSuffix: true })}
                </div>
              </div>
            ))
          )}
        </div>
        
        {/* Vulnerability Details */}
        <div className="lg:sticky lg:top-6 h-fit">
          {selectedVuln ? (
            <div className="card">
              <div className="flex items-start justify-between mb-4">
                <h2 className="text-xl font-semibold font-mono">{selectedVuln.cve}</h2>
                {getSeverityBadge(selectedVuln.severity)}
              </div>
              
              <div className="space-y-4">
                {selectedVuln.cvss_score && (
                  <div>
                    <div className="text-sm text-gray-500">CVSS Score</div>
                    <div className="text-2xl font-bold">{selectedVuln.cvss_score.toFixed(1)}</div>
                  </div>
                )}
                
                {selectedVuln.summary && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2">Summary</div>
                    <div className="text-sm">{selectedVuln.summary}</div>
                  </div>
                )}
                
                {selectedVuln.description && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2">Description</div>
                    <div className="text-sm text-gray-400">{selectedVuln.description}</div>
                  </div>
                )}
                
                {selectedVuln.published_date && (
                  <div>
                    <div className="text-sm text-gray-500">Published</div>
                    <div className="text-sm">
                      {new Date(selectedVuln.published_date).toLocaleDateString()}
                    </div>
                  </div>
                )}
                
                {selectedVuln.affected_devices && selectedVuln.affected_devices.length > 0 && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2">Affected Devices</div>
                    <div className="text-sm">
                      {selectedVuln.affected_devices.length} device(s)
                    </div>
                  </div>
                )}
                
                {selectedVuln.references && selectedVuln.references.length > 0 && (
                  <div>
                    <div className="text-sm text-gray-500 mb-2">References</div>
                    <div className="space-y-1 max-h-48 overflow-auto">
                      {selectedVuln.references.map((ref, idx) => (
                        <a
                          key={idx}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center space-x-1 text-sm text-blue-accent hover:underline"
                        >
                          <ExternalLink className="w-3 h-3" />
                          <span className="truncate">{ref}</span>
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="card text-center py-12 text-gray-500">
              Select a vulnerability to view details
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default VulnerabilitiesPage
