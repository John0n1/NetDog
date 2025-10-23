import { AlertTriangle, Shield, Activity } from 'lucide-react'
import { vulnerabilities, scans } from '../api'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '../store/authStore'

const StatusBadges = () => {
  const token = useAuthStore((state) => state.token)
  const enabled = Boolean(token)

  const { data: vulnStats } = useQuery({
    queryKey: ['vulnerabilities', 'stats'],
    queryFn: async () => {
      const response = await vulnerabilities.stats()
      return response.data
    },
    refetchInterval: 10_000,
    enabled,
  })

  const { data: runningScans } = useQuery({
    queryKey: ['scans', 'running'],
    queryFn: async () => {
      const response = await scans.list({ status_filter: 'running', limit: 100 })
      return response.data
    },
    refetchInterval: 5_000,
    enabled,
  })

  const activeScans = runningScans?.length ?? 0
  
  return (
    <div className="flex items-center space-x-2">
      {/* Active Scans */}
      <div className="flex items-center space-x-1 px-2 py-1 bg-dark-bg rounded-full">
        <Activity className={`w-4 h-4 ${activeScans > 0 ? 'text-blue-accent animate-pulse' : 'text-gray-600'}`} />
        <span className="text-xs font-semibold">{activeScans}</span>
      </div>
      
      {/* Vulnerabilities */}
      {vulnStats && (
        <>
          {vulnStats.critical > 0 && (
            <div className="badge badge-critical">
              <AlertTriangle className="w-3 h-3 mr-1" />
              {vulnStats.critical} Critical
            </div>
          )}
          {vulnStats.high > 0 && (
            <div className="badge badge-high">
              {vulnStats.high} High
            </div>
          )}
          {vulnStats.medium > 0 && (
            <div className="badge badge-medium">
              {vulnStats.medium} Medium
            </div>
          )}
        </>
      )}
      
      {/* Status Indicator */}
      <div className="flex items-center space-x-1 px-2 py-1 bg-green-900 text-green-200 rounded-full">
        <Shield className="w-4 h-4" />
        <span className="text-xs font-semibold">Online</span>
      </div>
    </div>
  )
}

export default StatusBadges
