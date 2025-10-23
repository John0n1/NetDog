import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, AlertTriangle, Monitor, Network, Zap, Menu, X } from 'lucide-react'
import { useState } from 'react'
import Console from './Console'
import StatusBadges from './StatusBadges'
import { scans, devices } from '../api'
import { useQuery } from '@tanstack/react-query'

const Navigation = () => {
  const location = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)
  const { data: runningScans } = useQuery({
    queryKey: ['scans', 'running'],
    queryFn: async () => {
      const response = await scans.list({ status_filter: 'running', limit: 100 })
      return response.data
    },
    refetchInterval: 3000,
  })
  
  // Get devices count for active scan
  const { data: devicesCount = 0 } = useQuery({
    queryKey: ['devices', 'count'],
    queryFn: async () => {
      const activeScan = runningScans?.find(scan => 
        scan.status === 'running' || scan.status === 'discovering' || scan.status === 'profiling'
      )
      if (!activeScan) return 0
      const response = await devices.list({ scan_id: activeScan.id, limit: 1000 })
      return response.data.length
    },
    enabled: (runningScans?.length ?? 0) > 0,
    refetchInterval: 2000,
  })
  
  const isScanning = (runningScans?.length ?? 0) > 0
  
  const navItems = [
    { path: '/scan', label: 'Scan & Devices', icon: Activity },
    { path: '/disruptor', label: 'Disruptor', icon: Zap },
    { path: '/netutil', label: 'NetUtil', icon: Network },
    { path: '/vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
  ]
  
  return (
    <nav className="bg-dark-surface border-b border-dark-border">
      <div className="max-w-7xl mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-blue-accent" />
            <span className="text-xl font-bold">NetDog</span>
            
            {/* Devices Discovery Indicator */}
            {isScanning && (
              <div className="flex items-center space-x-2 ml-2" title={`${devicesCount} devices discovered`}>
                <div className="relative">
                  <div className="w-3 h-3 bg-blue-500 rounded-full animate-ping absolute"></div>
                  <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                </div>
                <span className="text-xs text-blue-400 font-semibold">
                  {devicesCount} DEVICES
                </span>
              </div>
            )}
          </div>
          
          {/* Desktop Navigation */}
          <div className="hidden md:flex space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.path || 
                             (item.path === '/scan' && location.pathname === '/')
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center space-x-2 px-4 py-2 rounded transition-colors ${
                    isActive
                      ? 'bg-blue-accent text-white'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span>{item.label}</span>
                </Link>
              )
            })}
          </div>

          {/* Mobile menu toggle */}
          <button
            onClick={() => setMobileOpen((prev) => !prev)}
            className="md:hidden text-gray-400 hover:text-gray-200"
            aria-label="Toggle navigation"
          >
            {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
          
          {/* Status Badges */}
          <div className="hidden md:block">
            <StatusBadges />
          </div>
        </div>
        {/* Mobile Navigation Drawer */}
        {mobileOpen && (
          <div className="md:hidden border-t border-dark-border py-3">
            <div className="flex flex-col space-y-2">
              {navItems.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.path ||
                               (item.path === '/scan' && location.pathname === '/')
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileOpen(false)}
                    className={`flex items-center space-x-3 px-3 py-2 rounded transition-colors ${
                      isActive
                        ? 'bg-blue-accent text-white'
                        : 'text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    <span>{item.label}</span>
                  </Link>
                )
              })}
              <div className="pt-2 border-t border-dark-border">
                <StatusBadges />
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  )
}

const Layout = ({ children }) => {
  return (
    <div className="min-h-screen flex flex-col">
      <Navigation />
      
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Main Content */}
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
        
        {/* Console Pane */}
        <aside className="w-full lg:w-96 border-l border-dark-border">
          <Console />
        </aside>
      </div>
    </div>
  )
}

export default Layout
