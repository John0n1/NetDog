import { useState, useEffect, useRef } from 'react'
import { Terminal, X, Minimize2, Maximize2, Power } from 'lucide-react'
import { createWebSocket } from '../api'

const Console = () => {
  const [logs, setLogs] = useState([])
  const [isMinimized, setIsMinimized] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [liveEnabled, setLiveEnabled] = useState(() => {
    try {
      const stored = localStorage.getItem('console-live-enabled')
      return stored ? stored === 'true' : true
    } catch (error) {
      return true
    }
  })
  const logsEndRef = useRef(null)
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)
  const reconnectAttemptsRef = useRef(0)
  
  useEffect(() => {
    try {
      localStorage.setItem('console-live-enabled', liveEnabled.toString())
    } catch (error) {
      console.debug('Unable to persist console live setting:', error)
    }
  }, [liveEnabled])

  useEffect(() => {
    if (!liveEnabled) {
      if (wsRef.current) {
        wsRef.current.close(1000)
        wsRef.current = null
      }
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current)
        reconnectRef.current = null
      }
      reconnectAttemptsRef.current = 0
      addLog('INFO', 'console', 'Live stream paused')
      return
    }

    // Don't connect if no token
    let token = null
    try {
      const authStorage = localStorage.getItem('auth-storage')
      if (authStorage) {
        const parsed = JSON.parse(authStorage)
        token = parsed.state?.token
      }
    } catch (e) {
      token = localStorage.getItem('token')
    }
    
    if (!token || token === 'null' || token === 'undefined') {
      addLog('WARN', 'console', 'Log stream requires an authenticated session')
      return
    }

    let shouldReconnect = true
    const maxReconnectAttempts = 5
    const reconnectDelay = 3000 // 3 seconds

    const connect = () => {
      try {
        const ws = createWebSocket('/api/v1/ws/logs')
        wsRef.current = ws

        ws.onopen = () => {
          reconnectAttemptsRef.current = 0
          addLog('INFO', 'console', 'Connected to log stream')
        }

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data)
            if (data.type === 'console.log') {
              const log = data.data
              setLogs((prev) => [...prev.slice(-200), log])
            }
          } catch (err) {
            console.error('Failed to parse log message:', err)
          }
        }

        ws.onerror = (error) => {
          console.error('WebSocket error:', error)
          addLog('ERROR', 'console', 'WebSocket connection error')
        }

        ws.onclose = (event) => {
          wsRef.current = null
          if (!shouldReconnect) {
            return
          }

          addLog('WARN', 'console', 'Disconnected from log stream')
          if (event.code === 1000) {
            return
          }

          if (reconnectAttemptsRef.current < maxReconnectAttempts) {
            reconnectAttemptsRef.current += 1
            addLog('INFO', 'console', `Reconnecting in ${reconnectDelay / 1000}s... (attempt ${reconnectAttemptsRef.current}/${maxReconnectAttempts})`)
            reconnectRef.current = setTimeout(connect, reconnectDelay)
          } else {
            addLog('ERROR', 'console', 'Max reconnection attempts reached. Refresh to retry.')
          }
        }
      } catch (error) {
        console.error('Failed to create WebSocket:', error)
        addLog('ERROR', 'console', 'Failed to create WebSocket: ' + error.message)
      }
    }

    connect()

    return () => {
      shouldReconnect = false
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current)
        reconnectRef.current = null
      }
      if (wsRef.current) {
        wsRef.current.close(1000)
        wsRef.current = null
      }
    }
  }, [liveEnabled])
  
  useEffect(() => {
    if (autoScroll) {
      logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  useEffect(() => {
    addLog('INFO', 'console', 'Console ready')
  }, [])
  
  const addLog = (level, source, text) => {
    setLogs(prev => [...prev.slice(-200), {
      timestamp: new Date().toISOString(),
      level,
      source,
      text
    }])
  }
  
  const clearLogs = () => {
    setLogs([])
  }
  
  const getLevelColor = (level) => {
    switch (level) {
      case 'ERROR': return 'text-red-400'
      case 'WARN': return 'text-yellow-400'
      case 'INFO': return 'text-blue-400'
      case 'DEBUG': return 'text-gray-500'
      default: return 'text-gray-400'
    }
  }
  
  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', { hour12: false })
  }
  
  if (isMinimized) {
    return (
      <div className="h-12 bg-dark-surface border-t border-dark-border flex items-center justify-between px-4">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-blue-accent" />
          <span className="text-sm font-semibold">Console</span>
          <span className="text-xs text-gray-500">({logs.length} logs)</span>
        </div>
        <button
          onClick={() => setIsMinimized(false)}
          className="text-gray-400 hover:text-gray-200"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
      </div>
    )
  }
  
  return (
    <div className="h-full flex flex-col bg-dark-surface">
      {/* Header */}
      <div className="flex items-center justify-between p-3 border-b border-dark-border">
        <div className="flex items-center space-x-2">
          <Terminal className="w-5 h-5 text-blue-accent" />
          <span className="font-semibold">Console</span>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setLiveEnabled((prev) => !prev)}
            className={`flex items-center space-x-1 text-xs px-2 py-1 rounded ${
              liveEnabled ? 'bg-green-900 text-green-200' : 'bg-dark-bg text-gray-400'
            }`}
          >
            <Power className="w-3 h-3" />
            <span>{liveEnabled ? 'Live' : 'Paused'}</span>
          </button>
          <label className="flex items-center space-x-1 text-xs">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded"
            />
            <span>Auto-scroll</span>
          </label>
          <button
            onClick={clearLogs}
            className="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 rounded hover:bg-dark-hover"
          >
            Clear
          </button>
          <button
            onClick={() => setIsMinimized(true)}
            className="text-gray-400 hover:text-gray-200"
          >
            <Minimize2 className="w-4 h-4" />
          </button>
        </div>
      </div>
      
      {/* Logs */}
      <div className="flex-1 overflow-auto p-3 space-y-1 font-mono text-xs">
        {logs.length === 0 ? (
          <div className="text-gray-600 text-center py-8">
            {!localStorage.getItem('token') ? (
              <div>
                <p className="mb-2">Not connected to log stream</p>
                <p className="text-sm">Please log in to see activity</p>
              </div>
            ) : (
              'No logs yet. Start a scan to see activity.'
            )}
          </div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} className="flex space-x-2">
              <span className="text-gray-600">{formatTime(log.timestamp)}</span>
              <span className={`font-semibold ${getLevelColor(log.level)}`}>
                [{log.level}]
              </span>
              <span className="text-gray-500">[{log.source}]</span>
              <span className="text-gray-300">{log.text}</span>
            </div>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  )
}

export default Console
