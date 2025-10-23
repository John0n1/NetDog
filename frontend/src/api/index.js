import axios from 'axios'
import { useAuthStore } from '../store/authStore'

// Use the same host as the page for API calls
const protocol = window.location.protocol
const host = import.meta.env.VITE_API_HOST || window.location.hostname
const port = import.meta.env.VITE_API_PORT || '8000'
const API_URL = import.meta.env.VITE_API_URL || `${protocol}//${host}:${port}`

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Helper to read the token from store/persisted state without triggering React hooks
const getStoredToken = () => {
  const authState = useAuthStore.getState()
  if (authState?.token) {
    return authState.token
  }

  if (typeof localStorage === 'undefined') {
    return null
  }

  try {
    const authStorage = localStorage.getItem('auth-storage')
    if (authStorage) {
      const parsed = JSON.parse(authStorage)
      return parsed.state?.token ?? null
    }
  } catch (error) {
    try {
      return localStorage.getItem('token')
    } catch (fallbackError) {
      console.debug('Unable to access token from storage:', fallbackError)
    }
  }

  return null
}

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const isAuthRequest = error.config?.url?.includes('/api/v1/auth/token')
    if (error.response?.status === 401 && !isAuthRequest) {
      try {
        useAuthStore.getState().logout()
      } catch (storeError) {
        console.debug('Failed to reset auth store after 401:', storeError)
      }
      try {
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem('auth-storage')
          localStorage.removeItem('token')
        }
      } catch (storageError) {
        console.debug('Failed to clear persisted auth state:', storageError)
      }
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth
export const auth = {
  login: (username, password) =>
    api.post('/api/v1/auth/token', new URLSearchParams({ username, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }),
  register: (data) => api.post('/api/v1/auth/register', data),
  getMe: () => api.get('/api/v1/auth/me'),
}

// Scans
export const scans = {
  create: (data) => api.post('/api/v1/scan', data),
  get: (id) => api.get(`/api/v1/scan/${id}`),
  list: (params) => api.get('/api/v1/scans', { params }),
  delete: (id) => api.delete(`/api/v1/scan/${id}`),
}

// Devices
export const devices = {
  list: (params) => api.get('/api/v1/devices', { params }),
  get: (id) => api.get(`/api/v1/device/${id}`),
}

// Vulnerabilities
export const vulnerabilities = {
  list: (params) => api.get('/api/v1/vulns', { params }),
  get: (id) => api.get(`/api/v1/vuln/${id}`),
  stats: () => api.get('/api/v1/vulns/stats'),
}

// Network Utilities
export const netutil = {
  ping: (data) => api.post('/api/v1/netutil/ping', data),
  speedtest: (data) => api.post('/api/v1/netutil/speedtest', data),
  dnsLookup: (hostname) => api.post('/api/v1/netutil/dns-lookup', null, {
    params: { hostname }
  }),
  getMyNetwork: () => api.get('/api/v1/netutil/my-network'),
  disruptor: (data) => api.post('/api/v1/netutil/disruptor', data),
  traceroute: (data) => api.post('/api/v1/netutil/traceroute', data),
  portScan: (data) => api.post('/api/v1/netutil/port-scan', data),
}

// WebSocket
export const createWebSocket = (path) => {
  // Try to get token from Zustand persist storage first, then fallback to direct localStorage
  let token = null
  try {
    const authStorage = localStorage.getItem('auth-storage')
    if (authStorage) {
      const parsed = JSON.parse(authStorage)
      token = parsed.state?.token
    }
  } catch (e) {
    // Fallback to direct token storage
    token = localStorage.getItem('token')
  }
  
  // Don't create WebSocket if no valid token
  if (!token || token === 'null' || token === 'undefined') {
    throw new Error('No valid authentication token available')
  }
  
  // Use the same host as the page but with ws protocol
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = import.meta.env.VITE_WS_HOST || window.location.hostname
  const port = import.meta.env.VITE_API_PORT || '8000'
  const WS_URL = `${protocol}//${host}:${port}`
  
  return new WebSocket(`${WS_URL}${path}?token=${token}`)
}

export default api
