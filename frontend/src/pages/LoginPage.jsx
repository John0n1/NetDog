import { useState } from 'react'
import { Shield, LogIn, UserPlus } from 'lucide-react'
import { auth } from '../api'
import { useAuthStore } from '../store/authStore'

const LoginPage = () => {
  const [isLogin, setIsLogin] = useState(true)
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    full_name: ''
  })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  
  const { setToken, setUser } = useAuthStore()
  
  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    
    try {
      if (isLogin) {
        const response = await auth.login(formData.username, formData.password)
        setToken(response.data.access_token)
        const userRes = await auth.getMe()
        setUser(userRes.data)
      } else {
        await auth.register(formData)
        // Auto-login after registration
        const response = await auth.login(formData.username, formData.password)
        setToken(response.data.access_token)
        const userRes = await auth.getMe()
        setUser(userRes.data)
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }
  
  return (
    <div className="min-h-screen flex items-center justify-center bg-dark-bg p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <Shield className="w-12 h-12 text-blue-accent" />
            <h1 className="text-3xl font-bold">NetDog</h1>
          </div>
          <p className="text-gray-400">Network Security Scanner</p>
        </div>
        
        {/* Form */}
        <div className="card">
          <div className="flex mb-6 border-b border-dark-border">
            <button
              onClick={() => setIsLogin(true)}
              className={`flex-1 py-2 font-semibold ${isLogin ? 'text-blue-accent border-b-2 border-blue-accent' : 'text-gray-500'}`}
            >
              <LogIn className="w-4 h-4 inline mr-2" />
              Login
            </button>
            <button
              onClick={() => setIsLogin(false)}
              className={`flex-1 py-2 font-semibold ${!isLogin ? 'text-blue-accent border-b-2 border-blue-accent' : 'text-gray-500'}`}
            >
              <UserPlus className="w-4 h-4 inline mr-2" />
              Register
            </button>
          </div>
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-semibold mb-2">Username</label>
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                className="input w-full"
                required
              />
            </div>
            
            {!isLogin && (
              <>
                <div>
                  <label className="block text-sm font-semibold mb-2">Email</label>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="input w-full"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Full Name</label>
                  <input
                    type="text"
                    value={formData.full_name}
                    onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                    className="input w-full"
                  />
                </div>
              </>
            )}
            
            <div>
              <label className="block text-sm font-semibold mb-2">Password</label>
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="input w-full"
                required
              />
            </div>
            
            {error && (
              <div className="bg-red-900 text-red-200 px-4 py-2 rounded">
                {error}
              </div>
            )}
            
            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full"
            >
              {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
            </button>
          </form>
        </div>
        
        {/* Warning */}
        <div className="mt-6 p-4 bg-yellow-900 border border-yellow-700 rounded text-yellow-200 text-sm">
          <strong>⚠️ Legal Notice:</strong> This tool is for authorized security testing only. 
          Unauthorized scanning may be illegal in your jurisdiction.
        </div>
      </div>
    </div>
  )
}

export default LoginPage
