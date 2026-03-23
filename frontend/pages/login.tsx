import { useState, useEffect } from 'react';
import Link from 'next/link';
import { ShieldCheckIcon, ChartBarIcon, CogIcon, ArrowRightIcon, SparklesIcon } from '@heroicons/react/24/outline';
import { useRouter } from 'next/router';

// Normalize API base URL to avoid using 0.0.0.0 which browsers cannot reach
const RAW_API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
const API_URL = RAW_API_URL.replace('0.0.0.0', '127.0.0.1');

export default function Login() {
  const router = useRouter();
  const [step, setStep] = useState<'creds' | 'otp' | 'choice'>('creds');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState<string>('');
  const [demoMode, setDemoMode] = useState<string>('');
  const [sessionTimeLeft, setSessionTimeLeft] = useState<number>(300); // 5 minutes in seconds
  const [expiresAt, setExpiresAt] = useState<number | null>(null);

  // Check if user is already authenticated on component mount
  useEffect(() => {
    const force = router.query.force === '1' || router.query.force === 'true';
    const token = localStorage.getItem('access_token');
    const storedExpiry = localStorage.getItem('session_expires_at');
    const expiryTs = storedExpiry ? parseInt(storedExpiry, 10) : null;
    const now = Date.now();
    if (expiryTs && expiryTs <= now) {
      // Expired: force logout state
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('session_expires_at');
    }
    if (token && !force) {
      if (expiryTs && expiryTs > now) {
        setIsAuthenticated(true);
        setStep('choice');
        setExpiresAt(expiryTs);
        setSessionTimeLeft(Math.max(0, Math.floor((expiryTs - now) / 1000)));
      }
      // Load actual role from backend
      fetch(`${API_URL}/api/v1/users/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }).then(async (res) => {
        if (res.ok) {
          const data = await res.json();
          if (data?.role) setUserRole(data.role);
        }
      }).catch(() => {});
    } else if (force && token) {
      // Ensure a clean login when explicitly requested
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      localStorage.removeItem('session_expires_at');
      setIsAuthenticated(false);
      setUserRole('');
    }

    if (router.query.demo) {
      setDemoMode(router.query.demo as string);
    }
  }, [router.query.demo, router.query.force]);

  // Session timeout effect
  useEffect(() => {
    if (isAuthenticated && expiresAt) {
      const remainingMs = Math.max(0, expiresAt - Date.now());
      const timeoutId = setTimeout(() => {
        console.log('Session expired - auto logout');
        handleLogout();
        setError('Session expired. Please log in again.');
      }, remainingMs);
      return () => clearTimeout(timeoutId);
    }
  }, [isAuthenticated, expiresAt]);

  // Session countdown timer
  useEffect(() => {
    if (isAuthenticated && expiresAt) {
      const interval = setInterval(() => {
        const remaining = Math.max(0, Math.floor(((expiresAt || Date.now()) - Date.now()) / 1000));
        setSessionTimeLeft(remaining);
        if (remaining <= 0) {
          handleLogout();
          setError('Session expired. Please log in again.');
        }
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [isAuthenticated, expiresAt]);

  const startLogin = async () => {
    setError('');
    setLoading(true);
    try {
      console.log(`Making request to: ${API_URL}/api/v1/users/login`);

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);
      const res = await fetch(`${API_URL}/api/v1/users/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        mode: 'cors',
        credentials: 'include',
        body: JSON.stringify({ email: email.trim(), password }),
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      console.log(`Response status: ${res.status}`);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({} as any));
        throw new Error(errorData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }
      setStep('otp');
    } catch (e: any) {
      console.error('Login error:', e);
      if (e.name === 'AbortError') {
        setError('Request timed out. Please check if the backend server is running and try again.');
      } else if ((e.message || '').includes('NetworkError') || (e.message || '').includes('Failed to fetch')) {
        setError('Unable to connect to server. Please check if the backend is running on http://127.0.0.1:8000');
      } else {
        setError(e.message || 'Login failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const verifyOtp = async () => {
    setError('');
    setLoading(true);
    try {
      console.log(`Making OTP verification request to: ${API_URL}/api/v1/users/login/verify`);

      const res = await fetch(`${API_URL}/api/v1/users/login/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        mode: 'cors',
        credentials: 'include',
        body: JSON.stringify({ email: email.trim(), otp: otp.trim() }),
      });

      console.log(`OTP verification response status: ${res.status}`);

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({} as any));
        throw new Error(errorData.detail || `HTTP ${res.status}: ${res.statusText}`);
      }
      const data = await res.json();
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      const exp = Date.now() + 5 * 60 * 1000;
      localStorage.setItem('session_expires_at', String(exp));
      setExpiresAt(exp);
      setIsAuthenticated(true);
      setUserRole(data.user?.role || 'user');
      setStep('choice');
      setSessionTimeLeft(Math.max(0, Math.floor((exp - Date.now()) / 1000)));
      setEmail('');
      setPassword('');
      setOtp('');
    } catch (e: any) {
      console.error('OTP verification error:', e);
      if ((e.message || '').includes('NetworkError') || (e.message || '').includes('Failed to fetch')) {
        setError('Unable to connect to server. Please check if the backend is running.');
      } else {
        setError(e.message || 'Verification failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('session_expires_at');
    setIsAuthenticated(false);
    setUserRole('');
    setStep('creds');
    setSessionTimeLeft(300);
    setExpiresAt(null);
    setEmail('');
    setPassword('');
    setOtp('');
  };

  const goToAdminOrDashboard = async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (!token) {
        router.push('/login');
        return;
      }
      // Always re-check role with backend to avoid stale state
      const res = await fetch(`${API_URL}/api/v1/users/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        const role = (data?.role || '').toLowerCase();
        setUserRole(data?.role || '');
        if (role === 'admin' || role === 'super_admin') {
          router.push('/admin');
        } else {
          window.alert('Only admins can access the Admin Panel');
          // stay on choice panel
          return;
        }
      } else if (res.status === 401) {
        handleLogout();
        router.push('/login');
      } else {
        // Fallback to current state
        if (userRole && ['admin', 'super_admin'].includes(userRole.toLowerCase())) {
          router.push('/admin');
        } else {
          window.alert('Only admins can access the Admin Panel');
          return;
        }
      }
    } catch {
      window.alert('Unable to verify admin access at the moment. Please try again.');
      return;
    }
  };

  // If user is authenticated, show the choice panel
  if (isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
        <div className="w-full max-w-4xl bg-white shadow rounded-lg p-8">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-green-100 rounded-full mb-4">
              <ShieldCheckIcon className="h-8 w-8 text-green-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900 mb-2">Welcome! You're Successfully Logged In</h1>
            <p className="text-gray-600">Choose where you'd like to go next.</p>
            <div className="mt-2 inline-flex items-center px-4 py-2 bg-amber-50 border border-amber-200 rounded-full">
              <div className="w-2 h-2 bg-amber-500 rounded-full mr-2 animate-pulse"></div>
              <span className="text-sm font-medium text-amber-700">
                Session expires in {Math.floor(sessionTimeLeft / 60)}:{(sessionTimeLeft % 60).toString().padStart(2, '0')}
              </span>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <Link href="/chat" className="group bg-gradient-to-r from-blue-600 to-indigo-600 text-white p-6 rounded-xl hover:shadow-lg hover:scale-105 transition-all duration-200 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-white/20 rounded-lg mb-4">
                <ShieldCheckIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Secure Chat</h3>
              <p className="text-blue-100 text-sm">Access the AI-powered healthcare assistant with full security features</p>
            </Link>

            <Link href="/dashboard" className="group bg-gradient-to-r from-purple-600 to-pink-600 text-white p-6 rounded-xl hover:shadow-lg hover:scale-105 transition-all duration-200 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-white/20 rounded-lg mb-4">
                <ChartBarIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Dashboard</h3>
              <p className="text-purple-100 text-sm">View security metrics, monitoring data, and system analytics</p>
            </Link>

            <button onClick={goToAdminOrDashboard} className="group bg-gradient-to-r from-orange-600 to-red-600 text-white p-6 rounded-xl hover:shadow-lg hover:scale-105 transition-all duration-200 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-white/20 rounded-lg mb-4">
                <CogIcon className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-lg font-semibold mb-2">Admin Panel</h3>
              <p className="text-orange-100 text-sm">Manage users, security settings, and system configuration</p>
            </button>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-50 rounded-lg p-6 mb-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
            <div className="flex flex-wrap gap-3">
              <Link href="/" className="inline-flex items-center px-4 py-2 bg-white border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 hover:border-gray-400 transition-colors">
                <ArrowRightIcon className="h-4 w-4 mr-2" />
                Back to Home
              </Link>
              <button
                onClick={handleLogout}
                className="inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-medium hover:bg-red-700 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>

          {/* User Info */}
          <div className="text-center text-sm text-gray-500">
            <p>Logged in as: <span className="font-medium text-gray-700">{email}</span></p>
            <p>Role: <span className="font-medium text-gray-700 capitalize">{userRole}</span></p>
          </div>
        </div>
      </div>
    );
  }

  // Don't show login form if authenticated
  if (isAuthenticated) {
    return null;
  }

  // Show login form if not authenticated
  return (
    <div className="min-h-screen flex">
      {/* Left Side - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center bg-white p-8">
        <div className="w-full max-w-md">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center mb-6">
              <div className="w-8 h-8 bg-purple-600 rounded-lg mr-3"></div>
              <span className="text-xl font-semibold text-gray-900">Login</span>
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Hello, <span className="bg-blue-100 px-2 py-1 rounded">Welcome Back</span>
            </h1>
            <p className="text-gray-500">Hey, welcome back to your special place</p>
          </div>

          {/* Demo Mode Badge */}
          {demoMode && (
            <div className="mb-6 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800 border border-purple-200">
              <SparklesIcon className="h-3 w-3 mr-1" />
              Demo Mode: {demoMode.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
            </div>
          )}

          {/* Error Message */}
          {error && (
            <div className="mb-6 p-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg">
              {error}
            </div>
          )}

          {/* Login Form Steps */}
          {step === 'creds' ? (
            <div className="space-y-6">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                  Email Address
                </label>
                <input
                  id="email"
                  type="email"
                  placeholder="Enter your email"
                  className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors text-gray-900 placeholder-gray-400"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  placeholder="Enter your password"
                  className="w-full border border-gray-300 rounded-lg px-4 py-3 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors text-gray-900 placeholder-gray-400"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              
              {/* Remember Me & Forgot Password */}
              <div className="flex items-center justify-between">
                <label className="flex items-center">
                  <input type="checkbox" className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500" />
                  <span className="ml-2 text-sm text-gray-600">Remember me</span>
                </label>
                <Link href="#" className="text-sm text-blue-600 hover:text-blue-700 hover:underline">
                  Forgot Password?
                </Link>
              </div>

              <button
                onClick={startLogin}
                disabled={loading || !email || !password}
                className="w-full bg-blue-600 text-white rounded-lg py-3 px-4 font-medium hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
              >
                {loading ? 'Sending OTP…' : 'Sign In'}
              </button>

              <div className="text-center">
                <span className="text-sm text-gray-500">Don't have an account? </span>
                <Link href="#" className="text-sm text-blue-600 hover:text-blue-700 hover:underline font-medium">
                  Sign Up
                </Link>
              </div>
            </div>
          ) : step === 'otp' ? (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-100 rounded-full mb-4">
                  <ShieldCheckIcon className="h-8 w-8 text-blue-600" />
                </div>
                <h2 className="text-xl font-semibold text-gray-900 mb-2">Verify Your Identity</h2>
                <p className="text-sm text-gray-600">Enter the 6-digit code sent to</p>
                <p className="text-sm font-medium text-gray-900">{email}</p>
              </div>
              
              <div>
                <label htmlFor="otp" className="block text-sm font-medium text-gray-700 mb-2">
                  Verification Code
                </label>
                <input
                  id="otp"
                  type="text"
                  maxLength={6}
                  placeholder="123456"
                  className="w-full border border-gray-300 rounded-lg px-4 py-3 text-center tracking-widest text-lg font-mono focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-colors"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, ''))}
                />
              </div>
              
              <button
                onClick={verifyOtp}
                disabled={loading || otp.length !== 6}
                className="w-full bg-emerald-600 text-white rounded-lg py-3 px-4 font-medium hover:bg-emerald-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
              >
                {loading ? 'Verifying…' : 'Verify & Sign In'}
              </button>
              
              <button
                onClick={() => setStep('creds')}
                className="w-full text-gray-600 hover:text-gray-800 text-sm py-2 transition-colors"
              >
                ← Back to Login
              </button>
            </div>
          ) : null}

          {/* Back to Home Link */}
          <div className="mt-8 text-center">
            <Link href="/" className="text-sm text-blue-600 hover:text-blue-700 hover:underline transition-colors">
              ← Back to Home
            </Link>
          </div>
        </div>
      </div>

      {/* Right Side - Illustration Panel */}
      <div className="hidden lg:flex lg:w-1/2 bg-purple-600 items-center justify-center p-8">
        <div className="bg-purple-700 rounded-2xl p-8 max-w-md">
          {/* Illustration Content */}
          <div className="text-center text-white">
            {/* Person with Phone Illustration */}
            <div className="relative mb-8">
              {/* Person */}
              <div className="w-32 h-32 mx-auto mb-4 relative">
                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-20 h-20 bg-yellow-400 rounded-full"></div>
                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-16 h-16 bg-yellow-300 rounded-full"></div>
                <div className="absolute bottom-0 left-1/2 transform -translate-x-1/2 w-12 h-12 bg-yellow-200 rounded-full"></div>
              </div>
              
              {/* Phone */}
              <div className="absolute bottom-0 right-0 w-24 h-32 bg-pink-300 rounded-2xl border-4 border-white shadow-lg">
                <div className="w-16 h-16 mx-auto mt-4 bg-white rounded-full flex items-center justify-center">
                  <div className="w-12 h-12 bg-purple-600 rounded-full animate-pulse"></div>
                </div>
              </div>
              
              {/* Success Bubble */}
              <div className="absolute top-0 right-0 w-16 h-16 bg-white rounded-full flex items-center justify-center shadow-lg">
                <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
                  <div className="w-4 h-4 bg-white rounded-full"></div>
                </div>
              </div>
              
              {/* Lock Icon */}
              <div className="absolute top-0 left-0 w-16 h-16 bg-white rounded-full flex items-center justify-center shadow-lg">
                <div className="w-8 h-8 bg-purple-600 rounded-full flex items-center justify-center">
                  <div className="w-4 h-4 bg-white rounded-full"></div>
                </div>
              </div>
            </div>
            
            <h3 className="text-2xl font-bold mb-4">Secure Authentication</h3>
            <p className="text-purple-100 text-lg">
              Your healthcare data is protected with enterprise-grade security
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}


