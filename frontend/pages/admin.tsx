import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { 
  ShieldCheckIcon, 
  UserGroupIcon, 
  CogIcon, 
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  LockClosedIcon,
  EyeIcon,
  TrashIcon,
  PlusIcon,
  MinusIcon
} from '@heroicons/react/24/outline';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface MFAManagementData {
  user_id: string;
  action: string;
  success: boolean;
  message: string;
  mfa_status: any;
}

interface SessionManagementData {
  action: string;
  success: boolean;
  message: string;
  affected_sessions: number;
}

interface ComplianceData {
  rule_id: string;
  success: boolean;
  message: string;
  updated_status: any;
}

export default function AdminPanel() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [sessionExpiryAt, setSessionExpiryAt] = useState<number | null>(null);
  
  // Data states
  const [systemStatus, setSystemStatus] = useState<any>(null);
  const [systemMetrics, setSystemMetrics] = useState<any>(null);
  const [securityDashboard, setSecurityDashboard] = useState<any>(null);
  const [mfaStatus, setMfaStatus] = useState<any>(null);
  const [activeSessions, setActiveSessions] = useState<any>(null);
  const [complianceStatus, setComplianceStatus] = useState<any>(null);
  
  // Form states
  const [mfaForm, setMfaForm] = useState({ user_id: '', action: 'enable', reason: '' });
  const [sessionForm, setSessionForm] = useState({ session_id: '', user_id: '', action: 'force_logout', reason: '' });
  const [complianceForm, setComplianceForm] = useState({ rule_id: '', compliance_status: 'compliant', notes: '' });

  useEffect(() => {
    // Check authentication
    const token = localStorage.getItem('access_token');
    if (!token) {
      router.push('/login');
      return;
    }
    
    // Load initial data
    loadCurrentUser();
    loadSystemOverview();
  }, []);

  // Auto-logout after 5 minutes on admin and dashboard pages
  useEffect(() => {
    const expiresAt = Date.now() + 5 * 60 * 1000;
    setSessionExpiryAt(expiresAt);
    const timer = setTimeout(() => {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      router.push('/');
    }, 5 * 60 * 1000);
    return () => clearTimeout(timer);
  }, []);

  const loadCurrentUser = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/users/me`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setCurrentUser(data);
      } else {
        setError('Failed to load user information');
      }
    } catch (e) {
      setError('Failed to load user information');
    }
  };

  const loadSystemOverview = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      // Load system status
      const statusResponse = await fetch(`${API_URL}/api/v1/admin/system/status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (statusResponse.ok) {
        const statusData = await statusResponse.json();
        setSystemStatus(statusData);
      }
      
      // Load system metrics
      const metricsResponse = await fetch(`${API_URL}/api/v1/admin/system/metrics`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (metricsResponse.ok) {
        const metricsData = await metricsResponse.json();
        setSystemMetrics(metricsData);
      }
      
      // Load security dashboard
      const securityResponse = await fetch(`${API_URL}/api/v1/admin/security/dashboard`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (securityResponse.ok) {
        const securityData = await securityResponse.json();
        setSecurityDashboard(securityData);
      }
      
    } catch (error) {
      console.error('Error loading system overview:', error);
      setError('Failed to load system overview');
    } finally {
      setLoading(false);
    }
  };

  const loadMFAData = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/admin/mfa/status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setMfaStatus(data);
      }
    } catch (error) {
      console.error('Error loading MFA data:', error);
    }
  };

  const loadSessionData = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/admin/sessions/active`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setActiveSessions(data);
      }
    } catch (error) {
      console.error('Error loading session data:', error);
    }
  };

  const loadComplianceData = async () => {
    try {
      const token = localStorage.getItem('access_token');
      const response = await fetch(`${API_URL}/api/v1/admin/compliance/status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setComplianceStatus(data);
      }
    } catch (error) {
      console.error('Error loading compliance data:', error);
    }
  };

  const handleMFAManagement = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/mfa/manage`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(mfaForm)
      });
      
      if (response.ok) {
        const data: MFAManagementData = await response.json();
        setSuccess(data.message);
        setMfaForm({ user_id: '', action: 'enable', reason: '' });
        loadMFAData();
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to manage MFA');
      }
    } catch (error) {
      setError('Failed to manage MFA');
    } finally {
      setLoading(false);
    }
  };

  const handleSessionManagement = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/sessions/manage`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(sessionForm)
      });
      
      if (response.ok) {
        const data: SessionManagementData = await response.json();
        setSuccess(data.message);
        setSessionForm({ session_id: '', user_id: '', action: 'force_logout', reason: '' });
        loadSessionData();
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to manage sessions');
      }
    } catch (error) {
      setError('Failed to manage sessions');
    } finally {
      setLoading(false);
    }
  };

  const handleComplianceUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/admin/compliance/update`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(complianceForm)
      });
      
      if (response.ok) {
        const data: ComplianceData = await response.json();
        setSuccess(data.message);
        setComplianceForm({ rule_id: '', compliance_status: 'compliant', notes: '' });
        loadComplianceData();
      } else {
        const errorData = await response.json();
        setError(errorData.detail || 'Failed to update compliance');
      }
    } catch (error) {
      setError('Failed to update compliance');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'compliant':
        return 'text-green-600 bg-green-100';
      case 'warning':
      case 'partially_compliant':
        return 'text-yellow-600 bg-yellow-100';
      case 'unhealthy':
      case 'non_compliant':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'healthy':
      case 'compliant':
        return <CheckCircleIcon className="h-5 w-5 text-green-600" />;
      case 'warning':
      case 'partially_compliant':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600" />;
      case 'unhealthy':
      case 'non_compliant':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-600" />;
    }
  };

  if (loading && !systemStatus) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <ShieldCheckIcon className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">Admin Panel</h1>
              {currentUser && (
                <span className="ml-3 text-sm text-gray-600">{currentUser.email} ({currentUser.role})</span>
              )}
            </div>
            <button
              onClick={() => router.push('/')}
              className="bg-gray-600 text-white px-4 py-2 rounded-lg hover:bg-gray-700 transition-colors"
            >
              Back to Home
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-6">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex space-x-8">
            {[
              { id: 'overview', name: 'System Overview', icon: ChartBarIcon },
              { id: 'mfa', name: 'MFA Management', icon: LockClosedIcon },
              { id: 'sessions', name: 'Session Management', icon: UserGroupIcon },
              { id: 'compliance', name: 'Compliance', icon: ShieldCheckIcon },
              { id: 'security', name: 'Security Dashboard', icon: ExclamationTriangleIcon }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <tab.icon className="h-5 w-5 inline mr-2" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Error/Success Messages */}
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-400 mr-2" />
              <p className="text-red-800">{error}</p>
            </div>
          </div>
        )}
        
        {success && (
          <div className="mb-4 p-4 bg-green-50 border border-green-200 rounded-lg">
            <div className="flex">
              <CheckCircleIcon className="h-5 w-5 text-green-400 mr-2" />
              <p className="text-green-800">{success}</p>
            </div>
          </div>
        )}

        {/* System Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* System Status */}
              <div className="bg-white p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">System Status</h3>
                {systemStatus && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Status:</span>
                      <span className={`px-2 py-1 rounded-full text-sm font-medium ${getStatusColor(systemStatus.status)}`}>
                        {systemStatus.status}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Version:</span>
                      <span className="text-gray-900">{systemStatus.version}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Environment:</span>
                      <span className="text-gray-900">{systemStatus.environment}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* System Metrics */}
              <div className="bg-white p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">System Metrics</h3>
                {systemMetrics && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">CPU Usage:</span>
                      <span className="text-gray-900">{systemMetrics.cpu_usage}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Memory:</span>
                      <span className="text-gray-900">{systemMetrics.memory_usage}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-600">Active Connections:</span>
                      <span className="text-gray-900">{systemMetrics.active_connections}</span>
                    </div>
                  </div>
                )}
              </div>

              {/* Security Features */}
              <div className="bg-white p-6 rounded-lg shadow">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Features</h3>
                {systemStatus?.security_features && (
                  <div className="space-y-2">
                    {Object.entries(systemStatus.security_features).map(([feature, enabled]) => (
                      <div key={feature} className="flex items-center justify-between">
                        <span className="text-gray-600 text-sm capitalize">
                          {feature.replace(/_/g, ' ')}:
                        </span>
                        {enabled ? (
                          <CheckCircleIcon className="h-5 w-5 text-green-600" />
                        ) : (
                          <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* MFA Management Tab */}
        {activeTab === 'mfa' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">MFA Management</h3>
              
              {/* MFA Status Summary */}
              {mfaStatus && (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  <div className="bg-blue-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{mfaStatus.total_users}</div>
                    <div className="text-sm text-blue-600">Total Users</div>
                  </div>
                  <div className="bg-green-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{mfaStatus.mfa_enabled}</div>
                    <div className="text-sm text-green-600">MFA Enabled</div>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{mfaStatus.mfa_required}</div>
                    <div className="text-sm text-yellow-600">MFA Required</div>
                  </div>
                  <div className="bg-purple-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-purple-600">{mfaStatus.compliance_rate.toFixed(1)}%</div>
                    <div className="text-sm text-purple-600">Compliance Rate</div>
                  </div>
                </div>
              )}

              {/* MFA Management Form */}
              <form onSubmit={handleMFAManagement} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
                    <input
                      type="text"
                      value={mfaForm.user_id}
                      onChange={(e) => setMfaForm({ ...mfaForm, user_id: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Enter user ID"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Action</label>
                    <select
                      value={mfaForm.action}
                      onChange={(e) => setMfaForm({ ...mfaForm, action: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="enable">Enable MFA</option>
                      <option value="disable">Disable MFA</option>
                      <option value="force_enable">Force Enable MFA</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Reason</label>
                    <input
                      type="text"
                      value={mfaForm.reason}
                      onChange={(e) => setMfaForm({ ...mfaForm, reason: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Optional reason"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
                >
                  {loading ? 'Processing...' : 'Manage MFA'}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Session Management Tab */}
        {activeTab === 'sessions' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Session Management</h3>
              
              {/* Active Sessions Summary */}
              {activeSessions && (
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  <div className="bg-blue-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{activeSessions.total_sessions}</div>
                    <div className="text-sm text-blue-600">Total Sessions</div>
                  </div>
                  <div className="bg-green-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{activeSessions.active_sessions}</div>
                    <div className="text-sm text-green-600">Active Sessions</div>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{activeSessions.expired_sessions}</div>
                    <div className="text-sm text-yellow-600">Expired Sessions</div>
                  </div>
                  <div className="bg-red-50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{activeSessions.admin_sessions}</div>
                    <div className="text-sm text-red-600">Admin Sessions</div>
                  </div>
                </div>
              )}

              {/* Session Management Form */}
              <form onSubmit={handleSessionManagement} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Session ID</label>
                    <input
                      type="text"
                      value={sessionForm.session_id}
                      onChange={(e) => setSessionForm({ ...sessionForm, session_id: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Optional session ID"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">User ID</label>
                    <input
                      type="text"
                      value={sessionForm.user_id}
                      onChange={(e) => setSessionForm({ ...sessionForm, user_id: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Optional user ID"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Action</label>
                    <select
                      value={sessionForm.action}
                      onChange={(e) => setSessionForm({ ...sessionForm, action: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="force_logout">Force Logout</option>
                      <option value="extend">Extend Session</option>
                      <option value="restrict">Restrict User</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Reason</label>
                    <input
                      type="text"
                      value={sessionForm.reason}
                      onChange={(e) => setSessionForm({ ...sessionForm, reason: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Optional reason"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-red-600 text-white px-6 py-2 rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
                >
                  {loading ? 'Processing...' : 'Manage Sessions'}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Management</h3>
              
              {/* Compliance Status */}
              {complianceStatus && (
                <div className="mb-6">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-lg font-medium text-gray-900">Overall Compliance Status</h4>
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(complianceStatus.overall_status)}`}>
                      {complianceStatus.overall_status}
                    </span>
                  </div>
                  <div className="text-3xl font-bold text-blue-600 mb-2">
                    {complianceStatus.overall_compliance_percentage}%
                  </div>
                  <div className="text-gray-600">Compliance Rate</div>
                </div>
              )}

              {/* Compliance Update Form */}
              <form onSubmit={handleComplianceUpdate} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Rule ID</label>
                    <input
                      type="text"
                      value={complianceForm.rule_id}
                      onChange={(e) => setComplianceForm({ ...complianceForm, rule_id: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="e.g., hipaa_001"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                    <select
                      value={complianceForm.compliance_status}
                      onChange={(e) => setComplianceForm({ ...complianceForm, compliance_status: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="compliant">Compliant</option>
                      <option value="partially_compliant">Partially Compliant</option>
                      <option value="non_compliant">Non Compliant</option>
                      <option value="pending">Pending</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Notes</label>
                    <input
                      type="text"
                      value={complianceForm.notes}
                      onChange={(e) => setComplianceForm({ ...complianceForm, notes: e.target.value })}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                      placeholder="Optional notes"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-green-600 text-white px-6 py-2 rounded-lg hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                  {loading ? 'Processing...' : 'Update Compliance'}
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Security Dashboard Tab */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            {securityDashboard && (
              <>
                {/* Threat Landscape */}
                <div className="bg-white p-6 rounded-lg shadow">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Threat Landscape</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-red-50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">{securityDashboard.threat_landscape.active_threats}</div>
                      <div className="text-sm text-red-600">Active Threats</div>
                    </div>
                    <div className="bg-yellow-50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-yellow-600">{securityDashboard.threat_landscape.risk_level}</div>
                      <div className="text-sm text-yellow-600">Risk Level</div>
                    </div>
                    <div className="bg-blue-50 p-4 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">{securityDashboard.recent_security_events.length}</div>
                      <div className="text-sm text-blue-600">Recent Events</div>
                    </div>
                  </div>
                </div>

                {/* Recent Security Events */}
                <div className="bg-white p-6 rounded-lg shadow">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Security Events</h3>
                  <div className="space-y-3">
                    {securityDashboard.recent_security_events.slice(0, 5).map((event: any, index: number) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          {getStatusIcon(event.security_level)}
                          <div>
                            <div className="font-medium text-gray-900">{event.threat_type}</div>
                            <div className="text-sm text-gray-600">{event.description}</div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm text-gray-600">{new Date(event.timestamp).toLocaleString()}</div>
                          <div className="text-xs text-gray-500">{event.ip_address}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Compliance Status */}
                <div className="bg-white p-6 rounded-lg shadow">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Compliance Status</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(securityDashboard.compliance_status.standards || {}).map(([standard, data]: [string, any]) => (
                      <div key={standard} className="p-4 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium text-gray-900">{standard.toUpperCase()}</span>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(data.status)}`}>
                            {data.status}
                          </span>
                        </div>
                        <div className="text-2xl font-bold text-blue-600">{data.compliance_percentage}%</div>
                        <div className="text-sm text-gray-600">{data.compliant_rules}/{data.total_rules} rules compliant</div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
