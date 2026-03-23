import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { 
  ChartBarIcon, 
  ClockIcon, 
  UserIcon, 
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ChatBubbleLeftRightIcon,
  CalendarIcon,
  ArrowTrendingUpIcon,
  ArrowTrendingDownIcon,
  EyeIcon,
  TrashIcon
} from '@heroicons/react/24/outline';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface ConversationSession {
  session_id: string;
  user_id: string;
  created_at: string;
  last_activity: string;
  message_count: number;
  total_tokens: number;
  security_events: number;
  risk_score: number;
  topics: string[];
  status: string;
}

interface ChatAnalytics {
  total_conversations: number;
  total_messages: number;
  average_session_length: number;
  popular_topics: Array<{ topic: string; count: number }>;
  security_incidents: number;
  user_engagement: {
    sessions_per_day: number;
    messages_per_session: number;
    active_days: number;
  };
  time_distribution: {
    hourly: Record<string, number>;
    peak_hour: number;
  };
}

interface CurrentUser {
  id: string;
  email: string;
  username: string;
  role: string;
}

export default function Dashboard() {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState('overview');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [currentUser, setCurrentUser] = useState<CurrentUser | null>(null);
  const [userError, setUserError] = useState('');
  
  // Data states
  const [conversationSessions, setConversationSessions] = useState<ConversationSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<ConversationSession | null>(null);
  const [sessionHistory, setSessionHistory] = useState<any>(null);
  const [chatAnalytics, setChatAnalytics] = useState<ChatAnalytics | null>(null);
  const [timePeriod, setTimePeriod] = useState('24h');
  const [sessionExpiryAt, setSessionExpiryAt] = useState<number | null>(null);
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const [sessionsPerPage] = useState(10);

  useEffect(() => {
    // Check authentication
    const token = localStorage.getItem('access_token');
    if (!token) {
      router.push('/login');
      return;
    }
    
    // Load initial data
    loadCurrentUser();
    loadConversationSessions();
    loadChatAnalytics();
  }, [timePeriod]);

  // Auto-logout after 5 minutes on dashboard
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
        setUserError('Failed to load user information');
      }
    } catch (e) {
      setUserError('Failed to load user information');
    }
  };

  const loadConversationSessions = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/chat/sessions`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setConversationSessions(data);
      } else {
        setError('Failed to load conversation sessions');
      }
    } catch (error) {
      console.error('Error loading conversation sessions:', error);
      setError('Failed to load conversation sessions');
    } finally {
      setLoading(false);
    }
  };

  const loadSessionHistory = async (sessionId: string) => {
    try {
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/chat/sessions/${sessionId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setSessionHistory(data);
      } else {
        setError('Failed to load session history');
      }
    } catch (error) {
      console.error('Error loading session history:', error);
      setError('Failed to load session history');
    }
  };

  const loadChatAnalytics = async () => {
    try {
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/chat/analytics?time_period=${timePeriod}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setChatAnalytics(data);
      } else {
        setError('Failed to load chat analytics');
      }
    } catch (error) {
      console.error('Error loading chat analytics:', error);
      setError('Failed to load chat analytics');
    }
  };

  const deleteSession = async (sessionId: string) => {
    try {
      const token = localStorage.getItem('access_token');
      
      const response = await fetch(`${API_URL}/api/v1/chat/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        // Remove from local state
        setConversationSessions(prev => prev.filter(session => session.session_id !== sessionId));
        if (selectedSession?.session_id === sessionId) {
          setSelectedSession(null);
          setSessionHistory(null);
        }
      } else {
        setError('Failed to delete session');
      }
    } catch (error) {
      console.error('Error deleting session:', error);
      setError('Failed to delete session');
    }
  };

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 0.7) return 'text-red-600 bg-red-100';
    if (riskScore >= 0.4) return 'text-yellow-600 bg-yellow-100';
    return 'text-green-600 bg-green-100';
  };

  const getRiskLevel = (riskScore: number) => {
    if (riskScore >= 0.7) return 'High';
    if (riskScore >= 0.4) return 'Medium';
    return 'Low';
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const formatDuration = (minutes: number) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    if (hours > 0) {
      return `${hours}h ${mins}m`;
    }
    return `${mins}m`;
  };

  // Pagination
  const indexOfLastSession = currentPage * sessionsPerPage;
  const indexOfFirstSession = indexOfLastSession - sessionsPerPage;
  const currentSessions = conversationSessions.slice(indexOfFirstSession, indexOfLastSession);
  const totalPages = Math.ceil(conversationSessions.length / sessionsPerPage);

  const paginate = (pageNumber: number) => setCurrentPage(pageNumber);

  if (loading && !conversationSessions.length) {
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
              <ChartBarIcon className="h-8 w-8 text-purple-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">Security Dashboard</h1>
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
              { id: 'overview', name: 'Overview', icon: ChartBarIcon },
              { id: 'conversations', name: 'Conversation History', icon: ChatBubbleLeftRightIcon },
              { id: 'analytics', name: 'User Analytics', icon: ArrowTrendingUpIcon },
              { id: 'security', name: 'Security Insights', icon: ShieldCheckIcon }
            ].map((tab) => {
              const IconComponent = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`py-2 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id
                      ? 'border-purple-500 text-purple-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  }`}
                >
                  <IconComponent className="h-5 w-5 inline mr-2" />
                  {tab.name}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Error Messages */}
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-400 mr-2" />
              <p className="text-red-800">{error}</p>
            </div>
          </div>
        )}

        {/* Overview Tab */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Key Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-lg shadow">
                <div className="flex items-center">
                  <div className="p-2 bg-blue-100 rounded-lg">
                    <ChatBubbleLeftRightIcon className="h-6 w-6 text-blue-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Total Conversations</p>
                    <p className="text-2xl font-semibold text-gray-900">{conversationSessions.length}</p>
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow">
                <div className="flex items-center">
                  <div className="p-2 bg-green-100 rounded-lg">
                    <UserIcon className="h-6 w-6 text-green-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Active Sessions</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {conversationSessions.filter(s => s.status === 'active').length}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow">
                <div className="flex items-center">
                  <div className="p-2 bg-yellow-100 rounded-lg">
                    <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Security Events</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {conversationSessions.reduce((sum, s) => sum + s.security_events, 0)}
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-white p-6 rounded-lg shadow">
                <div className="flex items-center">
                  <div className="p-2 bg-purple-100 rounded-lg">
                    <ClockIcon className="h-6 w-6 text-purple-600" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600">Avg Session Length</p>
                    <p className="text-2xl font-semibold text-gray-900">
                      {conversationSessions.length > 0 
                        ? Math.round(conversationSessions.reduce((sum, s) => sum + s.message_count, 0) / conversationSessions.length)
                        : 0
                      } msgs
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Activity */}
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Recent Conversations</h3>
              </div>
              <div className="p-6">
                <div className="space-y-4">
                  {conversationSessions.slice(0, 5).map((session) => (
                    <div key={session.session_id} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                      <div className="flex items-center space-x-4">
                        <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                          <ChatBubbleLeftRightIcon className="h-5 w-5 text-blue-600" />
                        </div>
                        <div>
                          <p className="font-medium text-gray-900">Session {session.session_id.slice(-8)}</p>
                          <p className="text-sm text-gray-600">{formatDate(session.created_at)}</p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-4">
                        <span className="text-sm text-gray-600">{session.message_count} messages</span>
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(session.risk_score)}`}>
                          {getRiskLevel(session.risk_score)} Risk
                        </span>
                        <button
                          onClick={() => {
                            setSelectedSession(session);
                            loadSessionHistory(session.session_id);
                          }}
                          className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                        >
                          View Details
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Conversation History Tab */}
        {activeTab === 'conversations' && (
          <div className="space-y-6">
            {/* Filters and Search */}
            <div className="bg-white p-6 rounded-lg shadow">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between space-y-4 md:space-y-0">
                <div className="flex items-center space-x-4">
                  <label className="text-sm font-medium text-gray-700">Time Period:</label>
                  <select
                    value={timePeriod}
                    onChange={(e) => setTimePeriod(e.target.value)}
                    className="border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-purple-500 focus:border-purple-500"
                  >
                    <option value="24h">Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                  </select>
                </div>
                <div className="text-sm text-gray-600">
                  Showing {conversationSessions.length} conversations
                </div>
              </div>
            </div>

            {/* Conversations List */}
            <div className="bg-white rounded-lg shadow">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">Conversation Sessions</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Session
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Created
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Messages
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Risk Level
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Security Events
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {currentSessions.map((session) => (
                      <tr key={session.session_id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm font-medium text-gray-900">
                            {session.session_id.slice(-8)}
                          </div>
                          <div className="text-sm text-gray-500">
                            {session.topics.slice(0, 2).join(', ')}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatDate(session.created_at)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {session.message_count}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(session.risk_score)}`}>
                            {getRiskLevel(session.risk_score)}
                          </span>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {session.security_events}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex space-x-2">
                            <button
                              onClick={() => {
                                setSelectedSession(session);
                                loadSessionHistory(session.session_id);
                              }}
                              className="text-blue-600 hover:text-blue-900"
                            >
                              <EyeIcon className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => deleteSession(session.session_id)}
                              className="text-red-600 hover:text-red-900"
                            >
                              <TrashIcon className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="px-6 py-4 border-t border-gray-200">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-gray-700">
                      Showing {indexOfFirstSession + 1} to {Math.min(indexOfLastSession, conversationSessions.length)} of {conversationSessions.length} results
                    </div>
                    <div className="flex space-x-2">
                      {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                        <button
                          key={page}
                          onClick={() => paginate(page)}
                          className={`px-3 py-2 text-sm font-medium rounded-lg ${
                            currentPage === page
                              ? 'bg-purple-600 text-white'
                              : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'
                          }`}
                        >
                          {page}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Session Details Modal */}
            {selectedSession && sessionHistory && (
              <div className="bg-white rounded-lg shadow">
                <div className="px-6 py-4 border-b border-gray-200">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-gray-900">
                      Session Details: {selectedSession.session_id.slice(-8)}
                    </h3>
                    <button
                      onClick={() => {
                        setSelectedSession(null);
                        setSessionHistory(null);
                      }}
                      className="text-gray-400 hover:text-gray-600"
                    >
                      ×
                    </button>
                  </div>
                </div>
                <div className="p-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div>
                      <h4 className="font-medium text-gray-900 mb-2">Session Information</h4>
                      <div className="space-y-2 text-sm text-gray-600">
                        <div>Created: {formatDate(selectedSession.created_at)}</div>
                        <div>Last Activity: {formatDate(selectedSession.last_activity)}</div>
                        <div>Total Messages: {selectedSession.message_count}</div>
                        <div>Total Tokens: {selectedSession.total_tokens}</div>
                        <div>Status: {selectedSession.status}</div>
                      </div>
                    </div>
                    <div>
                      <h4 className="font-medium text-gray-900 mb-2">Security Summary</h4>
                      <div className="space-y-2 text-sm text-gray-600">
                        <div>Risk Score: {selectedSession.risk_score.toFixed(2)}</div>
                        <div>Security Events: {selectedSession.security_events}</div>
                        <div>Threats Detected: {sessionHistory.security_summary.threats_detected}</div>
                        <div>Sensitive Data Flagged: {sessionHistory.security_summary.sensitive_data_flagged}</div>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium text-gray-900 mb-2">Messages</h4>
                    <div className="space-y-4">
                      {sessionHistory.messages.map((message: any, index: number) => (
                        <div key={index} className="border rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-gray-900">
                              {new Date(message.timestamp).toLocaleString()}
                            </span>
                            <span className="text-xs text-gray-500">
                              IP: {message.ip_address}
                            </span>
                          </div>
                          <div className="space-y-2">
                            <div>
                              <span className="text-sm font-medium text-gray-700">User:</span>
                              <p className="text-sm text-gray-900 ml-2">{message.user_message}</p>
                            </div>
                            <div>
                              <span className="text-sm font-medium text-gray-700">AI Response:</span>
                              <p className="text-sm text-gray-900 ml-2">{message.ai_response}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* User Analytics Tab */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            {chatAnalytics && (
              <>
                {/* Analytics Overview */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="bg-white p-6 rounded-lg shadow">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Engagement Metrics</h3>
                    <div className="space-y-4">
                      <div>
                        <div className="text-2xl font-bold text-blue-600">{chatAnalytics.total_conversations}</div>
                        <div className="text-sm text-gray-600">Total Conversations</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-green-600">{chatAnalytics.total_messages}</div>
                        <div className="text-sm text-gray-600">Total Messages</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-purple-600">{chatAnalytics.average_session_length.toFixed(1)}</div>
                        <div className="text-sm text-gray-600">Avg Session Length</div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white p-6 rounded-lg shadow">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">User Behavior</h3>
                    <div className="space-y-4">
                      <div>
                        <div className="text-2xl font-bold text-blue-600">{chatAnalytics.user_engagement.sessions_per_day.toFixed(1)}</div>
                        <div className="text-sm text-gray-600">Sessions per Day</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-green-600">{chatAnalytics.user_engagement.messages_per_session.toFixed(1)}</div>
                        <div className="text-sm text-gray-600">Messages per Session</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-purple-600">{chatAnalytics.user_engagement.active_days}</div>
                        <div className="text-sm text-gray-600">Active Days</div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white p-6 rounded-lg shadow">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Insights</h3>
                    <div className="space-y-4">
                      <div>
                        <div className="text-2xl font-bold text-red-600">{chatAnalytics.security_incidents}</div>
                        <div className="text-sm text-gray-600">Security Incidents</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-yellow-600">{chatAnalytics.time_distribution.peak_hour}</div>
                        <div className="text-sm text-gray-600">Peak Hour (24h)</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Popular Topics */}
                <div className="bg-white p-6 rounded-lg shadow">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Popular Topics</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {chatAnalytics.popular_topics.map((topic, index) => (
                      <div key={index} className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                        <span className="font-medium text-gray-900 capitalize">{topic.topic}</span>
                        <span className="text-2xl font-bold text-blue-600">{topic.count}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Time Distribution Chart */}
                <div className="bg-white p-6 rounded-lg shadow">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">Activity by Hour</h3>
                  <div className="grid grid-cols-12 gap-1">
                    {Array.from({ length: 24 }, (_, hour) => (
                      <div key={hour} className="text-center">
                        <div className="text-xs text-gray-500 mb-1">{hour}</div>
                        <div 
                          className="bg-blue-200 rounded-t"
                          style={{ 
                            height: `${Math.max(20, (chatAnalytics.time_distribution.hourly[hour] || 0) * 10)}px`,
                            backgroundColor: hour === chatAnalytics.time_distribution.peak_hour ? '#3B82F6' : '#DBEAFE'
                          }}
                        ></div>
                      </div>
                    ))}
                  </div>
                  <div className="text-center mt-4 text-sm text-gray-600">
                    Peak activity at {chatAnalytics.time_distribution.peak_hour}:00
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* Security Insights Tab */}
        {activeTab === 'security' && (
          <div className="space-y-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Overview</h3>
              
              {/* Risk Distribution */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600">
                    {conversationSessions.filter(s => s.risk_score < 0.4).length}
                  </div>
                  <div className="text-sm text-gray-600">Low Risk Sessions</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-yellow-600">
                    {conversationSessions.filter(s => s.risk_score >= 0.4 && s.risk_score < 0.7).length}
                  </div>
                  <div className="text-sm text-gray-600">Medium Risk Sessions</div>
                </div>
                <div className="text-center">
                  <div className="text-3xl font-bold text-red-600">
                    {conversationSessions.filter(s => s.risk_score >= 0.7).length}
                  </div>
                  <div className="text-sm text-gray-600">High Risk Sessions</div>
                </div>
              </div>

              {/* Security Events Timeline */}
              <div>
                <h4 className="text-md font-medium text-gray-900 mb-3">Security Events Timeline</h4>
                <div className="space-y-3">
                  {conversationSessions
                    .filter(s => s.security_events > 0)
                    .sort((a, b) => new Date(b.last_activity).getTime() - new Date(a.last_activity).getTime())
                    .slice(0, 10)
                    .map((session) => (
                      <div key={session.session_id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <ExclamationTriangleIcon className="h-5 w-5 text-red-600" />
                          <div>
                            <div className="font-medium text-gray-900">
                              Session {session.session_id.slice(-8)}
                            </div>
                            <div className="text-sm text-gray-600">
                              {session.security_events} security events
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm text-gray-600">
                            {formatDate(session.last_activity)}
                          </div>
                          <div className={`text-xs font-medium ${getRiskColor(session.risk_score)}`}>
                            {getRiskLevel(session.risk_score)} Risk
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
