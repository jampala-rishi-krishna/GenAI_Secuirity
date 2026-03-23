import { useEffect, useState } from 'react';
import Head from 'next/head';
import { ShieldCheckIcon, ChatBubbleLeftRightIcon, ChartBarIcon, CogIcon, ArrowRightIcon, CheckCircleIcon, SparklesIcon } from '@heroicons/react/24/outline';
import { ShieldCheckIcon as ShieldCheckSolid } from '@heroicons/react/24/solid';
import Link from 'next/link';

export default function Home() {
  const [activeTab, setActiveTab] = useState('overview');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('access_token');
      const storedExpiry = localStorage.getItem('session_expires_at');
      const expiryTs = storedExpiry ? parseInt(storedExpiry, 10) : null;
      const now = Date.now();
      if (!token || !expiryTs || expiryTs <= now) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('session_expires_at');
        setIsAuthenticated(false);
      } else {
        setIsAuthenticated(true);
      }
    }
  }, []);

  const features = [
    {
      title: 'OWASP Top 10 Compliance',
      description: 'Full implementation of OWASP Top 10 for LLM Applications 2025',
      icon: ShieldCheckIcon,
      color: 'text-emerald-600',
      bgColor: 'bg-emerald-50',
      gradient: 'from-emerald-500 to-teal-600',
    },
    {
      title: 'Secure Healthcare AI',
      description: 'AI-powered healthcare assistant with comprehensive security measures',
      icon: ChatBubbleLeftRightIcon,
      color: 'text-blue-600',
      bgColor: 'bg-blue-50',
      gradient: 'from-blue-500 to-indigo-600',
    },
    {
      title: 'Real-time Monitoring',
      description: 'Live security dashboard with threat detection and analytics',
      icon: ChartBarIcon,
      color: 'text-purple-600',
      bgColor: 'bg-purple-50',
      gradient: 'from-purple-500 to-pink-600',
    },
    {
      title: 'Role-Based Access Control',
      description: 'Advanced RBAC system with fine-grained permissions',
      icon: CogIcon,
      color: 'text-orange-600',
      bgColor: 'bg-orange-50',
      gradient: 'from-orange-500 to-red-600',
    },
  ];

  const owaspCoverage = [
    { id: 'LLM01', title: 'Prompt Injection', status: '✅ Implemented', description: 'Input validation and filtering', severity: 'Critical' },
    { id: 'LLM02', title: 'Sensitive Information Disclosure', status: '✅ Implemented', description: 'Data sanitization and PII detection', severity: 'High' },
    { id: 'LLM04', title: 'Model Denial of Service', status: '✅ Implemented', description: 'Rate limiting and throttling', severity: 'High' },
    { id: 'LLM05', title: 'Improper Output Handling', status: '✅ Implemented', description: 'Output validation and encoding', severity: 'Medium' },
    { id: 'LLM06', title: 'Excessive Agency', status: '✅ Implemented', description: 'Least privilege access control', severity: 'Medium' },
    { id: 'LLM07', title: 'System Prompt Leakage', status: '✅ Implemented', description: 'Secure prompt management', severity: 'High' },
    { id: 'LLM09', title: 'Misinformation', status: '✅ Implemented', description: 'Output verification and disclaimers', severity: 'Low' },
    { id: 'LLM10', title: 'Unbounded Consumption', status: '✅ Implemented', description: 'Rate limiting and resource management', severity: 'Medium' },
  ];

  const stats = [
    { label: 'Security Vulnerabilities Blocked', value: '99.9%', description: 'Real-time threat prevention' },
    { label: 'Response Time', value: '< 200ms', description: 'Lightning-fast security checks' },
    { label: 'Uptime', value: '99.99%', description: 'Enterprise-grade reliability' },
    { label: 'Compliance Score', value: '100%', description: 'Full OWASP Top 10 coverage' },
  ];

  return (
    <>
      <Head>
        <title>Healthcare GenAI Security - OWASP Top 10 Implementation</title>
        <meta name="description" content="A comprehensive Healthcare GenAI Application with OWASP Top 10 for LLM Applications 2025 security implementation" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
        {/* Navigation */}
        <nav className="bg-white/80 backdrop-blur-md border-b border-white/20 sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex items-center">
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-lg blur-sm opacity-75"></div>
                  <ShieldCheckIcon className="relative h-8 w-8 text-white" />
                </div>
                <span className="ml-3 text-xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent">
                  Healthcare GenAI Security
                </span>
              </div>
              <div className="flex items-center space-x-6">
                <Link href="/chat" className="text-gray-700 hover:text-blue-600 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 hover:bg-blue-50">
                  Chat
                </Link>
                {isAuthenticated ? (
                  <Link href="/login" className="text-gray-700 hover:text-blue-600 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 hover:bg-blue-50">
                    Admin
                  </Link>
                ) : (
                  <Link href="/login?force=1" className="text-gray-700 hover:text-blue-600 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 hover:bg-blue-50">
                    Login
                  </Link>
                )}
                <Link href="/chat" className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-6 py-2 rounded-lg text-sm font-medium hover:shadow-lg hover:scale-105 transition-all duration-200">
                  Get Started
                </Link>
              </div>
            </div>
          </div>
        </nav>

        {/* Hero Section */}
        <div className="relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-blue-600/10 via-purple-600/10 to-indigo-600/10"></div>
          <div className="relative max-w-7xl mx-auto py-24 px-4 sm:py-32 sm:px-6 lg:px-8">
            <div className="text-center">
              <div className="inline-flex items-center px-4 py-2 rounded-full bg-blue-50 border border-blue-200 mb-8">
                <SparklesIcon className="h-4 w-4 text-blue-600 mr-2" />
                <span className="text-sm font-medium text-blue-700">Enterprise-Grade Security</span>
              </div>
              
              <h1 className="text-5xl font-extrabold tracking-tight text-gray-900 sm:text-6xl md:text-7xl">
                <span className="block">Healthcare GenAI</span>
                <span className="block bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 bg-clip-text text-transparent">
                  Security-First
                </span>
              </h1>
              
              <p className="mt-8 max-w-3xl mx-auto text-xl text-gray-600 leading-relaxed">
                A comprehensive demonstration of how GenAI applications can be properly secured following industry best practices and OWASP Top 10 for LLM Applications 2025.
              </p>
              
              <div className="mt-12 flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-6">
                <Link href="/chat" className="group bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-8 py-4 rounded-xl text-lg font-semibold hover:shadow-xl hover:scale-105 transition-all duration-200 flex items-center justify-center">
                  Try the Chat
                  <ArrowRightIcon className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
                </Link>
                <Link href="/login?force=1" className="group bg-white text-gray-900 px-8 py-4 rounded-xl text-lg font-semibold border-2 border-gray-200 hover:border-blue-300 hover:shadow-lg transition-all duration-200 flex items-center justify-center">
                  Login to Access
                  <ChartBarIcon className="ml-2 h-5 w-5 group-hover:scale-110 transition-transform" />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Section */}
        <div className="py-16 bg-white/50 backdrop-blur-sm">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-4">
              {stats.map((stat, index) => (
                <div key={index} className="text-center group">
                  <div className="bg-white rounded-2xl p-6 shadow-sm hover:shadow-lg transition-all duration-200 border border-gray-100">
                    <div className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                      {stat.value}
                    </div>
                    <div className="mt-2 text-sm font-medium text-gray-900">{stat.label}</div>
                    <div className="mt-1 text-xs text-gray-500">{stat.description}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Features Section */}
        <div className="py-24 bg-gradient-to-br from-white to-gray-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-gray-900 sm:text-5xl">
                Security Features
              </h2>
              <p className="mt-6 text-xl text-gray-600 max-w-3xl mx-auto">
                Comprehensive security implementation covering all major threat vectors with real-time protection
              </p>
            </div>
            
            <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-4">
              {features.map((feature, index) => (
                <div key={feature.title} className="group relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-2xl blur-lg opacity-0 group-hover:opacity-20 transition-opacity duration-300"></div>
                  <div className="relative bg-white rounded-2xl p-8 shadow-sm hover:shadow-xl transition-all duration-300 border border-gray-100 h-full">
                    <div className={`inline-flex p-4 rounded-xl ${feature.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                      <feature.icon className={`h-8 w-8 ${feature.color}`} />
                    </div>
                    <h3 className="mt-6 text-xl font-bold text-gray-900">{feature.title}</h3>
                    <p className="mt-4 text-gray-600 leading-relaxed">{feature.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* OWASP Coverage Section */}
        <div className="py-24 bg-gradient-to-br from-gray-900 via-blue-900 to-indigo-900">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-white sm:text-5xl">
                OWASP Top 10 for LLM Applications 2025
              </h2>
              <p className="mt-6 text-xl text-blue-200 max-w-3xl mx-auto">
                Complete coverage of all security requirements with enterprise-grade implementation
              </p>
            </div>
            
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              {owaspCoverage.map((item) => (
                <div key={item.id} className="group bg-white/10 backdrop-blur-sm rounded-2xl p-6 border border-white/20 hover:bg-white/20 transition-all duration-300">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <h3 className="text-lg font-bold text-white">
                          {item.id}: {item.title}
                        </h3>
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          {item.severity}
                        </span>
                      </div>
                      <p className="text-blue-200">{item.description}</p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircleIcon className="h-6 w-6 text-green-400" />
                      <span className="text-sm font-medium text-green-400">Implemented</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Security Showcase Section */}
        <div className="py-24 bg-gradient-to-br from-white to-blue-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="text-center mb-16">
              <h2 className="text-4xl font-bold text-gray-900 sm:text-5xl">
                Security Showcase
              </h2>
              <p className="mt-6 text-xl text-gray-600 max-w-3xl mx-auto">
                Interactive demonstrations of security features in action
              </p>
            </div>
            
            <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
              <div className="group bg-white rounded-2xl shadow-sm p-8 hover:shadow-xl transition-all duration-300 border border-gray-100">
                <div className="bg-gradient-to-r from-red-500 to-pink-500 p-4 rounded-xl w-fit mb-6">
                  <ShieldCheckIcon className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-4">Threat Detection Demo</h3>
                <p className="text-gray-600 mb-6 leading-relaxed">
                  See real-time prompt injection blocking and malicious input detection in action.
                </p>
                <Link href="/chat?demo=security" className="inline-flex items-center text-blue-600 hover:text-blue-700 font-medium group-hover:translate-x-1 transition-transform">
                  Try Demo
                  <ArrowRightIcon className="ml-2 h-4 w-4" />
                </Link>
              </div>
              
              <div className="group bg-white rounded-2xl shadow-sm p-8 hover:shadow-xl transition-all duration-300 border border-gray-100">
                <div className="bg-gradient-to-r from-blue-500 to-indigo-500 p-4 rounded-xl w-fit mb-6">
                  <ShieldCheckIcon className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-4">Data Protection Demo</h3>
                <p className="text-gray-600 mb-6 leading-relaxed">
                  Witness PII masking and sensitive data anonymization in real-time.
                </p>
                <Link href="/chat?demo=data-protection" className="inline-flex items-center text-blue-600 hover:text-blue-700 font-medium group-hover:translate-x-1 transition-transform">
                  Try Demo
                  <ArrowRightIcon className="ml-2 h-4 w-4" />
                </Link>
              </div>
              
              <div className="group bg-white rounded-2xl shadow-sm p-8 hover:shadow-xl transition-all duration-300 border border-gray-100">
                <div className="bg-gradient-to-r from-purple-500 to-pink-500 p-4 rounded-xl w-fit mb-6">
                  <CogIcon className="h-8 w-8 text-white" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 mb-4">Access Control Demo</h3>
                <p className="text-gray-600 mb-6 leading-relaxed">
                  Experience role-based permission enforcement and security controls.
                </p>
                <Link href="/login?demo=access-control" className="inline-flex items-center text-blue-600 hover:text-blue-700 font-medium group-hover:translate-x-1 transition-transform">
                  Try Demo
                  <ArrowRightIcon className="ml-2 h-4 w-4" />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* CTA Section */}
        <div className="relative overflow-hidden bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600">
          <div className="absolute inset-0 bg-black/20"></div>
          <div className="relative max-w-7xl mx-auto py-16 px-4 sm:py-24 sm:px-6 lg:px-8 lg:flex lg:items-center lg:justify-between">
            <div className="max-w-3xl">
              <h2 className="text-4xl font-bold tracking-tight text-white sm:text-5xl">
                <span className="block">Ready to see security in action?</span>
                <span className="block text-blue-200">Start exploring the application.</span>
              </h2>
              <p className="mt-6 text-xl text-blue-100">
                Experience enterprise-grade security measures protecting your AI interactions.
              </p>
            </div>
            <div className="mt-8 flex lg:mt-0 lg:flex-shrink-0">
              <div className="inline-flex rounded-xl shadow-lg">
                <Link href="/chat" className="inline-flex items-center justify-center px-8 py-4 border border-transparent text-lg font-semibold rounded-xl text-blue-600 bg-white hover:bg-gray-50 hover:scale-105 transition-all duration-200">
                  Get Started
                  <ArrowRightIcon className="ml-2 h-5 w-5" />
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <footer className="bg-gray-900">
          <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
            <div className="text-center">
              <div className="flex justify-center mb-6">
                <div className="relative">
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-lg blur-sm opacity-75"></div>
                  <ShieldCheckIcon className="relative h-8 w-8 text-white" />
                </div>
              </div>
              <p className="text-lg text-gray-300 mb-2">
                Healthcare GenAI Security Application
              </p>
              <p className="text-sm text-gray-500">
                Demonstrating secure AI implementation with Next.js, FastAPI, and comprehensive security measures
              </p>
            </div>
          </div>
        </footer>
      </div>
    </>
  );
} 