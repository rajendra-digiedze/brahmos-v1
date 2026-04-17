import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, Activity, Search, MessageCircle, Database, Server, Network, Brain, Maximize2, Minimize2, ExternalLink, Trash2, Download, Eye, EyeOff, LockKeyhole, User, Mail, ArrowRight } from 'lucide-react';
import {
  AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const resolveApiHost = () => {
  const host = window.location.hostname;
  if (host === "localhost" || host === "::1" || host === "0.0.0.0") {
    return "127.0.0.1";
  }
  return host;
};

const API_BASE = (import.meta.env.VITE_API_BASE_URL || `http://${resolveApiHost()}:8000/api`).replace(/\/$/, "");

const getFetchErrorMessage = (err) => {
  if (err instanceof TypeError) {
    return `Unable to reach backend (${API_BASE}). Open app with http://localhost:5173 and ensure backend is running on port 8000.`;
  }
  return err?.message || "Request failed.";
};

function App() {
  const [authToken, setAuthToken] = useState(() => localStorage.getItem("authToken") || "");
  const [authUser, setAuthUser] = useState(() => {
    const saved = localStorage.getItem("authUser");
    return saved ? JSON.parse(saved) : null;
  });
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ username: "", email: "", usernameOrEmail: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [authError, setAuthError] = useState("");
  const [isAuthLoading, setIsAuthLoading] = useState(false);
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState("All");
  const [timeRange, setTimeRange] = useState("");
  const [page, setPage] = useState(1);
  const [hasMaliciousAlert, setHasMaliciousAlert] = useState(false);
  const [lastCriticalId, setLastCriticalId] = useState(null);

  const [chatQuery, setChatQuery] = useState("");
  const [chatHistory, setChatHistory] = useState(() => {
    const saved = localStorage.getItem("chatHistory");
    return saved ? JSON.parse(saved) : [];
  });
  const [isChatting, setIsChatting] = useState(false);
  const [apiError, setApiError] = useState("");
  const [stats, setStats] = useState({ critical: 0, denied: 0, total: 0 });
  const [chartData, setChartData] = useState({ timeSeries: [], severityData: [] });
  const [isChatMaximized, setIsChatMaximized] = useState(false);

  useEffect(() => {
    if (authToken) {
      localStorage.setItem("authToken", authToken);
    } else {
      localStorage.removeItem("authToken");
    }
  }, [authToken]);

  useEffect(() => {
    if (authUser) {
      localStorage.setItem("authUser", JSON.stringify(authUser));
    } else {
      localStorage.removeItem("authUser");
    }
  }, [authUser]);

  useEffect(() => {
    localStorage.setItem("chatHistory", JSON.stringify(chatHistory));
  }, [chatHistory]);

  const withAuthHeaders = (headers = {}) => (
    authToken
      ? { ...headers, Authorization: `Bearer ${authToken}` }
      : headers
  );

  const handleAuthInput = (e) => {
    const { name, value } = e.target;
    setAuthForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleLogout = () => {
    setAuthToken("");
    setAuthUser(null);
    setAuthError("");
    setApiError("");
  };

  const handleAuthSubmit = async (e) => {
    e.preventDefault();
    setAuthError("");
    setIsAuthLoading(true);
    const endpoint = authMode === "login" ? "/auth/login" : "/auth/register";
    const payload = authMode === "login"
      ? { username_or_email: authForm.usernameOrEmail, password: authForm.password }
      : { username: authForm.username, email: authForm.email, password: authForm.password };

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data?.detail || "Authentication failed.");
      }
      setAuthToken(data.access_token);
      setAuthUser(data.user);
      setAuthForm({ username: "", email: "", usernameOrEmail: "", password: "" });
      setShowPassword(false);
      setApiError("");
    } catch (err) {
      setAuthError(getFetchErrorMessage(err));
    } finally {
      setIsAuthLoading(false);
    }
  };

  // Bug Fix: Reset Page Index if Filter changes
  useEffect(() => {
    setPage(1);
  }, [activeTab, timeRange]);

  useEffect(() => {
    if (!authToken) {
      return;
    }

    let isMounted = true;
    // Poll for new logs and SQL stats every 2 seconds
    const fetchData = async () => {
      try {
        const [logsRes, statsRes, chartRes] = await Promise.all([
          fetch(`${API_BASE}/logs?limit=500&page=${page}&time_range=${timeRange}&status_filter=${activeTab}`, {
            headers: withAuthHeaders(),
          }),
          fetch(`${API_BASE}/logs/stats`, { headers: withAuthHeaders() }),
          fetch(`${API_BASE}/logs/chart?time_range=${timeRange}&status_filter=${activeTab}`, {
            headers: withAuthHeaders(),
          })
        ]);
        if (logsRes.status === 401 || statsRes.status === 401 || chartRes.status === 401) {
          throw new Error("Unauthorized");
        }
        if (!logsRes.ok || !statsRes.ok || !chartRes.ok) {
          throw new Error("Backend returned a non-OK response.");
        }
        const logsData = await logsRes.json();
        const statsData = await statsRes.json();
        const chartRawData = await chartRes.json();

        if (isMounted) {
          // Client-Side Safeguard Filter: ensure the data matches the tab explicitly
          let filteredLogs = logsData;
          if (Array.isArray(logsData)) {
            if (activeTab !== "All") {
              const filterTarget = activeTab === "Malicious" ? "Critical" : activeTab;
              filteredLogs = logsData.filter(l =>
                activeTab === "Malicious" ? l.severity === "Critical" : l.status === activeTab
              );
            }
          }

          setLogs(filteredLogs);
          setStats(statsData);
          setApiError("");

          // Determine if we have a fresh Malicious alert.
          if (filteredLogs && filteredLogs.length > 0) {
            const newestLog = filteredLogs[0];
            if (newestLog.severity === 'Critical') {
              // check if it's new
              setLastCriticalId(prevId => {
                if (prevId !== newestLog.id) {
                  setHasMaliciousAlert(true);
                  setTimeout(() => { if (isMounted) setHasMaliciousAlert(false); }, 3000);
                  return newestLog.id;
                }
                return prevId;
              });
            }
          }

          processChartData(chartRawData);
        }
      } catch (err) {
        console.error("Failed to fetch data", err);
        if (isMounted) {
          if (String(err.message).includes("Unauthorized")) {
            handleLogout();
            setAuthError("Session expired. Please login again.");
          } else {
            setApiError(getFetchErrorMessage(err));
          }
        }
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeTab, timeRange, page, authToken]);

  const handleChat = async (e) => {
    e.preventDefault();
    if (!chatQuery.trim()) return;

    const newHistory = [...chatHistory, { role: "user", content: chatQuery }];
    setChatHistory(newHistory);
    setChatQuery("");
    setIsChatting(true);

    try {
      const res = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: withAuthHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ query: chatQuery })
      });
      if (res.status === 401) {
        handleLogout();
        setAuthError("Session expired. Please login again.");
        return;
      }
      const data = await res.json();
      setChatHistory([...newHistory, { role: "agent", content: data.response, pdf_url: data.pdf_url }]);
    } catch (err) {
      setChatHistory([...newHistory, { role: "agent", content: getFetchErrorMessage(err) }]);
    } finally {
      setIsChatting(false);
    }
  };

  const handleClearChat = () => {
    setChatHistory([]);
    setChatQuery("");
  };

  const maliciousCount = stats?.critical || 0;
  const deniedCount = stats?.denied || 0;

  // Chart Data Processing
  const processChartData = (apiChartData) => {
    let severityCount = { Critical: 0, High: 0, Low: 0 };

    // apiChartData has 'count', 'Critical', 'High', and 'time' already correctly aggregated by backend
    let timeSeries = [];
    if (Array.isArray(apiChartData)) {
      timeSeries = apiChartData.map(c => {
        let timeKey = c.time;
        const dateObj = new Date(c.time);
        if (!isNaN(dateObj.getTime())) {
          timeKey = dateObj.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit' });
        }

        severityCount.Critical += c.Critical;
        severityCount.High += c.High;
        const lows = Math.max(0, c.count - c.Critical - c.High);
        severityCount.Low += lows;

        return {
          time: timeKey,
          count: c.count,
          Critical: c.Critical,
          High: c.High,
          Low: lows
        };
      });
    }

    const severityData = [
      { name: 'Critical', value: severityCount.Critical, color: '#ef4444' },
      { name: 'High', value: severityCount.High, color: '#f59e0b' },
      { name: 'Low/Other', value: severityCount.Low, color: '#94a3b8' }
    ].filter(d => d.value > 0);

    setChartData({ timeSeries, severityData });
  };

  const { timeSeries, severityData } = chartData;
  const passwordValue = authForm.password || "";
  const passwordScore =
    (passwordValue.length >= 8 ? 1 : 0) +
    (/[A-Z]/.test(passwordValue) ? 1 : 0) +
    (/[0-9]/.test(passwordValue) ? 1 : 0) +
    (/[^A-Za-z0-9]/.test(passwordValue) ? 1 : 0);
  const passwordStrength = passwordScore <= 1 ? "Weak" : passwordScore <= 3 ? "Medium" : "Strong";
  const passwordStrengthColor = passwordStrength === "Strong" ? "text-emerald-400" : passwordStrength === "Medium" ? "text-amber-400" : "text-rose-400";

  if (!authToken || !authUser) {
    return (
      <div className="relative min-h-screen overflow-hidden bg-white p-4 font-sans sm:p-8">
        <div className="mx-auto flex min-h-[calc(100vh-2rem)] w-full max-w-md items-center">
          <div className="w-full rounded-3xl border border-slate-200 bg-white p-7 shadow-2xl sm:p-8">
            <div className="mb-6 flex items-center gap-3">
              <div className="rounded-xl bg-indigo-600/90 p-2 text-white shadow-lg shadow-indigo-800/40">
                <ShieldAlert className="h-6 w-6" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-slate-900">Secure Access</h1>
                <p className="text-xs text-slate-500">
                  {authMode === "login"
                    ? "Sign in to continue."
                    : "Create an account to continue."}
                </p>
              </div>
            </div>

            <div className="mb-5 grid grid-cols-2 gap-2 rounded-xl border border-slate-200 bg-slate-100 p-1">
              <button
                onClick={() => setAuthMode("login")}
                className={`rounded-lg px-3 py-2 text-sm font-medium transition-all ${authMode === "login" ? "bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-lg shadow-indigo-900/30" : "text-slate-600 hover:bg-white"}`}
              >
                Login
              </button>
              <button
                onClick={() => setAuthMode("register")}
                className={`rounded-lg px-3 py-2 text-sm font-medium transition-all ${authMode === "register" ? "bg-gradient-to-r from-indigo-600 to-cyan-600 text-white shadow-lg shadow-indigo-900/30" : "text-slate-600 hover:bg-white"}`}
              >
                Register
              </button>
            </div>

            <form onSubmit={handleAuthSubmit} className="space-y-3">
              {authMode === "register" && (
                <>
                  <label className="relative block">
                    <User className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                    <input
                      name="username"
                      value={authForm.username}
                      onChange={handleAuthInput}
                      placeholder="Username"
                      className="w-full rounded-lg border border-slate-300 bg-white px-10 py-2.5 text-sm text-slate-900 outline-none transition-colors focus:border-indigo-500"
                      required
                    />
                  </label>
                  <label className="relative block">
                    <Mail className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                    <input
                      name="email"
                      type="email"
                      value={authForm.email}
                      onChange={handleAuthInput}
                      placeholder="Email"
                      className="w-full rounded-lg border border-slate-300 bg-white px-10 py-2.5 text-sm text-slate-900 outline-none transition-colors focus:border-indigo-500"
                      required
                    />
                  </label>
                </>
              )}
              {authMode === "login" && (
                <label className="relative block">
                  <User className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                  <input
                    name="usernameOrEmail"
                    value={authForm.usernameOrEmail}
                    onChange={handleAuthInput}
                    placeholder="Email"
                    className="w-full rounded-lg border border-slate-300 bg-white px-10 py-2.5 text-sm text-slate-900 outline-none transition-colors focus:border-indigo-500"
                    required
                  />
                </label>
              )}
              <div className="relative">
                <LockKeyhole className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                <input
                  name="password"
                  type={showPassword ? "text" : "password"}
                  value={authForm.password}
                  onChange={handleAuthInput}
                  placeholder="Password"
                  className="w-full rounded-lg border border-slate-300 bg-white px-10 py-2.5 pr-10 text-sm text-slate-900 outline-none transition-colors focus:border-indigo-500"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((prev) => !prev)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-700"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  title={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>

              <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
                <div className="mb-2 flex items-center justify-between text-xs">
                  <span className="text-slate-600">Password guidance</span>
                  <span className={`font-medium ${passwordStrengthColor}`}>{passwordStrength}</span>
                </div>
                <div className="mb-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-200">
                  <div
                    className={`h-full rounded-full transition-all ${
                      passwordStrength === "Strong"
                        ? "bg-emerald-500"
                        : passwordStrength === "Medium"
                          ? "bg-amber-500"
                          : "bg-rose-500"
                    }`}
                    style={{ width: `${Math.max(15, (passwordScore / 4) * 100)}%` }}
                  />
                </div>
                <p className="flex items-center gap-2 text-xs text-slate-600">
                  <LockKeyhole className="h-3.5 w-3.5" />
                  Use 8+ chars with uppercase, number, and symbol for stronger security.
                </p>
              </div>

              {authError && (
                <p className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
                  {authError}
                </p>
              )}

              <button
                type="submit"
                disabled={isAuthLoading}
                className="group flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-500 px-3 py-2.5 text-sm font-semibold text-white shadow-lg shadow-indigo-900/40 transition hover:from-indigo-500 hover:to-cyan-400 disabled:opacity-60"
              >
                {isAuthLoading ? "Please wait..." : authMode === "login" ? "Login" : "Create Account"}
                {!isAuthLoading && <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 p-6 font-sans">
      <header className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="h-8 w-8 text-indigo-500" />
          <h1 className="text-2xl font-bold text-indigo-200">
            dZshield Enterprise SOC Dashboard
          </h1>
          {hasMaliciousAlert && (
            <div className="ml-4 flex items-center gap-2 px-3 py-1 bg-red-900/50 border border-red-500 rounded-full animate-pulse transition-all">
              <div className="w-2.5 h-2.5 bg-red-500 rounded-full shadow-[0_0_8px_rgba(239,68,68,0.8)]"></div>
              <span className="text-xs text-red-400 font-bold tracking-wider">MALICIOUS ALERT</span>
            </div>
          )}
        </div>
        <div className="flex gap-4 items-center">
          <div className="bg-slate-900 px-4 py-2 rounded-lg border border-slate-800 flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
            <span className="text-sm font-medium">Critical (L2 NiFi): {maliciousCount}</span>
          </div>
          <div className="bg-slate-900 px-4 py-2 rounded-lg border border-slate-800 flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-orange-500"></div>
            <span className="text-sm font-medium">Denied (L1 K8s): {deniedCount}</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2">
            <span className="text-xs text-slate-300">Signed in as {authUser.username}</span>
            <button
              onClick={handleLogout}
              className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700"
            >
              Logout
            </button>
          </div>
        </div>
      </header>
      {apiError && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-300">
          {apiError}
        </div>
      )}

      {/* Navigation & Filters */}
      <div className="flex flex-col lg:flex-row justify-between items-center bg-slate-900 p-4 rounded-xl shadow-xl border border-slate-800 mb-6 gap-4">
        <div className="flex gap-2 w-full lg:w-auto overflow-x-auto">
          {['All', 'Allowed', 'Denied', 'Malicious'].map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === tab ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'}`}>
              {tab}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-4 w-full lg:w-auto shrink-0">
          <span className="text-slate-400 text-sm font-medium">Timeline Timeline:</span>
          <select
            className="bg-slate-950 border border-slate-700 rounded-lg py-2 px-3 text-sm text-white focus:outline-none focus:border-indigo-500 min-w-[140px]"
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
          >
            <option value="">All Time</option>
            <option value="5m">Last 5 Mins</option>
            <option value="10m">Last 10 Mins</option>
            <option value="15m">Last 15 Mins</option>
            <option value="30m">Last 30 Mins</option>
            <option value="1h">Last 1 Hour</option>
            <option value="2h">Last 2 Hours</option>
            <option value="4h">Last 4 Hours</option>
            <option value="6h">Last 6 Hours</option>
            <option value="12h">Last 12 Hours</option>
            <option value="1d">Last 1 Day</option>
            <option value="7d">Last 7 Days</option>
          </select>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Time Series Area Chart */}
        <div className="lg:col-span-2 bg-slate-900 rounded-xl border border-slate-800 shadow-xl p-4 h-72">
          <h2 className="text-sm font-semibold flex items-center gap-2 text-slate-300 mb-4">
            <Activity className="w-4 h-4" /> Traffic Flow ({activeTab === "All" ? "Events" : `${activeTab} Logs`}/sec)
          </h2>
          <ResponsiveContainer width="100%" height="85%">
            <AreaChart data={timeSeries}>
              <defs>
                <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
              <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} tickMargin={10} minTickGap={20} />
              <YAxis stroke="#94a3b8" fontSize={12} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Area type="monotone" dataKey="count" name={activeTab === "All" ? "Total Events" : `${activeTab} Events`} stroke="#6366f1" fillOpacity={1} fill="url(#colorCount)" />
              {activeTab === "All" && (
                <Area type="monotone" dataKey="Critical" name="Critical Events" stroke="#ef4444" fillOpacity={1} fill="url(#colorCrit)" />
              )}
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution Pie Chart */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 shadow-xl p-4 h-72">
          <h2 className="text-sm font-semibold flex items-center gap-2 text-slate-300 mb-4">
            <ShieldAlert className="w-4 h-4" /> Severity Distribution
          </h2>
          <ResponsiveContainer width="100%" height="85%">
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
                stroke="none"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', borderRadius: '8px' }}
                itemStyle={{ color: '#e2e8f0' }}
              />
              <Legend verticalAlign="bottom" height={36} iconType="circle" />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Integrations Panel */}
        <div className="bg-slate-900 rounded-xl border border-slate-800 shadow-xl overflow-hidden flex flex-col h-[55vh] p-4 space-y-4">
          <h2 className="text-lg font-semibold flex items-center gap-2 text-slate-300 pb-2 border-b border-slate-800">
            <Network className="w-5 h-5" /> Zero-Trust Topology
          </h2>

          <div className="space-y-3 flex-1 overflow-y-auto pr-2">
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L1: Infrastructure</span>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Server className="w-3 h-3 text-green-400" /> Kubernetes / dZ GaaS</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L2: Data Platform</span>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Database className="w-3 h-3 text-green-400" /> Apache NiFi / Atlas</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L3: Knowledge Base</span>
                <a href="http://localhost:6333/dashboard" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300" title="Open Qdrant Visualizer"><ExternalLink className="w-3 h-3" /></a>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Database className="w-3 h-3 text-green-400" /> Qdrant / Neo4j Vectors</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L4/L5: AI Matrix</span>
                <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300" title="Open AI LLMA/Mistral API"><ExternalLink className="w-3 h-3" /></a>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Brain className="w-3 h-3 text-green-400" /> LlamaIndex / LLMA Tools</span>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Brain className="w-3 h-3 text-green-400" /> LangGraph AI</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L6: Orchestration</span>
                <a href="http://localhost:5678" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300" title="Open n8n Interface"><ExternalLink className="w-3 h-3" /></a>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Activity className="w-3 h-3 text-green-400" /> n8n Automation</span>
            </div>
            <div className="bg-slate-950 p-3 rounded-lg border border-indigo-900/50 flex flex-col gap-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-indigo-400 font-bold">L7: Agent Web</span>
                <a href="/" target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300" title="Open Dashboard"><ExternalLink className="w-3 h-3" /></a>
              </div>
              <span className="text-sm text-slate-300 flex items-center gap-2"><Shield className="w-3 h-3 text-green-400" /> Web Dashboard</span>
            </div>
          </div>
        </div>

        {/* Log Viewer Widget */}
        <div className="lg:col-span-2 bg-slate-900 rounded-xl border border-slate-800 shadow-xl overflow-hidden flex flex-col h-[55vh]">
          <div className="p-4 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
            <h2 className="text-lg font-semibold flex items-center gap-2"><Activity className="w-5 h-5" /> Live Network Logs</h2>
            <span className="text-xs text-slate-400">Updates every 2s</span>
          </div>
          <div className="overflow-y-auto flex-1 p-0">
            <table className="w-full text-left text-sm whitespace-nowrap">
              <thead className="bg-slate-800/50 text-slate-300 sticky top-0">
                <tr>
                  <th className="px-4 py-3 font-medium">Timeline</th>
                  <th className="px-4 py-3 font-medium">Source IP</th>
                  <th className="px-4 py-3 font-medium">Dest IP</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {Array.isArray(logs) && logs.map((log) => {
                  // extract fields from raw string: timeline| Source IP| Destination IP| Source Port| Destiantion Port| Status| Seviority
                  if (!log || !log.raw_log) return null;
                  const parts = log.raw_log.split('|').map(s => s.trim());
                  const time = parts.length > 0 ? parts[0] : "N/A";
                  const src = parts.length > 3 ? `${parts[1]}:${parts[3]}` : "N/A";
                  const dst = parts.length > 4 ? `${parts[2]}:${parts[4]}` : "N/A";

                  return (
                    <tr key={log.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-4 py-2 text-slate-400 font-mono text-xs">{new Date(time).toLocaleTimeString()}</td>
                      <td className="px-4 py-2 font-mono text-slate-300">{src}</td>
                      <td className="px-4 py-2 font-mono text-slate-300">{dst}</td>
                      <td className="px-4 py-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${log.status === 'Allowed' ? 'bg-green-500/10 text-green-400' :
                            log.status === 'Denied' ? 'bg-orange-500/10 text-orange-400' :
                              'bg-red-500/10 text-red-400'
                          }`}>
                          {log.status}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${log.severity === 'Critical' ? 'text-red-500 font-bold' :
                            log.severity === 'High' ? 'text-orange-500' :
                              'text-slate-400'
                          }`}>
                          {log.severity}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {logs.length === 0 && (
              <div className="flex justify-center items-center h-full text-slate-500 py-10">
                Waiting for logs or NO matches found...
              </div>
            )}
          </div>
          {/* Pagination Controls */}
          <div className="flex justify-between items-center p-3 border-t border-slate-800 bg-slate-900/50">
            <button
              disabled={page === 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-indigo-600 hover:text-white transition-colors disabled:opacity-50"
            >
              Previous 500
            </button>
            <span className="text-slate-400 text-sm">Page {page}</span>
            <button
              disabled={logs.length < 500}
              onClick={() => setPage(p => p + 1)}
              className="px-3 py-1 bg-slate-800 text-slate-300 rounded hover:bg-indigo-600 hover:text-white transition-colors disabled:opacity-50"
            >
              Next 500
            </button>
          </div>
        </div>

        {/* AI Agent Chat Interface */}
        <div className={`bg-slate-900 rounded-xl border border-slate-800 shadow-xl overflow-hidden flex flex-col ${isChatMaximized ? 'fixed inset-4 z-50 lg:inset-x-20 lg:inset-y-10' : 'h-[55vh]'}`}>
          <div className="p-4 border-b border-slate-800 bg-indigo-950/30 flex justify-between items-center">
            <h2 className="text-lg font-semibold flex items-center gap-2 text-indigo-300">
              <MessageCircle className="w-5 h-5" /> Chat4ED Console
            </h2>
            <div className="flex items-center gap-2">
              <button
                onClick={handleClearChat}
                className="p-1 hover:bg-slate-800 rounded-md text-red-400 hover:text-red-300 transition-colors"
                title="Clear Chat History"
              >
                <Trash2 className="w-4 h-4" />
              </button>
              <button
                onClick={() => setIsChatMaximized(!isChatMaximized)}
                className="p-1 hover:bg-slate-800 rounded-md text-slate-400 transition-colors"
                title={isChatMaximized ? "Minimize Console" : "Maximize Console for Reports"}
              >
                {isChatMaximized ? <Minimize2 className="w-5 h-5" /> : <Maximize2 className="w-5 h-5" />}
              </button>
            </div>
          </div>

          <div className={`flex-1 overflow-y-auto p-4 space-y-4 ${isChatMaximized ? 'bg-slate-950' : ''}`}>
            <div className="bg-slate-800/50 rounded-lg p-3 text-sm text-slate-300 inline-block">
              Welcome to the Chat4ED Analyst Console (Layer 7). My logic is governed by CrewAI orchestration and Mistral NLP models. How can I assist with your attack graph investigations today? You can ask me for reports on any timeframe!
            </div>

            {chatHistory.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`rounded-lg p-4 text-sm whitespace-pre-wrap flex-col ${msg.role === 'user'
                    ? 'bg-blue-600/20 text-blue-200 border border-blue-500/20 max-w-[85%]'
                    : 'bg-slate-800/50 text-slate-300 border border-slate-700/50 w-full lg:max-w-[95%]'
                  }`}>
                  {msg.content}
                  {msg.pdf_url && (
                    <div className="mt-3">
                      <a href={msg.pdf_url.startsWith('http') ? msg.pdf_url : API_BASE.replace('/api', '') + msg.pdf_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 rounded-lg text-white font-semibold hover:bg-indigo-500 transition-colors shadow-lg shadow-indigo-900/20 w-fit">
                        <Download className="w-4 h-4" /> Download PDF Report
                      </a>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {isChatting && (
              <div className="text-slate-500 text-sm italic">Agent is analyzing logs and preparing reports...</div>
            )}
          </div>

          <form onSubmit={handleChat} className="p-4 border-t border-slate-800 bg-slate-900/50">
            <div className="relative">
              <input
                type="text"
                value={chatQuery}
                onChange={e => setChatQuery(e.target.value)}
                placeholder="Ask about logs, reports, or timeframes (e.g. 'Give me logs for last 5 mins')..."
                className="w-full bg-slate-950 border border-slate-700 rounded-lg py-3 pl-4 pr-12 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                disabled={isChatting}
              />
              <button
                type="submit"
                disabled={isChatting}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-2 bg-indigo-600 hover:bg-indigo-500 rounded-md text-white transition-colors disabled:opacity-50"
              >
                <Search className="w-4 h-4" />
              </button>
            </div>
          </form>
        </div>
      </div>
      {isChatMaximized && (
        <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={() => setIsChatMaximized(false)}></div>
      )}
    </div>
  );
}

export default App;
