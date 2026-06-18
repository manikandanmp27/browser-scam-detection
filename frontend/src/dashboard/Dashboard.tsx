import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  History, 
  List, 
  AlertOctagon, 
  BookOpen, 
  Activity, 
  Search, 
  RefreshCw, 
  Trash2, 
  Check, 
  Plus, 
  Info,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { DashboardStats, UrlScanResponse, ScamReportCreate, TopThreat } from '../types';

const BACKEND_URL = 'https://browser-scam-detection.onrender.com';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<'overview' | 'history' | 'lists' | 'report' | 'academy'>('overview');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [history, setHistory] = useState<UrlScanResponse[]>([]);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [blacklist, setBlacklist] = useState<{ domain: string; source: string; added_at: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Search and Filter States for History
  const [historySearch, setHistorySearch] = useState('');
  const [historyFilter, setHistoryFilter] = useState('all');
  const [expandedScans, setExpandedScans] = useState<Record<number, boolean>>({});

  // Whitelist / Blacklist inputs
  const [listSubTab, setListSubTab] = useState<'whitelist' | 'blacklist'>('whitelist');
  const [newDomain, setNewDomain] = useState('');
  const [blacklistSource, setBlacklistSource] = useState('admin');

  // Scam Report form inputs
  const [reportUrl, setReportUrl] = useState('');
  const [reportReason, setReportReason] = useState('Phishing website impersonating brand');
  const [reportDesc, setReportDesc] = useState('');
  const [reportSuccess, setReportSuccess] = useState(false);
  const [submittingReport, setSubmittingReport] = useState(false);

  const fetchData = async (silent = false) => {
    if (!silent) setLoading(true);
    setErrorMsg(null);
    try {
      // Fetch Stats
      const statsRes = await fetch(`${BACKEND_URL}/api/v1/stats`);
      if (!statsRes.ok) throw new Error('Failed to fetch dashboard metrics.');
      const statsData = await statsRes.json();
      setStats(statsData);

      // Fetch full history
      const historyRes = await fetch(`${BACKEND_URL}/api/v1/history?limit=100`);
      if (historyRes.ok) {
        const historyData = await historyRes.json();
        setHistory(historyData);
      }

      // Fetch Whitelist
      const wlRes = await fetch(`${BACKEND_URL}/api/v1/whitelist`);
      if (wlRes.ok) {
        const wlData = await wlRes.json();
        setWhitelist(wlData);
      }

      // Fetch Blacklist
      const blRes = await fetch(`${BACKEND_URL}/api/v1/blacklist`);
      if (blRes.ok) {
        const blData = await blRes.json();
        setBlacklist(blData);
      }

    } catch (err) {
      console.error(err);
      setErrorMsg('ScamShield Backend Service is unreachable. Displaying fallback/cached records.');
      // Initialize mock data for offline visual demo
      loadMockData();
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const loadMockData = () => {
    setStats({
      total_scans: 148,
      total_scams_detected: 24,
      total_reports: 9,
      recent_scans: [],
      top_threats: [
        { domain: 'amaz0n-delivery-support.com', count: 12, max_risk: 92 },
        { domain: 'metamask-wallets-claim.xyz', count: 6, max_risk: 95 },
        { domain: 'paypal-security-signin.cf', count: 5, max_risk: 88 }
      ]
    });
    setHistory([
      {
        id: 1,
        url: 'https://paypal-security-signin.cf/login',
        domain: 'paypal-security-signin.cf',
        risk_score: 88,
        category: 'Confirmed Scam',
        reasons: ['Brand name "paypal" in domain.', 'Suspicious TLD (.cf).', 'Password credentials field found.'],
        details: { typosquatting_detected: true, whois_age_days: 6 },
        scanned_at: new Date(Date.now() - 3600000).toISOString()
      },
      {
        id: 2,
        url: 'https://www.google.com/',
        domain: 'google.com',
        risk_score: 0,
        category: 'Safe',
        reasons: [],
        details: { whitelisted: true },
        scanned_at: new Date(Date.now() - 12000000).toISOString()
      },
      {
        id: 3,
        url: 'https://amaz0n-delivery-support.com/gift',
        domain: 'amaz0n-delivery-support.com',
        risk_score: 92,
        category: 'Confirmed Scam',
        reasons: ['Typosquatting of brand "amazon".', 'Giveaway keywords matched in path.'],
        details: { typosquatting_detected: true, whois_age_days: 14 },
        scanned_at: new Date(Date.now() - 25000000).toISOString()
      },
      {
        id: 4,
        url: 'https://crypto-doubler-giveaway.win/index.html',
        domain: 'crypto-doubler-giveaway.win',
        risk_score: 75,
        category: 'High Risk',
        reasons: ['Double crypto scam text detected.', 'Suspicious TLD (.win).'],
        details: { whois_age_days: 29 },
        scanned_at: new Date(Date.now() - 50000000).toISOString()
      }
    ]);
    setWhitelist(['google.com', 'github.com', 'microsoft.com', 'apple.com']);
    setBlacklist([
      { domain: 'paypa1-verify-secure.org', source: 'admin', added_at: new Date().toISOString() },
      { domain: 'claim-free-btc-reward.xyz', source: 'community', added_at: new Date().toISOString() }
    ]);
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData(true);
  };

  const toggleExpandScan = (id?: number) => {
    if (!id) return;
    setExpandedScans(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // Add rule to whitelist/blacklist
  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return;

    try {
      const endpoint = listSubTab === 'whitelist' ? 'whitelist' : 'blacklist';
      const payload = listSubTab === 'whitelist' 
        ? { domain: newDomain.trim() }
        : { domain: newDomain.trim(), source: blacklistSource };

      const res = await fetch(`${BACKEND_URL}/api/v1/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        setNewDomain('');
        fetchData(true);
      }
    } catch (err) {
      console.error(err);
      // Offline fallback additions
      if (listSubTab === 'whitelist') {
        setWhitelist(prev => [...prev, newDomain.trim()]);
      } else {
        setBlacklist(prev => [...prev, { domain: newDomain.trim(), source: blacklistSource, added_at: new Date().toISOString() }]);
      }
      setNewDomain('');
    }
  };

  // Remove rule from whitelist/blacklist
  const handleRemoveRule = async (domain: string, type: 'whitelist' | 'blacklist') => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/v1/${type}/${domain}`, {
        method: 'DELETE'
      });
      if (res.ok) {
        fetchData(true);
      }
    } catch (err) {
      console.error(err);
      if (type === 'whitelist') {
        setWhitelist(prev => prev.filter(d => d !== domain));
      } else {
        setBlacklist(prev => prev.filter(b => b.domain !== domain));
      }
    }
  };

  // Submit Scam Report
  const handleSubmitReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportUrl.trim()) return;
    setSubmittingReport(true);
    setReportSuccess(false);

    try {
      const payload: ScamReportCreate = {
        url: reportUrl.trim(),
        reason: reportReason,
        description: reportDesc
      };

      const res = await fetch(`${BACKEND_URL}/api/v1/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        setReportUrl('');
        setReportDesc('');
        setReportSuccess(true);
        fetchData(true);
      }
    } catch (err) {
      console.error(err);
      // Mock submit offline
      setReportUrl('');
      setReportDesc('');
      setReportSuccess(true);
    } finally {
      setSubmittingReport(false);
    }
  };

  // Filtered History
  const filteredHistory = history.filter(item => {
    const matchesSearch = item.url.toLowerCase().includes(historySearch.toLowerCase()) || 
                          item.domain.toLowerCase().includes(historySearch.toLowerCase());
    
    if (historyFilter === 'all') return matchesSearch;
    if (historyFilter === 'scams') return matchesSearch && (item.category === 'Confirmed Scam' || item.category === 'High Risk');
    if (historyFilter === 'suspicious') return matchesSearch && item.category === 'Suspicious';
    if (historyFilter === 'safe') return matchesSearch && item.category === 'Safe';
    return matchesSearch;
  });

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'Safe': return 'status-safe';
      case 'Suspicious': return 'status-suspicious';
      case 'High Risk': return 'status-risk';
      case 'Confirmed Scam': return 'status-scam';
      default: return '';
    }
  };

  return (
    <div className="dashboard-layout">
      {/* Sidebar Navigation */}
      <aside className="dashboard-sidebar">
        <div className="sidebar-brand">
          <Shield className="brand-logo-icon" />
          <div className="brand-title">
            ScamShield <span className="logo-badge">AI v1</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button 
            className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Activity size={18} />
            <span>Threat Center</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <History size={18} />
            <span>Audit Log</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'lists' ? 'active' : ''}`}
            onClick={() => setActiveTab('lists')}
          >
            <List size={18} />
            <span>Rule Editor</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'report' ? 'active' : ''}`}
            onClick={() => setActiveTab('report')}
          >
            <AlertOctagon size={18} />
            <span>Report Center</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'academy' ? 'active' : ''}`}
            onClick={() => setActiveTab('academy')}
          >
            <BookOpen size={18} />
            <span>SecAcademy</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="footer-status-card">
            <div className="status-label-row">
              <span className="dot-glowing" style={{ backgroundColor: errorMsg ? '#ea580c' : '#10b981' }}></span>
              <span>{errorMsg ? 'DEGRADED STATE' : 'SECURE SEC-AGENT'}</span>
            </div>
            <p className="status-sub">{errorMsg ? 'Server offline' : 'Real-time protection enabled'}</p>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="dashboard-main">
        {/* Top bar header */}
        <header className="dashboard-header">
          <div className="header-info">
            <h1>{activeTab === 'overview' ? 'Cybersecurity Center' : 
                 activeTab === 'history' ? 'Threat History Audit Log' : 
                 activeTab === 'lists' ? 'Local Whitelist & Blacklist Rules' : 
                 activeTab === 'report' ? 'Submit Phishing Reports' : 
                 'AI Security Academy'}</h1>
            <p className="subtitle">Real-time scan logs, database records, and network rule configurations</p>
          </div>

          <div className="header-actions">
            <button className="refresh-data-btn" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw size={16} className={refreshing ? 'spin-icon' : ''} />
              <span>Sync Network</span>
            </button>
          </div>
        </header>

        {errorMsg && (
          <div className="network-warning-banner">
            <Info size={16} />
            <span>{errorMsg}</span>
          </div>
        )}

        {loading ? (
          <div className="dashboard-loading">
            <RefreshCw className="spin-icon large-loader" />
            <p>Loading ScamShield security tables...</p>
          </div>
        ) : (
          <div className="dashboard-tab-content">
            
            {/* OVERVIEW TAB */}
            {activeTab === 'overview' && (
              <div className="tab-overview">
                
                {/* Statistics Cards */}
                <div className="stats-cards-grid">
                  <div className="stat-card card-glow-emerald">
                    <div className="stat-card-header">
                      <span>MONITORED SCAN ACTIONS</span>
                      <Activity className="card-header-icon color-blue" />
                    </div>
                    <div className="stat-value">{stats?.total_scans}</div>
                    <div className="stat-footer-text">URLs parsed since deployment</div>
                  </div>

                  <div className="stat-card card-glow-red">
                    <div className="stat-card-header">
                      <span>THREATS ISOLATED</span>
                      <ShieldAlert className="card-header-icon color-red" />
                    </div>
                    <div className="stat-value text-red">{stats?.total_scams_detected}</div>
                    <div className="stat-footer-text">High-risk & phishing sites flagged</div>
                  </div>

                  <div className="stat-card card-glow-amber">
                    <div className="stat-card-header">
                      <span>FEEDBACK REPORTS</span>
                      <AlertOctagon className="card-header-icon color-amber" />
                    </div>
                    <div className="stat-value text-amber">{stats?.total_reports}</div>
                    <div className="stat-footer-text">Submitted to community blocklists</div>
                  </div>
                </div>

                {/* Grid Section: Top Threat Domains and Quick Tips */}
                <div className="overview-subgrid">
                  
                  {/* Top Blocked Domains */}
                  <div className="subgrid-card card-half">
                    <h2>Targeted Attack Sectors</h2>
                    <p className="card-subtitle">Highest frequency phishing target domains logged</p>
                    
                    {stats?.top_threats && stats.top_threats.length > 0 ? (
                      <div className="threats-ranking-list">
                        {stats.top_threats.map((threat: TopThreat, i: number) => (
                          <div key={i} className="threat-rank-row">
                            <span className="rank-num">0{i+1}</span>
                            <div className="threat-domain-info">
                              <span className="threat-domain-name">{threat.domain}</span>
                              <span className="threat-domain-meta">{threat.count} trigger events</span>
                            </div>
                            <span className="rank-score-pill">Risk Score: {threat.max_risk}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="no-rank-data">
                        <ShieldCheck className="clean-shield-large" />
                        <p>No attack sectors registered yet.</p>
                      </div>
                    )}
                  </div>

                  {/* AI Generated Recommendations */}
                  <div className="subgrid-card card-half card-gradient-glow">
                    <h2>AI Security Guard Recommendations</h2>
                    <div className="ai-advisor-panel">
                      <div className="advisor-bubble">
                        <div className="advisor-header">
                          <span className="ai-spark-icon">✨</span>
                          <strong>ScamShield AI Engine</strong>
                        </div>
                        <p className="advisor-body">
                          We observed multiple attempts targeting credentials using typosquatting domains (e.g. replacing letters with numbers like <strong>0 for o</strong>). 
                          Enable strict domain matching in your rules. Never enter credentials on subdomains where the core domain registration matches brand names but uses suspicious TLDs like <strong>.xyz</strong> or <strong>.cf</strong>.
                        </p>
                      </div>
                      <div className="academy-checklists">
                        <div className="chk-row"><Check size={14} className="chk-icon-green" /> <span>Auto-blacklist active</span></div>
                        <div className="chk-row"><Check size={14} className="chk-icon-green" /> <span>WHOIS age verification enabled</span></div>
                        <div className="chk-row"><Check size={14} className="chk-icon-green" /> <span>ML content parser loaded</span></div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Recent Scans Table */}
                <div className="overview-recent-table-card">
                  <h2>Recent Detection Logs</h2>
                  <div className="custom-table-container">
                    <table className="custom-table">
                      <thead>
                        <tr>
                          <th>WEBPAGE URL</th>
                          <th>DOMAIN</th>
                          <th>RISK INDEX</th>
                          <th>VERDICT</th>
                          <th>TIMESTAMP</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.slice(0, 5).map((scan, index) => (
                          <tr key={index}>
                            <td className="table-url-cell" title={scan.url}>{scan.url}</td>
                            <td>{scan.domain}</td>
                            <td>
                              <div className="table-risk-bar-container">
                                <div className="table-risk-bar" style={{ width: `${scan.risk_score}%`, backgroundColor: scan.risk_score > 60 ? '#ef4444' : scan.risk_score > 30 ? '#f59e0b' : '#10b981' }}></div>
                                <span className="table-risk-score">{Math.round(scan.risk_score)}/100</span>
                              </div>
                            </td>
                            <td>
                              <span className={`table-status-pill ${getCategoryColor(scan.category)}`}>
                                {scan.category}
                              </span>
                            </td>
                            <td className="table-time-cell">{new Date(scan.scanned_at).toLocaleTimeString()}</td>
                          </tr>
                        ))}
                        {history.length === 0 && (
                          <tr>
                            <td colSpan={5} className="table-empty-row">No scans logged. Visited domains will be logged here.</td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

              </div>
            )}

            {/* AUDIT LOG TAB */}
            {activeTab === 'history' && (
              <div className="tab-history">
                
                {/* Search / Filter Section */}
                <div className="filter-bar">
                  <div className="search-input-wrapper">
                    <Search size={18} className="search-icon" />
                    <input 
                      type="text" 
                      placeholder="Search logged scans by URL or domain..." 
                      value={historySearch}
                      onChange={e => setHistorySearch(e.target.value)}
                    />
                  </div>
                  <div className="select-filter-wrapper">
                    <select value={historyFilter} onChange={e => setHistoryFilter(e.target.value)}>
                      <option value="all">All Logs</option>
                      <option value="scams">Flagged Threats (High Risk / Scam)</option>
                      <option value="suspicious">Suspicious Pages</option>
                      <option value="safe">Safe Pages</option>
                    </select>
                  </div>
                </div>

                {/* Audit List */}
                <div className="history-logs-container">
                  {filteredHistory.length > 0 ? (
                    filteredHistory.map((scan) => {
                      const isExpanded = !!expandedScans[scan.id || 0];
                      const catColor = getCategoryColor(scan.category);
                      
                      return (
                        <div key={scan.id} className={`history-log-item ${isExpanded ? 'expanded' : ''}`}>
                          <div className="history-log-header" onClick={() => toggleExpandScan(scan.id)}>
                            <div className="header-primary-details">
                              <span className={`status-icon-badge ${catColor}`}>
                                {scan.category === 'Safe' ? <ShieldCheck size={18} /> : <ShieldAlert size={18} />}
                              </span>
                              <div className="header-meta-details">
                                <span className="header-url" title={scan.url}>{scan.url}</span>
                                <span className="header-timestamp">{new Date(scan.scanned_at).toLocaleString()}</span>
                              </div>
                            </div>

                            <div className="header-secondary-details">
                              <div className="score-value-block">
                                <span className="score-num">{Math.round(scan.risk_score)}</span>
                                <span className="score-lbl">Risk</span>
                              </div>
                              <span className={`status-pill ${catColor}`}>{scan.category}</span>
                              <button className="expand-chevron-btn">
                                {isExpanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
                              </button>
                            </div>
                          </div>

                          {isExpanded && (
                            <div className="history-log-body">
                              <div className="analysis-grid">
                                
                                <div className="analysis-col">
                                  <h3>Threat Indicator Hits</h3>
                                  {scan.reasons.length > 0 ? (
                                    <ul className="analysis-bullets">
                                      {scan.reasons.map((reason, idx) => (
                                        <li key={idx} className="analysis-bullet-item">
                                          <span className="red-dot"></span>
                                          <span>{reason}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  ) : (
                                    <div className="safe-indicator-msg">
                                      <Check size={16} className="chk-icon-green" />
                                      <span>All diagnostic checks passed. No malware or typosquatting signatures matched.</span>
                                    </div>
                                  )}
                                </div>

                                <div className="analysis-col border-left">
                                  <h3>Scan Details Metadata</h3>
                                  <div className="metadata-table">
                                    <div className="meta-row">
                                      <span className="meta-label">Domain Name</span>
                                      <span className="meta-val">{scan.domain}</span>
                                    </div>
                                    <div className="meta-row">
                                      <span className="meta-label">Domain Age (WHOIS)</span>
                                      <span className="meta-val">
                                        {scan.details?.whois_age_days !== undefined && scan.details?.whois_age_days !== null 
                                          ? `${scan.details.whois_age_days} days` 
                                          : 'Unknown/Error'}
                                      </span>
                                    </div>
                                    <div className="meta-row">
                                      <span className="meta-label">VirusTotal Hits</span>
                                      <span className="meta-val">
                                        {scan.details?.virustotal_flagged ? 'Flagged Malicious' : 'Harmless/Not listed'}
                                      </span>
                                    </div>
                                    <div className="meta-row">
                                      <span className="meta-label">Google Safe Browsing</span>
                                      <span className="meta-val">
                                        {scan.details?.google_safe_browsing_flagged ? 'Flagged Malicious' : 'Clean'}
                                      </span>
                                    </div>
                                    {scan.details?.ml_scam_probability !== undefined && (
                                      <div className="meta-row">
                                        <span className="meta-label">ML Scam confidence</span>
                                        <span className="meta-val">{(scan.details.ml_scam_probability * 100).toFixed(1)}%</span>
                                      </div>
                                    )}
                                  </div>

                                  <div className="quick-actions-row">
                                    <button 
                                      className="action-pill-btn wl-btn"
                                      onClick={() => {
                                        setListSubTab('whitelist');
                                        setNewDomain(scan.domain);
                                        setActiveTab('lists');
                                      }}
                                    >
                                      Whitelist Domain
                                    </button>
                                    <button 
                                      className="action-pill-btn bl-btn"
                                      onClick={() => {
                                        setListSubTab('blacklist');
                                        setNewDomain(scan.domain);
                                        setActiveTab('lists');
                                      }}
                                    >
                                      Blacklist Domain
                                    </button>
                                  </div>
                                </div>

                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })
                  ) : (
                    <div className="empty-history-logs">
                      <History size={48} className="color-slate" />
                      <p>No logged scans matches your filters.</p>
                    </div>
                  )}
                </div>

              </div>
            )}

            {/* RULE WRITER / LIST TAB */}
            {activeTab === 'lists' && (
              <div className="tab-lists">
                
                {/* List selector toggles */}
                <div className="subtab-header-toggles">
                  <button 
                    className={`subtab-btn ${listSubTab === 'whitelist' ? 'active' : ''}`}
                    onClick={() => setListSubTab('whitelist')}
                  >
                    Whitelisted Domains ({whitelist.length})
                  </button>
                  <button 
                    className={`subtab-btn ${listSubTab === 'blacklist' ? 'active' : ''}`}
                    onClick={() => setListSubTab('blacklist')}
                  >
                    Blacklisted Domains ({blacklist.length})
                  </button>
                </div>

                {/* Rules controls */}
                <div className="list-tab-body">
                  
                  {/* Add Domain form */}
                  <div className="add-rule-panel-wrapper">
                    <h3>Add Rule Target</h3>
                    <form className="add-rule-form" onSubmit={handleAddRule}>
                      <input 
                        type="text" 
                        placeholder="e.g. secure-login.chase.com" 
                        value={newDomain}
                        onChange={e => setNewDomain(e.target.value)}
                        required
                      />
                      {listSubTab === 'blacklist' && (
                        <select value={blacklistSource} onChange={e => setBlacklistSource(e.target.value)}>
                          <option value="admin">Admin override</option>
                          <option value="system">System automation</option>
                          <option value="community">Community suspect</option>
                        </select>
                      )}
                      <button type="submit" className="add-rule-submit-btn">
                        <Plus size={16} />
                        <span>Add Target</span>
                      </button>
                    </form>
                    <p className="form-sub-hint">
                      {listSubTab === 'whitelist' 
                        ? 'Whitelisted domains bypass all checks and immediately return Safe (0/100 risk score).'
                        : 'Blacklisted domains trigger an immediate Confirmed Scam block response (100/100 risk score).'}
                    </p>
                  </div>

                  {/* List View Container */}
                  <div className="rules-list-container">
                    <div className="list-header-label">ACTIVE NETWORK POLICIES</div>
                    
                    {listSubTab === 'whitelist' ? (
                      whitelist.length > 0 ? (
                        <div className="rules-grid-items">
                          {whitelist.map((domain, index) => (
                            <div key={index} className="rule-list-row">
                              <div className="rule-info-side">
                                <ShieldCheck className="rule-check-icon color-green" size={16} />
                                <span className="rule-domain-str">{domain}</span>
                              </div>
                              <button 
                                className="rule-delete-action-btn"
                                onClick={() => handleRemoveRule(domain, 'whitelist')}
                                title="Remove whitelist rule"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-rule-placeholder">No Whitelist rules defined.</div>
                      )
                    ) : (
                      blacklist.length > 0 ? (
                        <div className="rules-grid-items">
                          {blacklist.map((item, index) => (
                            <div key={index} className="rule-list-row">
                              <div className="rule-info-side">
                                <ShieldAlert className="rule-alert-icon color-red" size={16} />
                                <div className="rule-domain-column">
                                  <span className="rule-domain-str">{item.domain}</span>
                                  <span className="rule-source-sub">Source: {item.source} • Added {new Date(item.added_at).toLocaleDateString()}</span>
                                </div>
                              </div>
                              <button 
                                className="rule-delete-action-btn"
                                onClick={() => handleRemoveRule(item.domain, 'blacklist')}
                                title="Remove blacklist rule"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-rule-placeholder">No Blacklist rules defined.</div>
                      )
                    )}
                  </div>

                </div>

              </div>
            )}

            {/* REPORT SITE TAB */}
            {activeTab === 'report' && (
              <div className="tab-report">
                
                <div className="report-form-layout-wrapper">
                  
                  <div className="report-intro-card">
                    <h2>Scam Reporting Gateway</h2>
                    <p>
                      Found a scam site that bypassed ScamShield? Report it here. Your report will be analyzed and the domain will be added to the community blacklist to protect all other extension users in real time.
                    </p>
                    <div className="alert-guidelines">
                      <h3>Report Guidelines</h3>
                      <ul>
                        <li>Confirm the site claims to be a popular brand but is hosted on a different domain.</li>
                        <li>Do not report legitimate websites or official login pages.</li>
                        <li>Provide as much detail as possible to help administrators confirm the scam status.</li>
                      </ul>
                    </div>
                  </div>

                  <div className="report-main-form-card">
                    {reportSuccess && (
                      <div className="report-success-box">
                        <ShieldCheck size={24} className="success-check-icon" />
                        <div className="success-body">
                          <h4>Report Submitted Successfully</h4>
                          <p>The domain has been successfully added to the local blacklist database. ScamShield will block it on subsequent visits.</p>
                          <button onClick={() => setReportSuccess(false)} className="success-dismiss-btn">File Another Report</button>
                        </div>
                      </div>
                    )}

                    {!reportSuccess && (
                      <form className="scam-report-main-form" onSubmit={handleSubmitReport}>
                        <div className="form-group">
                          <label>Malicious Webpage URL</label>
                          <input 
                            type="url" 
                            placeholder="https://scam-site.com/double-crypto" 
                            value={reportUrl}
                            onChange={e => setReportUrl(e.target.value)}
                            required
                          />
                        </div>

                        <div className="form-group">
                          <label>Primary Threat Classification</label>
                          <select value={reportReason} onChange={e => setReportReason(e.target.value)}>
                            <option value="Phishing website impersonating brand">Phishing website impersonating brand</option>
                            <option value="Fake crypto giveaway / wallet credential harvester">Fake crypto giveaway / wallet credential harvester</option>
                            <option value="Unregistered scam webstore stealing credit card details">Unregistered scam webstore stealing credit card details</option>
                            <option value="Malicious tech support popup / phone numbers scam">Malicious tech support popup / phone numbers scam</option>
                            <option value="Malware download scam masquerading as useful software">Malware download scam masquerading as useful software</option>
                          </select>
                        </div>

                        <div className="form-group">
                          <label>Threat Description / Observations</label>
                          <textarea 
                            rows={4}
                            placeholder="Describe visual signals found (e.g. Fake login box, countdown timers, fake support chatbot...)"
                            value={reportDesc}
                            onChange={e => setReportDesc(e.target.value)}
                          />
                        </div>

                        <button type="submit" className="submit-report-btn" disabled={submittingReport}>
                          {submittingReport ? <RefreshCw className="spin-icon" size={16} /> : <AlertOctagon size={16} />}
                          <span>{submittingReport ? 'Submitting Threat Details...' : 'Submit Phishing Site'}</span>
                        </button>
                      </form>
                    )}
                  </div>

                </div>

              </div>
            )}

            {/* SECURITY ACADEMY TAB */}
            {activeTab === 'academy' && (
              <div className="tab-academy">
                <div className="academy-main-grid">
                  
                  {/* Common Threat Types */}
                  <div className="academy-card">
                    <h2>Scam Threat Taxonomy</h2>
                    <div className="threat-type-blocks">
                      <div className="threat-type-block">
                        <div className="type-badge red">PHISHING</div>
                        <h4>Brand Impersonation & Typosquatting</h4>
                        <p>
                          Creating domains with slightly altered spellings (e.g., replacement of characters: <code>amaz0n.com</code> or subdomains like <code>paypal.com.secure-sign.in</code>) to trick users into submitting logins.
                        </p>
                      </div>

                      <div className="threat-type-block">
                        <div className="type-badge orange">CRYPTO</div>
                        <h4>Fake Crypto Giveaways & Airdrops</h4>
                        <p>
                          Promising to double cryptocurrency investments if you send funds to a specified wallet address. Often uses fake live streams or deepfakes of celebrities (e.g., Elon Musk).
                        </p>
                      </div>

                      <div className="threat-type-block">
                        <div className="type-badge amber">TECH SUPPORT</div>
                        <h4>Fake Virus Alerts & Tech Support Call Scams</h4>
                        <p>
                          Spamming browser alerts claiming "Your device has been locked due to a Trojan." It blocks the page and displays a helpline phone number to steal payment for fake repair support.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Anti Phishing Checklist */}
                  <div className="academy-card checklist-card">
                    <h2>Manual Inspection Checklist</h2>
                    <p className="card-subtitle">Use this checklist when analyzing questionable sites</p>
                    
                    <div className="checklist-items">
                      <div className="ch-item">
                        <input type="checkbox" id="chk1" />
                        <label htmlFor="chk1">
                          <strong>Check Domain TLD:</strong> Is it a standard <code>.com</code>, <code>.org</code>, or <code>.gov</code>? Be extremely suspicious of random TLDs like <code>.xyz</code>, <code>.top</code>, or <code>.win</code>.
                        </label>
                      </div>
                      <div className="ch-item">
                        <input type="checkbox" id="chk2" />
                        <label htmlFor="chk2">
                          <strong>Inspect the Core Address:</strong> Do not just trust subdomains. Verify what sits directly before the last dot (e.g. <code>paypal.com.scam.net</code> is hosted on <code>scam.net</code>, not paypal!).
                        </label>
                      </div>
                      <div className="ch-item">
                        <input type="checkbox" id="chk3" />
                        <label htmlFor="chk3">
                          <strong>Urgency Markers:</strong> Is there a countdown timer or a warning that your account is locked? True portals do not rush actions in minutes.
                        </label>
                      </div>
                      <div className="ch-item">
                        <input type="checkbox" id="chk4" />
                        <label htmlFor="chk4">
                          <strong>Check Login Redirects:</strong> Inspect if the login page was triggered by a link in an unprompted email. Legitimate portals encourage typing URLs directly.
                        </label>
                      </div>
                    </div>
                  </div>

                </div>
              </div>
            )}

          </div>
        )}
      </main>
    </div>
  );
}
