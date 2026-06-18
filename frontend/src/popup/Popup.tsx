import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, ExternalLink, RefreshCw, AlertCircle, FileText, CheckCircle } from 'lucide-react';
import { UrlScanResponse } from '../types';

export default function Popup() {
  const [scanResult, setScanResult] = useState<UrlScanResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<{ id?: number; url?: string; title?: string }>({});

  const loadScanData = async () => {
    setLoading(true);
    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.storage) {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        const tab = tabs[0];
        if (tab && tab.id) {
          setActiveTab(tab);
          const tabKey = `tab_${tab.id}`;
          chrome.storage.local.get([tabKey], (res) => {
            if (res[tabKey]) {
              setScanResult(res[tabKey]);
            } else {
              setScanResult(null);
            }
            setLoading(false);
          });
        } else {
          setLoading(false);
        }
      });
    } else {
      // Mock data for browser previews
      setTimeout(() => {
        setActiveTab({ 
          id: 1, 
          url: 'https://paypal.com.verification-security-portal.xyz/login', 
          title: 'Verify PayPal Account' 
        });
        setScanResult({
          url: 'https://paypal.com.verification-security-portal.xyz/login',
          domain: 'verification-security-portal.xyz',
          risk_score: 88.0,
          category: 'Confirmed Scam',
          reasons: [
            'Brand name "paypal" detected in subdomain, but hosted on domain "verification-security-portal.xyz".',
            'Domain resembles legitimate brand "paypal" (typosquatting).',
            'Login/credentials form found on an untrusted or unfamiliar domain.',
            'Domain is very young (created 12 days ago).'
          ],
          details: {
            typosquatting_detected: true,
            impersonated_brand: 'paypal',
            suspicious_url_keywords: ['login'],
            suspicious_tld: true,
            ml_scam_probability: 0.89,
            keyword_matches: ['verify your credentials'],
            whois_age_days: 12,
            virustotal_flagged: false,
            google_safe_browsing_flagged: false,
            login_form_on_untrusted_domain: true
          },
          scanned_at: new Date().toISOString()
        });
        setLoading(false);
      }, 600);
    }
  };

  useEffect(() => {
    loadScanData();
  }, []);

  const handleManualScan = () => {
    if (activeTab.id && activeTab.url) {
      setLoading(true);
      if (typeof chrome !== 'undefined' && chrome.runtime) {
        chrome.runtime.sendMessage(
          { action: 'trigger_scan', tabId: activeTab.id, url: activeTab.url },
          () => {
            setTimeout(() => {
              loadScanData();
            }, 800);
          }
        );
      }
    }
  };

  const handleOpenDashboard = () => {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open('/options.html', '_blank');
    }
  };

  const getRiskColor = (category: string) => {
    switch (category) {
      case 'Safe': return '#10b981'; // Green
      case 'Suspicious': return '#f59e0b'; // Amber
      case 'High Risk': return '#f97316'; // Orange
      case 'Confirmed Scam': return '#ef4444'; // Red
      default: return '#64748b'; // Gray
    }
  };

  const riskColor = scanResult ? getRiskColor(scanResult.category) : '#64748b';
  const score = scanResult ? scanResult.risk_score : 0;
  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const isHttpOrHttps = activeTab.url?.startsWith('http://') || activeTab.url?.startsWith('https://');

  return (
    <div className="popup-container">
      <header className="popup-header">
        <div className="logo-section">
          <Shield className="shield-icon-glowing" />
          <span className="logo-text">ScamShield <span className="logo-accent">AI</span></span>
        </div>
        <button className="scan-refresh-btn" onClick={handleManualScan} disabled={loading || !isHttpOrHttps} title="Rescan Tab">
          <RefreshCw className={loading ? "spin-icon" : ""} />
        </button>
      </header>

      <main className="popup-content">
        {!isHttpOrHttps && !loading ? (
          <div className="unsupported-page">
            <AlertCircle className="unsupported-icon" />
            <p className="unsupported-title">Cannot Scan Page</p>
            <p className="unsupported-desc">ScamShield only scans HTTP and HTTPS websites. Browser settings, extension stores, and empty pages are skipped.</p>
          </div>
        ) : loading ? (
          <div className="loading-spinner-container">
            <RefreshCw className="spin-icon large-loader" />
            <p>Analyzing website features...</p>
          </div>
        ) : scanResult ? (
          <div className="scan-results-view">
            {/* Risk Gauge Circle */}
            <div className="gauge-container">
              <svg className="gauge-svg" viewBox="0 0 100 100">
                <circle className="gauge-bg-track" cx="50" cy="50" r={radius} />
                <circle 
                  className="gauge-fill" 
                  cx="50" 
                  cy="50" 
                  r={radius} 
                  stroke={riskColor}
                  strokeDasharray={circumference}
                  strokeDashoffset={strokeDashoffset}
                  style={{
                    filter: `drop-shadow(0 0 6px ${riskColor}80)`
                  }}
                />
              </svg>
              <div className="gauge-score-value">
                <span className="score-number">{Math.round(score)}</span>
                <span className="score-total">/100</span>
              </div>
            </div>

            {/* Category Banner */}
            <div className="category-status-pill" style={{ backgroundColor: `${riskColor}15`, border: `1px solid ${riskColor}40`, color: riskColor }}>
              {scanResult.category === 'Safe' && <CheckCircle size={16} style={{ marginRight: '6px' }} />}
              {scanResult.category !== 'Safe' && <AlertTriangle size={16} style={{ marginRight: '6px' }} />}
              {scanResult.category.toUpperCase()}
            </div>

            {/* Tab Domain Info */}
            <div className="domain-label">
              <span>Domain: <strong>{scanResult.domain}</strong></span>
            </div>

            {/* Reasons Scroll List */}
            <div className="threat-reasons-panel">
              <div className="reasons-header-label">Threat Diagnostics</div>
              {scanResult.reasons.length > 0 ? (
                <ul className="reasons-list">
                  {scanResult.reasons.map((reason, index) => (
                    <li key={index} className="reason-item">
                      <span className="reason-bullet" style={{ backgroundColor: riskColor }}></span>
                      <span className="reason-text">{reason}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="clean-verdict">
                  <CheckCircle className="clean-verdict-icon" />
                  <span>No malicious indicators found on page.</span>
                </div>
              )}
            </div>

            {/* Details Quick Grid */}
            <div className="details-quick-grid">
              {scanResult.details.whois_age_days !== undefined && scanResult.details.whois_age_days !== null && (
                <div className="grid-cell">
                  <span className="cell-label">Domain Age</span>
                  <span className="cell-value">{scanResult.details.whois_age_days} days</span>
                </div>
              )}
              {scanResult.details.ml_scam_probability !== undefined && (
                <div className="grid-cell">
                  <span className="cell-label">ML Scam Confidence</span>
                  <span className="cell-value">{(scanResult.details.ml_scam_probability * 100).toFixed(0)}%</span>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="no-scan-data">
            <AlertCircle size={36} className="no-scan-icon" />
            <p>No data loaded for this site.</p>
            <button className="scan-action-btn" onClick={handleManualScan}>Scan Website</button>
          </div>
        )}
      </main>

      <footer className="popup-footer">
        <button className="footer-nav-btn" onClick={handleOpenDashboard}>
          <FileText size={14} style={{ marginRight: '6px' }} />
          Threat Control Dashboard
          <ExternalLink size={12} style={{ marginLeft: '6px' }} />
        </button>
      </footer>
    </div>
  );
}
