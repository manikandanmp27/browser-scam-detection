export interface UrlScanRequest {
  url: string;
  page_text?: string;
  page_title?: string;
  popups_detected?: boolean;
  countdowns_detected?: boolean;
  login_form_detected?: boolean;
}

export interface UrlScanResponse {
  id?: number;
  url: string;
  domain: string;
  risk_score: number;
  category: 'Safe' | 'Suspicious' | 'High Risk' | 'Confirmed Scam';
  reasons: string[];
  details: {
    whitelisted?: boolean;
    blacklisted?: boolean;
    typosquatting_detected?: boolean;
    impersonated_brand?: string | null;
    suspicious_url_keywords?: string[];
    suspicious_tld?: boolean;
    ml_scam_probability?: number;
    keyword_matches?: string[];
    whois_age_days?: number | null;
    virustotal_flagged?: boolean;
    google_safe_browsing_flagged?: boolean;
    login_form_on_untrusted_domain?: boolean;
  };
  scanned_at: string;
}

export interface ScamReportCreate {
  url: string;
  reason: string;
  description?: string;
}

export interface ScamReportResponse {
  id: number;
  url: string;
  domain: string;
  reason: string;
  description?: string;
  reported_at: string;
}

export interface TopThreat {
  domain: string;
  count: number;
  max_risk: number;
}

export interface DashboardStats {
  total_scans: number;
  total_scams_detected: number;
  total_reports: number;
  recent_scans: UrlScanResponse[];
  top_threats: TopThreat[];
}
