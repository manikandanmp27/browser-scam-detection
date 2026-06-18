import { UrlScanRequest, UrlScanResponse } from './types';

const BACKEND_URL = 'https://browser-scam-detection.onrender.com';
const SCAN_ENDPOINT = `${BACKEND_URL}/api/v1/scan`;

function updateBadge(tabId: number, category: string) {
  let badgeText = '';
  let badgeColor = '#10b981';

  switch (category) {
    case 'Safe':
      badgeText = 'SAFE';
      badgeColor = '#10b981'; // Green
      break;
    case 'Suspicious':
      badgeText = 'WARN';
      badgeColor = '#f59e0b'; // Amber
      break;
    case 'High Risk':
      badgeText = 'RISK';
      badgeColor = '#f97316'; // Orange
      break;
    case 'Confirmed Scam':
      badgeText = 'SCAM';
      badgeColor = '#ef4444'; // Red
      break;
    default:
      badgeText = '';
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

async function scanTab(tabId: number, url: string) {
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    return;
  }

  // Set transient loading badge
  chrome.action.setBadgeText({ tabId, text: '...' });
  chrome.action.setBadgeBackgroundColor({ tabId, color: '#64748b' });

  try {
    // Contact content script to extract DOM features
    const contentResponse = await new Promise<{ success: boolean; data?: UrlScanRequest; error?: string }>((resolve) => {
      chrome.tabs.sendMessage(tabId, { action: 'extract_metadata' }, (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(response || { success: false, error: 'Empty response' });
        }
      });
    });

    let scanPayload: UrlScanRequest = { url };
    if (contentResponse.success && contentResponse.data) {
      scanPayload = { ...contentResponse.data, url }; // Ensure URL is correct
    }

    // Call FastAPI backend
    const response = await fetch(SCAN_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(scanPayload)
    });

    if (!response.ok) {
      throw new Error(`Scam detection backend error: ${response.statusText}`);
    }

    const result: UrlScanResponse = await response.json();

    // Cache the result in extension storage (by tab ID and by clean URL prefix for fallback)
    await chrome.storage.local.set({ [`tab_${tabId}`]: result });
    
    try {
      const parsedUrl = new URL(url);
      const cleanUrl = parsedUrl.origin + parsedUrl.pathname;
      await chrome.storage.local.set({ [`url_${cleanUrl}`]: result });
    } catch (_) {}

    // Update extension badge
    updateBadge(tabId, result.category);
  } catch (error) {
    console.error('[ScamShield] Scan exception:', error);
    chrome.action.setBadgeText({ tabId, text: 'ERR' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#ef4444' });

    // Store error state details in local storage so Popup shows it
    let domainVal = 'unknown';
    try {
      domainVal = new URL(url).hostname;
    } catch (_) {}

    await chrome.storage.local.set({
      [`tab_${tabId}`]: {
        url,
        domain: domainVal,
        risk_score: 0.0,
        category: 'Safe',
        reasons: ['Scan failed. Ensure the ScamShield Backend is running and reachable.'],
        details: {},
        scanned_at: new Date().toISOString()
      }
    });
  }
}

// Scan when a tab's URL finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    scanTab(tabId, tab.url);
  }
});

// Remove local tab scan cache when closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});

// Allow manual triggers from the Popup UI
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'trigger_scan' && message.tabId && message.url) {
    scanTab(message.tabId, message.url).then(() => {
      sendResponse({ success: true });
    });
    return true; // keeps the message port open for async response
  }
  return false;
});
