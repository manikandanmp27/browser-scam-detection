import { UrlScanRequest } from './types';

function extractMetadata(): UrlScanRequest {
  const url = window.location.href;
  const page_title = document.title;
  
  // Extract visible body text (cap at 10,000 chars to save bandwidth/processing)
  const page_text = document.body ? document.body.innerText.substring(0, 10000) : "";
  
  // Detect password inputs (login form indicators)
  const passwordInput = document.querySelector('input[type="password"]');
  const login_form_detected = !!passwordInput;
  
  // Detect countdown timers / artificial urgency
  let countdowns_detected = false;
  
  // Pattern matching standard formats (e.g. 12:34, 2h 4m, 59s, 3 minutes left)
  const timerRegex = /\b\d{1,2}:\d{2}(?::\d{2})?\b|\b\d{1,2}\s*(?:min|m|hr|h)\s*\d{1,2}\s*(?:sec|s)\b|\b\d+\s*seconds?\s*(?:left|remaining)\b/i;
  
  if (timerRegex.test(page_text)) {
    countdowns_detected = true;
  } else {
    // Check for elements with timer or countdown related classes/ids
    const timerSelectors = document.querySelectorAll(
      '[class*="timer" i], [class*="countdown" i], [id*="timer" i], [id*="countdown" i]'
    );
    for (const el of Array.from(timerSelectors)) {
      const text = (el as HTMLElement).innerText;
      if (/\d+/.test(text) && text.length < 50) { // must contain a number and be short
        countdowns_detected = true;
        break;
      }
    }
  }
  
  // Detect excessive/intrusive popups & modals
  let popups_detected = false;
  const popupSelectors = document.querySelectorAll(
    'div[class*="modal" i], div[class*="popup" i], div[class*="overlay" i], div[class*="dialog" i], ' +
    '[id*="modal" i], [id*="popup" i], [id*="overlay" i], [id*="dialog" i]'
  );
  
  let visiblePopupsCount = 0;
  for (const el of Array.from(popupSelectors)) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (
      (style.position === 'fixed' || style.position === 'absolute') &&
      style.display !== 'none' &&
      style.visibility !== 'hidden' &&
      rect.width > 120 &&
      rect.height > 50
    ) {
      visiblePopupsCount++;
    }
  }
  
  if (visiblePopupsCount >= 2) {
    popups_detected = true;
  }
  
  return {
    url,
    page_text,
    page_title,
    login_form_detected,
    countdowns_detected,
    popups_detected
  };
}

// Register Chrome message listener
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'extract_metadata') {
    try {
      const data = extractMetadata();
      sendResponse({ success: true, data });
    } catch (e) {
      sendResponse({ success: false, error: (e as Error).toString() });
    }
  }
  return true; // Keep channel open for async response
});
