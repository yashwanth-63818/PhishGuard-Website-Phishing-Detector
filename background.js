// PhishGuard Security Core - Background Service
importScripts('env.js');

const VT_API_KEY = ENV.VT_API_KEY;
const PHISHTANK_API_KEY = ENV.PHISHTANK_API_KEY;

chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishGuard Security Core Active");
});

// ===== CORE SECURITY ENGINE =====

// Update VirusTotal ID generation for better compatibility
function getVtUrlId(url) {
  try {
    const b64 = btoa(unescape(encodeURIComponent(url)));
    return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  } catch (e) {
    return btoa(url).replace(/=/g, "");
  }
}

async function checkVirusTotal(url) {
  if (!VT_API_KEY || VT_API_KEY.length < 32 || VT_API_KEY.includes('PASTE_YOUR')) {
    console.warn("VirusTotal API Key missing or invalid.");
    return { malicious: 0 };
  }

  const urlId = getVtUrlId(url);
  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    if (response.status === 404) {
      return { malicious: 0 };
    }

    const data = await response.json();
    return data.data.attributes.last_analysis_stats || { malicious: 0 };
  } catch (e) {
    console.error("VT Fetch Error:", e);
    return { malicious: 0 };
  }
}

// Simple Heuristic Check
function checkHeuristics(url) {
  const suspiciousKeywords = ['login-', 'verify-', 'secure-', 'account-update', 'signin', 'bank', 'payment'];
  return suspiciousKeywords.some(keyword => url.toLowerCase().includes(keyword));
}

async function checkUrlSecurity(url, callback) {
  let resultStatus = "safe";
  let details = { threatId: null };
  let callbackCalled = false;

  const safeCallback = (status, info) => {
    if (!callbackCalled) {
      callbackCalled = true;
      if (callback) callback(status, info);
    }
  };

  try {
    const vtResult = await checkVirusTotal(url);
    if (vtResult && vtResult.malicious > 0) {
      resultStatus = "malicious";
      details.threatId = `VT-${vtResult.malicious}`;
    }

    if (resultStatus === "safe") {
      const isSuspicious = checkHeuristics(url);
      if (isSuspicious) {
        resultStatus = "phishing";
        details.threatId = "HEUR-01";
      }
    }

    safeCallback(resultStatus, details);
  } catch (error) {
    console.error("Security Check Error:", error);
    const fallback = checkHeuristics(url);
    safeCallback(fallback ? "phishing" : "safe", { threatId: "ERR" });
  }
}

// ===== LISTENERS =====

// Track last notification time per tab to prevent spamming
const tabCooldownMap = new Map();

// Use webNavigation for 100% reliability across all domains
// Cache for scanning results to speed up delivery
const scanCache = new Map();

// 1. Start scanning as EARLY as possible (onBeforeNavigate)
// 1. PRE-SCAN ENGINE: Starts scanning as soon as the browser intends to go to a URL
if (chrome.webNavigation) {
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
      const url = details.url;
      if (!scanCache.has(url)) {
        checkUrlSecurity(url, (status) => {
          scanCache.set(url, { status, timestamp: Date.now() });
          addToHistory(url, status, 'navigated');
        });
      } else {
        // Even if cached, record the navigation event
        addToHistory(url, scanCache.get(url).status, 'navigated');
      }
    }
  });
}

// ===== HISTORY RECORDING =====
async function addToHistory(url, status, type) {
  try {
    const domain = new URL(url).hostname;
    const timestamp = Date.now();

    const historyItem = {
      url: url,
      domain: domain,
      ip: "Resolved via DNS", // Standard browser behavior
      status: status,
      timestamp: timestamp,
      type: type // 'navigated' or 'typed'
    };

    const data = await chrome.storage.local.get(['scanHistory']);
    const history = data.scanHistory || [];

    // Keep last 50 items
    history.unshift(historyItem);
    const updatedHistory = history.slice(0, 50);

    await chrome.storage.local.set({ scanHistory: updatedHistory });
    console.log("History updated:", historyItem);
  } catch (e) {
    console.error("Error adding to history:", e);
  }
}

// 2. MESSAGE HUB: Responds to the page when it's actually ready
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Manual scan from popup
  if (request.action === "scanUrl") {
    checkUrlSecurity(request.url, (status, details) => {
      addToHistory(request.url, status, 'typed');
      sendResponse({ status, details });
    });
    return true;
  }

  // Auto-scan request from content script (THE PROPER WAY)
  if (request.action === "getContentStatus") {
    const targetUrl = request.url;

    const deliverStatus = () => {
      const cached = scanCache.get(targetUrl);
      if (cached) {
        addToHistory(targetUrl, cached.status, 'navigated');
        sendResponse({ status: cached.status });
      } else {
        // Not in cache? Run a priority scan
        checkUrlSecurity(targetUrl, (status) => {
          scanCache.set(targetUrl, { status, timestamp: Date.now() });
          addToHistory(targetUrl, status, 'navigated');
          sendResponse({ status });
        });
      }
    };

    deliverStatus();
    return true; // Keep async channel open
  }
});

// Periodic cache cleanup
setInterval(() => {
  const now = Date.now();
  for (const [url, data] of scanCache.entries()) {
    if (now - data.timestamp > 300000) { // 5 minutes
      scanCache.delete(url);
    }
  }
}, 60000);

