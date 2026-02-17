// Normalization helper
function normalizeUrl(url) {
  if (!url.startsWith('http')) {
    return 'https://' + url;
  }
  return url;
}

// ===== SCANNER LOGIC =====
function scanUrl() {
  const urlInput = document.getElementById("url-input");
  const resultContainer = document.getElementById("result");
  const rawUrl = urlInput.value.trim();

  if (!rawUrl) {
    showError("Please enter a URL to check.");
    return;
  }

  const url = normalizeUrl(rawUrl);

  // Show Loading State
  resultContainer.innerHTML = `
    <div class="loading-state">
      <div class="loader"></div>
      <p style="margin-top: 15px; font-size: 0.85rem; color: #a0a0c0;">Deep scanning URL...</p>
    </div>
  `;

  console.log("Requesting scan for:", url);

  // Send message to background.js
  chrome.runtime.sendMessage({ action: "scanUrl", url: url }, (response) => {
    if (chrome.runtime.lastError) {
      console.error("Runtime Error:", chrome.runtime.lastError);
      showError("Extension engine is starting up. Please wait 5 seconds and try again.");
      return;
    }

    const status = response ? response.status : "unknown";
    const details = response ? response.details : {};

    injectResult(url, status, details);
  });
}

function injectResult(url, status, details) {
  const resultContainer = document.getElementById("result");
  const isSafe = status === "safe";

  resultContainer.innerHTML = `
    <div class="scan-result-card">
      <div class="result-header">
        <span class="result-title">Security Report</span>
        <span class="status-pill ${isSafe ? 'safe' : 'danger'}">${status}</span>
      </div>
      <div class="result-details">
        <div class="detail-row">
          <span class="detail-label">Target Url:</span>
          <span class="detail-value" title="${url}">${new URL(url).hostname}</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Protection:</span>
          <span class="detail-value">VirusTotal Live</span>
        </div>
        <div class="detail-row">
          <span class="detail-label">Scanning ID:</span>
          <span class="detail-value">${details.threatId || 'P-404'}</span>
        </div>
      </div>
      <div style="margin-top: 15px; text-align: center; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 15px;">
        <p style="font-size: 0.8rem; color: ${isSafe ? '#00ff88' : '#ff4d4d'}; font-weight: 600; display: flex; align-items: center; justify-content: center; gap: 8px;">
          ${isSafe
      ? '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 6L9 17L4 12"></path></svg> No threats found. Site is safe.'
      : '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"></path></svg> High danger! Do not proceed.'}
        </p>
      </div>
    </div>
  `;
}

function showError(message) {
  const resultContainer = document.getElementById("result");
  resultContainer.innerHTML = `
    <div class="error-msg" style="color: #ff4d4d; font-size: 0.85rem; text-align: center; padding: 20px; background: rgba(255,77,77,0.05); border-radius: 12px;">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom: 10px; display: block; margin-left: auto; margin-right: auto;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0zM12 9v4M12 17h.01"></path></svg>
      ${message}
    </div>
  `;
}


// Initializers
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById("url-input");
  const btn = document.getElementById("scan-btn");
  const historyBtn = document.getElementById("history-btn");
  const historyPanel = document.getElementById("history-panel");
  const closeHistory = document.getElementById("close-history");
  const historyList = document.getElementById("history-list");

  if (input) {
    input.addEventListener("keypress", (e) => {
      if (e.key === "Enter") scanUrl();
    });
  }

  if (btn) {
    btn.addEventListener("click", scanUrl);
  }

  // History Toggle
  if (historyBtn && historyPanel) {
    historyBtn.addEventListener("click", () => {
      renderHistory();
      historyPanel.classList.add("active");
    });
  }

  if (closeHistory && historyPanel) {
    closeHistory.addEventListener("click", () => {
      historyPanel.classList.remove("active");
    });
  }

  function renderHistory() {
    chrome.storage.local.get(['scanHistory'], (data) => {
      const history = data.scanHistory || [];
      if (history.length === 0) {
        historyList.innerHTML = `
          <div class="empty-history">
            <p>No scan history yet</p>
          </div>
        `;
        return;
      }

      historyList.innerHTML = history.map(item => {
        const date = new Date(item.timestamp).toLocaleString();
        const isSafe = item.status === 'safe';
        const typeIcon = item.type === 'typed'
          ? '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>'
          : '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"></path></svg>';

        return `
          <div class="history-item">
            <div class="history-item-top">
              <span class="history-domain">${item.domain}</span>
              <span class="history-status ${item.status}">${item.status}</span>
            </div>
            <div class="history-details">
              <div class="history-ip">
                ${typeIcon}
                <span>${item.type === 'typed' ? 'Manual Check' : 'Navigation'}</span>
                <span style="margin: 0 4px; opacity: 0.3;">•</span>
                <span>${item.ip}</span>
              </div>
              <div class="history-time">${date}</div>
            </div>
          </div>
        `;
      }).join('');
    });
  }
});
