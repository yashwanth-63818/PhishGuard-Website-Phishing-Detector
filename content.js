// PhishGuard Content Script - Robust Notification System
(function () {
  // Guard: Only run in the top-level window
  if (window.top !== window.self) return;

  let isDisplaying = false;
  let lastCheckedUrl = "";

  // core function to initiate scan and show result
  async function performProperScan() {
    const currentUrl = window.location.href;

    // Don't re-scan if we already scanned this exact URL on this page (SPA check)
    if (currentUrl === lastCheckedUrl) return;
    lastCheckedUrl = currentUrl;

    console.log("PhishGuard: Initiating security check for", currentUrl);

    chrome.runtime.sendMessage({
      action: "getContentStatus",
      url: currentUrl
    }, (response) => {
      // Security check: If the user navigated away while the message was in flight, ABORT.
      // This prevents the "notification for old site on new site" bug.
      if (window.location.href !== currentUrl) {
        console.log("PhishGuard: Tab URL changed, suppressing old notification.");
        return;
      }

      if (response && response.status) {
        showNotification(response.status, currentUrl);
      }
    });
  }

  function showNotification(status, url) {
    // If a notification is already up, remove it before showing new one
    const existing = document.getElementById("phishguard-notification");
    if (existing) {
      existing.remove();
      isDisplaying = false;
    }

    isDisplaying = true;
    const isSafe = status === "safe";
    const hostname = new URL(url).hostname;

    const container = document.createElement("div");
    container.id = "phishguard-notification";
    container.className = isSafe ? "pg-status-safe" : "pg-status-danger";

    container.innerHTML = `
      <div class="pg-close">&times;</div>
      <div class="pg-icon-circle">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="${isSafe ? '#00ff88' : '#ff4d4d'}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          ${isSafe
        ? '<path d="M20 6L9 17L4 12"></path>'
        : '<path d="M10.29 3.86L1.82 18a2 0 0 0 1.71 3h16.94a2 0 0 0 1.71-3L13.71 3.86a2 0 0 0-3.42 0zM12 9v4M12 17h.01"></path>'}
        </svg>
      </div>
      <div class="pg-content">
        <div class="pg-header">
          <span class="pg-title">${isSafe ? 'Site Safe' : 'Threat Detected'}</span>
        </div>
        <p class="pg-desc">${isSafe ? 'PhishGuard verified this site.' : 'Warning: High risk detected!'}</p>
        <div style="font-size: 11px; margin-top: 4px; opacity: 0.6; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px;">
          ${hostname}
        </div>
      </div>
    `;

    document.body.appendChild(container);

    const removeSelf = () => {
      if (container.parentElement) {
        container.classList.add("fade-out");
        setTimeout(() => {
          if (container.parentElement) container.remove();
          isDisplaying = false;
        }, 400);
      }
    };

    container.querySelector(".pg-close").onclick = removeSelf;
    // Auto-remove after 2.5 seconds (slightly longer for visibility)
    setTimeout(removeSelf, 2500);
  }

  // 1. Initial Scan on Load
  if (document.readyState === "complete" || document.readyState === "interactive") {
    performProperScan();
  } else {
    window.addEventListener("DOMContentLoaded", performProperScan);
  }

  // 2. SPA Support (LinkedIn, Gmail, etc.)
  // Detect URL changes that don't trigger a full page reload
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      performProperScan();
    }
  }).observe(document, { subtree: true, childList: true });

})();
