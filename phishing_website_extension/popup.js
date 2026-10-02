const DEFAULT_API_URL = "https://7dec001e-a2cb-4bdb-bc80-a98d766241a3-00-1fbi5u7itjada.pike.replit.dev/api/phishing/check";

const configs = {
  SAFE: {
    cls: "safe",
    icon: "✅",
    title: "Safe Website",
    message: "✅ This is a safe website.",
    barColor: "#22c55e",
  },
  PHISHING: {
    cls: "phishing",
    icon: "⚠️",
    title: "Phishing Detected!",
    message: "⚠️ This is a phishing website. Do not use.",
    barColor: "#ef4444",
  },
  MALICIOUS: {
    cls: "malicious",
    icon: "🚫",
    title: "Dangerous Content!",
    message: "🚫 This website contains dangerous or prohibited content. Do not use.",
    barColor: "#dc2626",
  },
  ERROR: {
    cls: "error",
    icon: "⚡",
    title: "Detection Error",
    message: "Could not connect to detection API. Check settings.",
    barColor: "#f59e0b",
  },
  CHECKING: {
    cls: "checking",
    icon: "⏳",
    title: "Analyzing...",
    message: "AI is evaluating this website...",
    barColor: "#6366f1",
  },
  UNKNOWN: {
    cls: "unknown",
    icon: "🔍",
    title: "Not Checked Yet",
    message: "Navigate to a website to start protection.",
    barColor: "#6b7280",
  },
};

function renderStatus(classification, data) {
  const cfg = configs[classification] || configs.UNKNOWN;
  const card = document.getElementById("status-card");
  card.className = `status-card ${cfg.cls}`;
  document.getElementById("status-icon").textContent = cfg.icon;
  document.getElementById("status-title").textContent = cfg.title;
  document.getElementById("status-message").textContent = data?.reason || cfg.message;

  const detailsSection = document.getElementById("details-section");
  const confidenceRow = document.getElementById("confidence-row");
  const riskSection = document.getElementById("risk-section");

  if (data?.confidence !== undefined) {
    detailsSection.style.display = "block";
    confidenceRow.style.display = "flex";
    document.getElementById("confidence-value").textContent = `${data.confidence}%`;
    const bar = document.getElementById("confidence-bar");
    bar.style.width = `${data.confidence}%`;
    bar.style.background = cfg.barColor;
  } else {
    detailsSection.style.display = "none";
    confidenceRow.style.display = "none";
  }

  const riskFactors = data?.risk_factors || [];
  if (riskFactors.length > 0 && classification !== "SAFE") {
    riskSection.style.display = "block";
    const riskList = document.getElementById("risk-list");
    riskList.innerHTML = riskFactors
      .map((f) => `<div class="risk-factor-item"><span>•</span><span>${f}</span></div>`)
      .join("");
  } else {
    riskSection.style.display = "none";
  }
}

async function loadCurrentTabStatus() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  const url = tab.url || "";
  const urlDisplay = document.getElementById("current-url");
  urlDisplay.textContent = url || "No URL";
  urlDisplay.title = url;

  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) {
    renderStatus("UNKNOWN", null);
    return;
  }

  renderStatus("CHECKING", null);

  chrome.runtime.sendMessage({ type: "GET_STATUS" }, (lastCheck) => {
    if (!lastCheck) {
      chrome.runtime.sendMessage(
        { type: "CHECK_URL", url: tab.url, tabId: tab.id },
        (result) => {
          if (result) {
            renderStatus(result.classification, result);
          } else {
            renderStatus("UNKNOWN", null);
          }
        }
      );
      return;
    }

    const isSameUrl =
      lastCheck.url === tab.url ||
      lastCheck.url?.replace(/\/$/, "") === tab.url?.replace(/\/$/, "");

    if (isSameUrl) {
      renderStatus(lastCheck.classification, lastCheck);
    } else {
      chrome.runtime.sendMessage(
        { type: "CHECK_URL", url: tab.url, tabId: tab.id },
        (result) => {
          if (result) {
            renderStatus(result.classification, result);
          } else {
            renderStatus("UNKNOWN", null);
          }
        }
      );
    }
  });
}

document.getElementById("recheck-btn").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  renderStatus("CHECKING", null);

  chrome.runtime.sendMessage(
    { type: "CHECK_URL", url: tab.url, tabId: tab.id },
    (result) => {
      if (result) {
        renderStatus(result.classification, result);
      }
    }
  );
});

const settingsToggle = document.getElementById("settings-toggle");
const settingsPanel = document.getElementById("settings-panel");
const apiUrlInput = document.getElementById("api-url-input");

settingsToggle.addEventListener("click", () => {
  settingsPanel.classList.toggle("visible");
});

chrome.storage.sync.get(["apiUrl"], (result) => {
  apiUrlInput.value = result.apiUrl || DEFAULT_API_URL;
});

document.getElementById("save-settings").addEventListener("click", () => {
  const url = apiUrlInput.value.trim();
  if (!url) return;
  chrome.storage.sync.set({ apiUrl: url }, () => {
    settingsPanel.classList.remove("visible");
    const btn = document.getElementById("save-settings");
    btn.textContent = "✓ Saved!";
    btn.style.background = "#22c55e";
    setTimeout(() => {
      btn.textContent = "Save Settings";
      btn.style.background = "";
    }, 2000);
  });
});

loadCurrentTabStatus();
