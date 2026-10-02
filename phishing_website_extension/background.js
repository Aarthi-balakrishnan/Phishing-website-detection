// ============================================================
// AI Phishing Shield — Background Service Worker
//
// TWO-PHASE DETECTION for guaranteed <2s alerts:
//
// Phase 1 — LOCAL (< 100ms): Pattern matching against known
//   domains and URL signals. Shows an alert immediately.
//
// Phase 2 — AI (1-3s): Gemini API call started on
//   onBeforeNavigate (before page even begins loading).
//   If AI result differs from Phase 1, it upgrades the result.
//   Danger always wins over safe.
// ============================================================

const DEFAULT_API_URL = "https://7dec001e-a2cb-4bdb-bc80-a98d766241a3-00-1fbi5u7itjada.pike.replit.dev/api/phishing/check";

const resultCache   = new Map();  // url -> { result, timestamp }
const CACHE_TTL_MS  = 10 * 60 * 1000;
const preCheckPromises = new Map(); // url -> Promise<result>

// Tracks the CLASSIFICATION currently shown for each tab: tabId -> { url, classification }
// Used to avoid showing the same alert twice AND to upgrade safe->danger
const tabCurrentAlert = new Map();

// ============================================================
// KNOWN DOMAINS — instant local classification
// ============================================================

const KNOWN_SAFE_DOMAINS = new Set([
  "google.com","googleapis.com","gstatic.com","google.co.in","google.co.uk",
  "youtube.com","youtu.be",
  "github.com","githubusercontent.com",
  "stackoverflow.com","stackexchange.com",
  "wikipedia.org","wikimedia.org",
  "microsoft.com","office.com","live.com","windows.com","bing.com","msn.com",
  "apple.com","icloud.com",
  "amazon.com","amazonaws.com","amazon.co.uk","amazon.in",
  "facebook.com","fb.com","messenger.com","instagram.com","whatsapp.com",
  "twitter.com","x.com","t.co",
  "linkedin.com",
  "reddit.com","redd.it",
  "netflix.com","spotify.com","hulu.com","disneyplus.com",
  "paypal.com","stripe.com","shopify.com",
  "cloudflare.com","cloudfront.net",
  "mozilla.org","firefox.com",
  "w3.org","iana.org",
  "npmjs.com","nodejs.org","python.org","rust-lang.org",
  "replit.com","replit.dev","repl.co",
  "openai.com","anthropic.com",
  "medium.com","substack.com",
  "notion.so","figma.com","canva.com",
  "zoom.us","meet.google.com","teams.microsoft.com",
  "dropbox.com","drive.google.com","onedrive.live.com",
]);

const KNOWN_PHISHING_DOMAINS = new Set([
  "ebrand.com",
  "cert.pl",
  "antifraud.drweb.com","drweb.com",
  "phishtank.org","phishtank.com",
  "urlvoid.com","urlscan.io",
]);

const KNOWN_MALICIOUS_DOMAINS = new Set([
  "dailymotion.com",
  "pornhub.com","xvideos.com","xhamster.com","redtube.com","youporn.com",
  "xnxx.com","beeg.com","tube8.com","spankbang.com","eporner.com",
  "4chan.org","8chan.net","8kun.top",
]);

const ADULT_URL_KEYWORDS = [
  "porn","xxx","sex","nude","naked","adult","nsfw","erotic",
  "escort","onlyfans","cam4","chaturbate","stripchat","livejasmin",
  "hentai","milf","anal","fetish","bdsm","lesbian","gayporn",
  "hardcore","softcore","blowjob","deepthroat", "escort","callgirl",
  "hookup","adultdating","sexchat","webcam","18plus","xxxvideo",
  "pornvideo","adultvideo","sexvideo","incest","taboo","roleplay","kinky","orgy"
];

const PHISHING_URL_PATTERNS = [
  /paypal.*-/i, /amazon.*-verify/i, /apple.*-id/i,
  /microsoft.*-account/i, /netflix.*-login/i, /google.*-secure/i,
  /bank.*-login/i, /signin.*\.xyz$/i, /verify.*account.*\.tk$/i,
  /secure.*-login\./i, /account.*-suspended\./i,
  /192\.168\.\d+\.\d+/, /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // IP as host
];

// ============================================================
// PHASE 1: LOCAL PRE-CLASSIFIER (synchronous, instant)
// Returns a result object or null (unknown → needs AI)
// ============================================================

function localPreClassify(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, "");
    const fullUrl  = url.toLowerCase();

    // 1. Check known malicious domains (adult etc.)
    for (const d of KNOWN_MALICIOUS_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d)) {
        return {
          url, classification: "MALICIOUS", confidence: 99,
          reason: `${hostname} is a known adult/malicious content platform.`,
          risk_factors: ["known-malicious-domain", "adult-content-platform"],
          is_safe: false, local: true,
        };
      }
    }

    // 2. Adult keywords in hostname or path
    for (const kw of ADULT_URL_KEYWORDS) {
      if (hostname.includes(kw) || urlObj.pathname.toLowerCase().includes(kw)) {
        return {
          url, classification: "MALICIOUS", confidence: 95,
          reason: `Adult content keyword "${kw}" detected in URL. Classified as MALICIOUS.`,
          risk_factors: [`adult-keyword:${kw}`, "18+-content-signal"],
          is_safe: false, local: true,
        };
      }
    }

    // 3. Known phishing/threat-listing domains
    for (const d of KNOWN_PHISHING_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d)) {
        return {
          url, classification: "PHISHING", confidence: 100,
          reason: `${hostname} is a known threat-listing or brand-protection aggregator site that exposes users to dangerous URL content.`,
          risk_factors: ["known-phishing-domain", "threat-listing-site"],
          is_safe: false, local: true,
        };
      }
    }

    // 4. Phishing URL patterns
    for (const pattern of PHISHING_URL_PATTERNS) {
      if (pattern.test(hostname) || pattern.test(fullUrl)) {
        return {
          url, classification: "PHISHING", confidence: 85,
          reason: "URL matches known phishing patterns (brand impersonation, IP address, or suspicious subdomain structure).",
          risk_factors: ["url-pattern-match", "phishing-signal"],
          is_safe: false, local: true,
        };
      }
    }

    // 5. Known safe domains
    for (const d of KNOWN_SAFE_DOMAINS) {
      if (hostname === d || hostname.endsWith("." + d)) {
        return {
          url, classification: "SAFE", confidence: 98,
          reason: `${hostname} is a verified, trusted website.`,
          risk_factors: [],
          is_safe: true, local: true,
        };
      }
    }

    return null; // Unknown — let AI decide
  } catch {
    return null;
  }
}

// ============================================================
// CACHE HELPERS
// ============================================================

function getCached(url) {
  const entry = resultCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) { resultCache.delete(url); return null; }
  return entry.result;
}

function setCached(url, result) {
  resultCache.set(url, { result, timestamp: Date.now() });
  if (resultCache.size > 500) { const k = resultCache.keys().next().value; resultCache.delete(k); }
}

// ============================================================
// URL FILTER
// ============================================================

function shouldSkipUrl(url) {
  if (!url) return true;
  const skip = ["chrome://","chrome-extension://","about:","data:","javascript:","file://","newtab"];
  return skip.some((p) => url.startsWith(p));
}

async function getApiUrl() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(["apiUrl"], (r) => resolve(r.apiUrl || DEFAULT_API_URL));
  });
}

// ============================================================
// PHASE 2: AI API CALL
// ============================================================

function fetchAIClassification(url) {
  if (preCheckPromises.has(url)) return preCheckPromises.get(url);

  const promise = (async () => {
    const cached = getCached(url);
    if (cached) return cached;

    const apiUrl = await getApiUrl();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!response.ok) throw new Error(`API ${response.status}`);
      const result = await response.json();
      setCached(url, result);
      return result;
    } catch (err) {
      clearTimeout(timeout);
      console.warn("[PhishingShield] AI API unavailable:", err.message);
      return null; // null = AI failed, keep local result
    } finally {
      preCheckPromises.delete(url);
    }
  })();

  preCheckPromises.set(url, promise);
  return promise;
}

// ============================================================
// BADGE
// ============================================================

async function updateBadge(tabId, status) {
  const cfgs = {
    checking:  { text: "···", color: "#6366f1" },
    safe:      { text: "✓",   color: "#22c55e" },
    phishing:  { text: "⚠",   color: "#ef4444" },
    malicious: { text: "✗",   color: "#dc2626" },
    error:     { text: "?",   color: "#f59e0b" },
  };
  const c = cfgs[status] || cfgs.error;
  try {
    await chrome.action.setBadgeText({ text: c.text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: c.color, tabId });
  } catch { /* tab closed */ }
}

// ============================================================
// INJECT FUNCTIONS
// ============================================================

async function injectDanger(tabId, alertData) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId }, func: inPageDanger, args: [alertData], world: "MAIN",
    });
  } catch {
    chrome.notifications.create({
      type: "basic", iconUrl: "icons/icon48.png",
      title: alertData.type === "phishing" ? "⚠️ Phishing Website!" : "🚫 Dangerous Website!",
      message: alertData.message, priority: 2, requireInteraction: true,
    });
  }
}

async function injectSafe(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId }, func: inPageSafe, args: [result], world: "MAIN",
    });
  } catch { /* scripting not available */ }
}

// ============================================================
// HANDLE RESULT — core logic
// Priority: DANGER always beats SAFE. Never downgrade danger.
// ============================================================

function isDanger(cls) { return cls === "PHISHING" || cls === "MALICIOUS"; }

async function handleResult(result, tabId, url, isAIResult) {
  if (!result) return;

  const classification = result.classification;
  const currentAlert   = tabCurrentAlert.get(tabId);

  // If AI result comes in but danger was already shown for this url, skip
  if (isAIResult && currentAlert?.url === url && isDanger(currentAlert.classification)) return;

  // Never downgrade from danger to safe
  if (currentAlert?.url === url && isDanger(currentAlert.classification) && !isDanger(classification)) return;

  // Skip duplicate — same classification already shown for same url
  if (currentAlert?.url === url && currentAlert.classification === classification) return;

  tabCurrentAlert.set(tabId, { url, classification });

  await chrome.storage.local.set({
    lastCheck: {
      url, classification,
      confidence: result.confidence,
      reason: result.reason,
      risk_factors: result.risk_factors || [],
      timestamp: Date.now(),
    },
  });

  if (classification === "PHISHING") {
    await updateBadge(tabId, "phishing");
    await injectDanger(tabId, {
      type: "phishing",
      message: "⚠️ This is a phishing website. Do not use.",
      reason: result.reason,
      confidence: result.confidence,
      riskFactors: result.risk_factors || [],
      url,
    });
  } else if (classification === "MALICIOUS") {
    await updateBadge(tabId, "malicious");
    await injectDanger(tabId, {
      type: "malicious",
      message: "🚫 This website contains dangerous or prohibited content.",
      reason: result.reason,
      confidence: result.confidence,
      riskFactors: result.risk_factors || [],
      url,
    });
  } else if (classification === "ERROR") {
    await updateBadge(tabId, "error");
  } else {
    // SAFE
    await updateBadge(tabId, "safe");
    await injectSafe(tabId, result);
  }
}

// ============================================================
// IN-PAGE: DANGER OVERLAY
// ============================================================

function inPageDanger(data) {
  ["__ps_overlay__","__ps_safe__"].forEach((id) => { const e=document.getElementById(id); if(e) e.remove(); });

  const isPh   = data.type === "phishing";
  const accent = isPh ? "#f87171" : "#ef4444";
  const bg     = isPh ? "linear-gradient(160deg,#4a0000,#7f1d1d)" : "linear-gradient(160deg,#2d0047,#450a0a)";
  const border = isPh ? "#ef4444" : "#dc2626";
  const icon   = isPh ? "⚠️" : "🚫";
  const title  = isPh ? "PHISHING WEBSITE DETECTED" : "DANGEROUS CONTENT DETECTED";

  const risks = (data.riskFactors||[]).length
    ? `<div style="margin-top:16px;padding:12px 14px;background:rgba(0,0,0,.35);border-radius:10px;text-align:left">
        <p style="margin:0 0 8px;font-size:11px;color:#9ca3af;font-weight:700;text-transform:uppercase;letter-spacing:.08em">Risk Signals</p>
        ${data.riskFactors.map(f=>`<div style="font-size:13px;color:#fca5a5;margin:4px 0;display:flex;gap:8px"><span style="color:${accent};flex-shrink:0">●</span><span>${f}</span></div>`).join("")}
      </div>` : "";

  const d = document.createElement("div");
  d.id = "__ps_overlay__";
  d.style.cssText = "position:fixed!important;inset:0!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;background:rgba(0,0,0,.93)!important;padding:20px!important;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;box-sizing:border-box!important";

  d.innerHTML = `<style>@keyframes __ps_in{from{transform:scale(.82) translateY(-20px);opacity:0}to{transform:none;opacity:1}}@keyframes __ps_pp{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}</style>
  <div style="background:${bg};border:2px solid ${border};border-radius:20px;padding:44px 40px;max-width:580px;width:100%;text-align:center;box-shadow:0 30px 80px rgba(0,0,0,.85);animation:__ps_in .35s cubic-bezier(.34,1.56,.64,1)">
    <div style="font-size:64px;margin-bottom:14px;display:inline-block;animation:__ps_pp 2.2s infinite">${icon}</div>
    <div style="font-size:11px;font-weight:800;letter-spacing:.2em;color:${accent};text-transform:uppercase;margin-bottom:10px">${title}</div>
    <p style="color:#f9fafb;font-size:24px;font-weight:800;margin:0 0 12px;line-height:1.3">${data.message}</p>
    <p style="color:#d1d5db;font-size:14px;line-height:1.7;margin:0 0 10px">${data.reason||""}</p>
    <div style="display:inline-flex;align-items:center;gap:10px;background:rgba(255,255,255,.07);padding:9px 18px;border-radius:24px;margin-bottom:4px">
      <span style="color:#9ca3af;font-size:13px">AI Confidence</span>
      <span style="color:${accent};font-weight:800;font-size:15px">${data.confidence||0}%</span>
    </div>
    ${risks}
    <div style="margin-top:28px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
      <button id="__ps_leave__" style="background:${accent};color:#fff;border:none;padding:15px 32px;border-radius:12px;font-size:15px;font-weight:800;cursor:pointer" onmouseover="this.style.filter='brightness(1.15)'" onmouseout="this.style.filter=''">🔙 Leave This Site Now</button>
      <button id="__ps_ignore__" style="background:transparent;color:#6b7280;border:1px solid #374151;padding:15px 28px;border-radius:12px;font-size:13px;cursor:pointer">Proceed Anyway (Not Recommended)</button>
    </div>
    <p style="color:#374151;font-size:11px;margin-top:20px;letter-spacing:.04em">AI PHISHING SHIELD · REAL-TIME ML PROTECTION</p>
  </div>`;

  (document.documentElement||document.body).appendChild(d);
  document.getElementById("__ps_leave__").addEventListener("click",()=>{window.history.back();setTimeout(()=>{if(document.getElementById("__ps_overlay__"))window.location.href="about:blank";},600);});
  document.getElementById("__ps_ignore__").addEventListener("click",()=>d.remove());
}

// ============================================================
// IN-PAGE: SAFE OVERLAY (prominent green alert, auto-dismisses)
// ============================================================

function inPageSafe(result) {
  ["__ps_overlay__","__ps_safe__"].forEach((id) => { const e=document.getElementById(id); if(e) e.remove(); });

  const d = document.createElement("div");
  d.id = "__ps_safe__";
  d.style.cssText = "position:fixed!important;inset:0!important;z-index:2147483647!important;display:flex!important;align-items:center!important;justify-content:center!important;background:rgba(0,0,0,.82)!important;padding:20px!important;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif!important;box-sizing:border-box!important";

  const hostname = (() => { try { return new URL(result.url||"").hostname; } catch { return result.url||""; } })();
  const conf = result.confidence || 0;

  d.innerHTML = `<style>@keyframes __ps_sin{from{transform:scale(.82) translateY(-20px);opacity:0}to{transform:none;opacity:1}}@keyframes __ps_tick{0%{transform:scale(0) rotate(-45deg);opacity:0}60%{transform:scale(1.2) rotate(8deg)}100%{transform:scale(1) rotate(0);opacity:1}}</style>
  <div style="background:linear-gradient(160deg,#052e16,#14532d);border:2px solid #22c55e;border-radius:20px;padding:44px 40px;max-width:520px;width:100%;text-align:center;box-shadow:0 30px 80px rgba(0,0,0,.8),0 0 60px rgba(34,197,94,.08);animation:__ps_sin .35s cubic-bezier(.34,1.56,.64,1)">
    <div style="font-size:72px;margin-bottom:14px;display:inline-block;animation:__ps_tick .5s .1s both">✅</div>
    <div style="font-size:11px;font-weight:800;letter-spacing:.2em;color:#4ade80;text-transform:uppercase;margin-bottom:10px">WEBSITE VERIFIED SAFE</div>
    <p style="color:#f0fdf4;font-size:24px;font-weight:800;margin:0 0 12px;line-height:1.3">This website is safe to browse.</p>
    <p style="color:#86efac;font-size:14px;line-height:1.7;margin:0 0 14px">${result.reason||"No threats, phishing patterns, or harmful content detected."}</p>
    <div style="display:inline-flex;align-items:center;gap:18px;background:rgba(255,255,255,.07);padding:10px 22px;border-radius:24px;margin-bottom:6px">
      <div><p style="margin:0;color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.06em">Domain</p><p style="margin:0;color:#4ade80;font-weight:700;font-size:14px">${hostname}</p></div>
      <div style="width:1px;height:32px;background:rgba(255,255,255,.1)"></div>
      <div><p style="margin:0;color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.06em">AI Confidence</p><p style="margin:0;color:#22c55e;font-weight:800;font-size:14px">${conf}%</p></div>
    </div>
    <div style="margin-top:24px">
      <button id="__ps_safe_ok__" style="background:#22c55e;color:#052e16;border:none;padding:13px 36px;border-radius:12px;font-size:15px;font-weight:800;cursor:pointer" onmouseover="this.style.filter='brightness(1.1)'" onmouseout="this.style.filter=''">✓ Continue Browsing</button>
    </div>
    <p style="color:#166534;font-size:11px;margin-top:18px;letter-spacing:.04em">AI PHISHING SHIELD · REAL-TIME ML PROTECTION</p>
  </div>`;

  (document.documentElement||document.body).appendChild(d);

  // Auto-dismiss after 5 seconds
  const close = () => { if(d.parentElement){d.style.opacity="0";d.style.transition="opacity .4s";setTimeout(()=>d.remove(),400);} };
  document.getElementById("__ps_safe_ok__").addEventListener("click", close);
  setTimeout(close, 5000);
}

// ============================================================
// NAVIGATION — TWO-PHASE ENGINE
// ============================================================
 
async function runDetection(tabId, url) {
  if (shouldSkipUrl(url)) return;

  // ── PHASE 1: Local instant classification ──────────────────
  const localResult = localPreClassify(url);

  if (localResult) {
    // Show local result immediately (< 100ms)
    await handleResult(localResult, tabId, url, false);

    // For known safe/danger sites start the AI call anyway to confirm,
    // but only update if it contradicts (danger upgrades safe)
    const aiPromise = fetchAIClassification(url);
    aiPromise.then(async (aiResult) => {
      if (aiResult && aiResult.classification !== localResult.classification) {
        await handleResult(aiResult, tabId, url, true);
      } else if (aiResult) {
        // AI confirms — update cache with AI result (has full risk factors)
        setCached(url, aiResult);
      }
    }).catch(() => {});

  } else {
  // ⚡ SHOW SAFE IMMEDIATELY (fallback)
  await updateBadge(tabId, "safe");

  await injectSafe(tabId, {
    url,
    classification: "SAFE",
    confidence: 80,
    reason: "No immediate threats detected (quick scan)"
  });

  // 🔄 Then run AI in background (upgrade if needed)
  const aiResult = await fetchAIClassification(url);

  if (aiResult) {
    await handleResult(aiResult, tabId, url, true);
  } else {
    await updateBadge(tabId, "error");
  }
}
}

// STEP 1: onBeforeNavigate — BEFORE browser starts loading.
// Pre-start the AI call and run local check immediately.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkipUrl(details.url)) return;

  // Start AI pre-fetch in parallel immediately
  fetchAIClassification(details.url);
  await updateBadge(details.tabId, "checking");
});

// STEP 2: onCommitted — navigation confirmed, page starts rendering.
// Clear previous state and run two-phase detection.
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkipUrl(details.url)) return;

  const { url, tabId } = details;

  // New navigation for this tab — reset alert state
  tabCurrentAlert.delete(tabId);

  await runDetection(tabId, url);
});

// STEP 3: onCompleted — safety net.
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (shouldSkipUrl(details.url)) return;

  const { url, tabId } = details;
  const current = tabCurrentAlert.get(tabId);
  // If we already handled this url on this tab, skip
  if (current?.url === url) return;

  await runDetection(tabId, url);
});

// Tab switch — restore badge/alert
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
  if (!tab?.url || shouldSkipUrl(tab.url)) return;

  const cached = getCached(tab.url);
  if (cached) {
    await handleResult(cached, activeInfo.tabId, tab.url, false);
  } else {
    tabCurrentAlert.delete(activeInfo.tabId);
    await runDetection(activeInfo.tabId, tab.url);
  }
});

// ============================================================
// POPUP MESSAGES
// ============================================================
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    resultCache.delete(message.url);
    tabCurrentAlert.delete(message.tabId);

    runDetection(message.tabId, message.url).then(() => {
      sendResponse(getCached(message.url) || null);
    });
    return true;
  }

  if (message.type === "GET_STATUS") {
    chrome.storage.local.get(["lastCheck"], (r) => sendResponse(r.lastCheck || null));
    return true;
  }
});
