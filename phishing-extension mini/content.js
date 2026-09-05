(function () {
  if (window.__phishingShieldLoaded) return;
  window.__phishingShieldLoaded = true;

  // ===== ALERT UI =====
  window.__showPhishingShieldAlert = function (data) {
    const existing = document.getElementById("__phishing_shield_overlay__");
    if (existing) existing.remove();

    const isSafe = data.type === "safe";
    const isPhishing = data.type === "phishing";

    const bgColor = isSafe ? "#052e16" : isPhishing ? "#7f1d1d" : "#450a0a";
    const borderColor = isSafe ? "#16a34a" : isPhishing ? "#ef4444" : "#dc2626";
    const accentColor = isSafe ? "#22c55e" : isPhishing ? "#f87171" : "#ef4444";
    const icon = isSafe ? "✅" : isPhishing ? "⚠️" : "🚫";

    const title = isSafe
      ? "SAFE WEBSITE"
      : isPhishing
      ? "PHISHING WEBSITE DETECTED"
      : "DANGEROUS CONTENT DETECTED";

    const overlay = document.createElement("div");
    overlay.id = "__phishing_shield_overlay__";
    overlay.style.cssText = `
      position:fixed !important;
      top:0 !important;
      left:0 !important;
      width:100vw !important;
      height:100vh !important;
      background:rgba(0,0,0,0.92) !important;
      z-index:2147483647 !important;
      display:flex !important;
      align-items:center !important;
      justify-content:center !important;
      padding:20px !important;
      font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif !important;
    `;

    const riskHtml =
      data.riskFactors && data.riskFactors.length
        ? `<div style="margin-top:16px;padding:12px;background:rgba(255,255,255,0.05);border-radius:8px;">
            <p style="margin:0 0 8px;font-size:12px;color:#9ca3af;font-weight:600;">Risk Factors</p>
            ${data.riskFactors
              .map(
                (f) =>
                  `<div style="font-size:13px;color:${accentColor};margin:4px 0;">• ${f}</div>`
              )
              .join("")}
          </div>`
        : "";

    overlay.innerHTML = `
      <div style="
        background:${bgColor};
        border:2px solid ${borderColor};
        border-radius:16px;
        padding:40px;
        max-width:560px;
        width:100%;
        text-align:center;
        box-shadow:0 25px 60px rgba(0,0,0,0.8);
      ">
        <div style="font-size:60px;margin-bottom:10px;">${icon}</div>
        <h1 style="color:${accentColor};font-size:22px;font-weight:800;margin-bottom:10px;">${title}</h1>
        <p style="color:#fff;font-size:20px;font-weight:700;margin:10px 0;">${data.message}</p>
        <p style="color:#ccc;font-size:14px;margin-bottom:10px;">${data.reason || ""}</p>
        <div style="color:${accentColor};font-weight:bold;margin-bottom:10px;">
          Confidence: ${data.confidence || 0}%
        </div>
        ${riskHtml}

        <div style="margin-top:20px;">
          <button id="leave_btn" style="margin-right:10px;padding:10px 20px;background:${accentColor};color:#fff;border:none;border-radius:8px;cursor:pointer;">
            🔙 Leave
          </button>
          <button id="ignore_btn" style="padding:10px 20px;background:transparent;color:#ccc;border:1px solid #555;border-radius:8px;cursor:pointer;">
            Ignore
          </button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById("leave_btn").onclick = () => {
      window.history.back();
    };

    document.getElementById("ignore_btn").onclick = () => {
      overlay.remove();
    };
  };

  // ===== SAFE POPUP =====
  window.__showPhishingShieldSafe = function () {
    const notice = document.createElement("div");
    notice.innerText = "✅ Safe Website";
    notice.style.cssText = `
      position:fixed;
      bottom:20px;
      right:20px;
      background:#052e16;
      color:#22c55e;
      padding:10px 14px;
      border-radius:8px;
      z-index:999999;
      font-size:14px;
    `;
    document.body.appendChild(notice);

    setTimeout(() => notice.remove(), 3000);
  };
})();


// ===== DETECTION LOGIC =====

const MANUAL_BLOCKED_SITES = [
  "dynamicbusiness.com/locked/norton-reveals-100-most-dangerous-websites4168.html"
];

// 🔞 Adult keywords (kept minimal to avoid false positives)
const ADULT_URL_KEYWORDS = [
  "porn","xxx","sex","nude","naked","adult","nsfw","erotic",
  "escort","onlyfans","cam4","chaturbate","stripchat","livejasmin",
  "hentai","milf","anal","fetish","bdsm","lesbian","gayporn",
  "hardcore","softcore","blowjob","deepthroat", "escort","callgirl",
  "hookup","adultdating","sexchat","webcam","18plus","xxxvideo",
  "pornvideo","adultvideo","sexvideo","scandalous","incest","taboo","roleplay","kinky","orgy"
];

// ⚠️ Scandal keywords
const SCANDAL_KEYWORDS = [
  "scandal","leaked","viral-video","private-video","gossip"
];

// ✅ Trusted whitelist
const TRUSTED_SITES = [
  "guvi.in",
  "chat.openai.com",
  "claude.ai",
  "google.com",
  "youtube.com",
  "github.com",
  "infyspringboard.onwingspan.com",
  "replit.com",
  "khanacademy.org",
  "coursera.org",
  "edx.org",
  "swayam.gov.in",
  "nptel.ac.in",
  "unacademy.com",
  "physicswallah.com",
  "quizlet.com",
  "wolframalpha.com",
  "w3schools.com",
  "code.org",
  "scholar.google.com"
];

// 🔍 Safe keyword matcher (prevents partial match like "class" → "ass")
function containsKeyword(text, keywords) {
  return keywords.some(word =>
    new RegExp(`\\b${word}\\b`, "i").test(text)
  );
}

window.addEventListener("load", () => {
  const url = window.location.href.toLowerCase();

  // ✅ Skip trusted sites
  if (TRUSTED_SITES.some(site => url.includes(site))) {
    window.__showPhishingShieldSafe();
    return;
  }
  setTimeout(() => {

  // 🔴 Manual block
  if (MANUAL_BLOCKED_SITES.some(site => url.includes(site))) {
    window.__showPhishingShieldAlert({
      type: "phishing",
      message: "Blocked website",
      reason: "This page is manually flagged as dangerous",
      confidence: 100,
      riskFactors: ["Manually blocked URL"]
    });
    return;
  }

  // 🔍 Detection (URL only → no false positives)
  const isAdult = containsKeyword(url, ADULT_URL_KEYWORDS);
  const isScandal = containsKeyword(url, SCANDAL_KEYWORDS);

  if (isAdult) {
    window.__showPhishingShieldAlert({
      type: "danger",
      message: "18+ Content Detected",
      reason: "This page may contain adult content",
      confidence: 90,
      riskFactors: ["Adult-related keywords in URL"]
    });

  } else if (isScandal) {
    window.__showPhishingShieldAlert({
      type: "danger",
      message: "Sensitive Content Detected",
      reason: "This page may contain misleading or viral content",
      confidence: 70,
      riskFactors: ["Scandal-related keywords"]
    });

  } else {
    window.__showPhishingShieldSafe();
  }
 }, 2000); // ⏳ 2 sec delay
});