const HISTORY_KEY = "trustlayer-history-v1";

const FEATURE_KEYWORDS = {
  urgency_terms: ["urgent", "immediately", "now", "act fast", "asap", "right away", "within today", "click"],
  link_presence: ["http", "https", "www", ".com", ".net", ".org", "bit.ly", "tinyurl", "goo.gl", "click here"],
  financial_terms: [
    "bank",
    "account",
    "payment",
    "transaction",
    "upi",
    "wallet",
    "credit card",
    "debit card",
    "investment",
    "refund",
    "transfer",
  ],
  threat_language: [
    "blocked",
    "suspended",
    "penalty",
    "warning",
    "legal action",
    "security alert",
    "unauthorized",
    "verify now",
  ],
  sensitive_requests: ["otp", "password", "pin", "cvv", "passcode", "verification code", "login details"],
  emotional_pressure: ["limited time", "last chance", "don't miss", "exclusive offer", "final notice", "act now", "expires today"],
};

const WEIGHTS = {
  urgency_terms: 20,
  link_presence: 15,
  financial_terms: 25,
  threat_language: 20,
  sensitive_requests: 30,
  emotional_pressure: 15,
};

const REASON_MAP = {
  urgency_terms: "Urgency language detected",
  link_presence: "Suspicious link pattern found",
  financial_terms: "Financially sensitive language identified",
  threat_language: "Threat or penalty language detected",
  sensitive_requests: "Sensitive information requested",
  emotional_pressure: "Emotional pressure tactics detected",
};

const CAMPAIGN_PROFILES = {
  "Account Security & Verification": {
    hook: "Fear",
    keywords: [
      "login",
      "new device",
      "account",
      "suspended",
      "sign in",
      "code",
      "verify",
      "password",
      "security check",
      "unrecognized",
      "google drive",
      "storage",
      "re authenticate",
      "password reset",
      "session",
      "lockout",
    ],
  },
  "Financial & Banking": {
    hook: "Money",
    keywords: [
      "wire transfer",
      "invoice",
      "tax refund",
      "zelle",
      "credit card",
      "salary",
      "pay scale",
      "subscription",
      "renew",
      "fraud",
      "apple.com",
      "unclaimed funds",
      "crypto",
      "wallet",
      "high risk transactions",
      "bank",
    ],
  },
  "Deliveries & Logistics": {
    hook: "Convenience",
    keywords: [
      "deliver",
      "parcel",
      "reschedule",
      "package",
      "warehouse",
      "address",
      "customs",
      "shipment",
      "track",
      "gift card",
      "amazon",
      "order",
    ],
  },
  "Workplace & Productivity": {
    hook: "Authority",
    keywords: [
      "meeting invite",
      "emergency update",
      "join",
      "google meet",
      "fake login",
      "file shared",
      "shared",
      "drive",
      "layoff",
      "open to view",
      "it ticket",
      "patch",
      "laptop",
      "quick favor",
      "conference",
      "mandatory",
      "harassment training",
      "eod",
      "hr action",
      "holiday party",
      "hr system",
      "register",
      "confidential",
      "strategy roadmap",
    ],
  },
  "Social Media & Communication": {
    hook: "Curiosity",
    keywords: [
      "friend request",
      "view profile",
      "mentioned",
      "video",
      "copyrighted",
      "deleted",
      "free products",
      "voicemail",
      "unknown number",
      "whatsapp",
      "new device",
      "enter the code",
    ],
  },
  "Emerging Tech & AI Scams": {
    hook: "2026",
    keywords: [
      "scan to pay",
      "qr code",
      "voice note",
      "ai cloned",
      "researchers",
      "data link",
      "grant",
      "gmail",
      "smartcalendar ai",
      "optimize your schedule",
      "pro version",
      "limited keys",
      "oauth",
    ],
  },
  "Miscellaneous Lures": {
    hook: "Mixed",
    keywords: [
      "won",
      "claim",
      "warrant",
      "arrest",
      "unpaid fines",
      "donate",
      "disaster",
      "loan forgiveness",
      "pre approved",
      "lab results",
      "patient portal",
      "free",
      "pay shipping",
    ],
  },
};

const CAMPAIGN_CATEGORY_MAP = {
  "Account Security & Verification": "Phishing",
  "Financial & Banking": "Financial Fraud",
  "Deliveries & Logistics": "Phishing",
  "Workplace & Productivity": "Social Engineering",
  "Social Media & Communication": "Social Engineering",
  "Emerging Tech & AI Scams": "Phishing",
  "Miscellaneous Lures": "Social Engineering",
};

const PLAYBOOKS = {
  Phishing: [
    "Do not click links or download attachments from this message.",
    "Verify the sender or service through an official channel before taking action.",
    "Report the message to your security or IT team and block the source if possible.",
  ],
  "Financial Fraud": [
    "Do not transfer funds, share banking details, or approve payment requests.",
    "Contact the bank or finance owner using a trusted phone number or official app.",
    "Escalate the message for fraud review and preserve the original content as evidence.",
  ],
  "Social Engineering": [
    "Pause the interaction and validate the request with a known contact path.",
    "Do not share internal files, credentials, or MFA codes in response to this message.",
    "Notify the appropriate security, HR, or operations contact for review.",
  ],
  Safe: [
    "No immediate threat action is recommended.",
    "Continue normal verification habits if the message later changes or requests credentials.",
  ],
  Unknown: [
    "Treat the message cautiously until it is independently verified.",
    "Avoid sharing sensitive data or installing anything referenced in the content.",
    "Escalate for manual review if the request affects money, access, or identity.",
  ],
};

const LEETSPEAK_MAP = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
};

const state = {
  totalScans: 1284,
  highRiskScans: 231,
  batchReport: null,
  history: [],
};

const riskStyles = {
  Low: { badge: "risk-pill--low", reason: "reason-item--low", bar: "score-bar--low" },
  Medium: { badge: "risk-pill--medium", reason: "reason-item--medium", bar: "score-bar--medium" },
  High: { badge: "risk-pill--high", reason: "reason-item--high", bar: "score-bar--high" },
  Unknown: { badge: "risk-pill--unknown", reason: "reason-item--unknown", bar: "score-bar--unknown" },
};

const elements = {
  input: document.getElementById("threatInput"),
  batchInput: document.getElementById("batchInput"),
  analyzeButton: document.getElementById("analyzeButton"),
  batchButton: document.getElementById("batchButton"),
  sampleButton: document.getElementById("sampleButton"),
  exportButton: document.getElementById("exportButton"),
  trustScore: document.getElementById("trustScore"),
  riskBadge: document.getElementById("riskBadge"),
  category: document.getElementById("category"),
  campaign: document.getElementById("campaign"),
  hook: document.getElementById("hook"),
  confidence: document.getElementById("confidence"),
  reasonsList: document.getElementById("reasonsList"),
  actionsList: document.getElementById("actionsList"),
  scoreBar: document.getElementById("scoreBar"),
  totalScans: document.getElementById("totalScans"),
  highRiskPercent: document.getElementById("highRiskPercent"),
  batchTotal: document.getElementById("batchTotal"),
  batchHigh: document.getElementById("batchHigh"),
  batchResults: document.getElementById("batchResults"),
  historyList: document.getElementById("historyList"),
};

function sanitizeText(value, maxLength = 240) {
  return String(value ?? "").replace(/[<>]/g, "").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function sanitizeRiskLevel(value) {
  return ["Low", "Medium", "High", "Unknown"].includes(value) ? value : "Unknown";
}

function sanitizeNumeric(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.max(0, Math.min(100, Math.round(numeric)));
}

function normalizeForAnalysis(text) {
  const replaced = Array.from(String(text ?? "").toLowerCase()).map((char) => LEETSPEAK_MAP[char] || char).join("");
  return replaced
    .replace(/[\u200b-\u200f\u202a-\u202e]/g, "")
    .replace(/[^a-z0-9\s:/._'-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function collectFeatureMatches(normalizedText, keywords) {
  const matches = [];
  for (const keyword of keywords) {
    if (normalizedText.includes(keyword)) {
      matches.push(keyword);
    }
  }
  return matches;
}

function extractFeatures(text) {
  const normalizedText = normalizeForAnalysis(text);
  const extracted = {};

  Object.entries(FEATURE_KEYWORDS).forEach(([featureName, keywords]) => {
    const matches = collectFeatureMatches(normalizedText, keywords);
    extracted[featureName] = {
      present: matches.length > 0,
      count: matches.length,
      matches,
    };
  });

  const alphaChars = (normalizedText.match(/[a-z]/g) || []).length;
  const totalChars = normalizedText.length;
  const wordCount = normalizedText ? normalizedText.split(" ").length : 0;
  const signalCount = Object.keys(FEATURE_KEYWORDS).reduce(
    (count, key) => count + (extracted[key].present ? 1 : 0),
    0
  );
  const nonAsciiChars = Array.from(String(text ?? "")).filter((char) => char.charCodeAt(0) > 127).length;

  extracted.metadata = {
    length: totalChars,
    word_count: wordCount,
    normalized_text: normalizedText,
    non_ascii_ratio: Number((nonAsciiChars / Math.max(1, String(text ?? "").length)).toFixed(2)),
    signal_count: signalCount,
    insufficient_data: totalChars < 12 || wordCount < 3,
    gibberish_like: totalChars > 0 && alphaChars < Math.max(3, Math.floor(totalChars / 4)) && signalCount === 0,
    non_english_heavy: String(text ?? "").length > 0 && nonAsciiChars / Math.max(1, String(text ?? "").length) > 0.35,
  };

  return extracted;
}

function clamp(value, lower = 0, upper = 100) {
  return Math.max(lower, Math.min(upper, Math.round(value)));
}

function computeScore(features) {
  const rawRiskScore = Object.entries(WEIGHTS).reduce(
    (sum, [featureName, weight]) => sum + (features[featureName]?.present ? weight : 0),
    0
  );
  const riskScore = clamp(rawRiskScore);
  return { riskScore, trustScore: clamp(100 - riskScore) };
}

function detectCampaign(features) {
  const text = features.metadata.normalized_text;
  let bestName = null;
  let bestScore = 0;

  Object.entries(CAMPAIGN_PROFILES).forEach(([name, profile]) => {
    const score = profile.keywords.filter((keyword) => text.includes(keyword)).length;
    if (score > bestScore) {
      bestName = name;
      bestScore = score;
    }
  });

  if (!bestName || bestScore < 2) {
    return { name: null, hook: null, severity: "None", score: 0 };
  }

  return {
    name: bestName,
    hook: CAMPAIGN_PROFILES[bestName].hook,
    severity: "High",
    score: bestScore,
  };
}

function classify(features, riskScore, campaign) {
  if (features.metadata.insufficient_data && riskScore === 0) {
    return "Unknown";
  }
  if (features.financial_terms.present && features.sensitive_requests.present) {
    return "Financial Fraud";
  }
  if (features.link_presence.present && features.urgency_terms.present) {
    return "Phishing";
  }
  if (features.emotional_pressure.present && features.threat_language.present) {
    return "Social Engineering";
  }
  if (campaign.name) {
    return CAMPAIGN_CATEGORY_MAP[campaign.name] || "Phishing";
  }
  if (riskScore === 0) {
    return "Safe";
  }
  return "Unknown";
}

function determineRiskLevel(riskScore) {
  if (riskScore >= 70) return "High";
  if (riskScore >= 30) return "Medium";
  return "Low";
}

function calculateConfidence(features, riskScore) {
  const metadata = features.metadata;
  let confidence = Math.max(10, Math.min(100, riskScore));

  if (metadata.signal_count <= 1) confidence -= 15;
  if (metadata.insufficient_data) confidence -= 25;
  if (metadata.gibberish_like) confidence -= 20;
  if (metadata.non_english_heavy && metadata.signal_count === 0) confidence -= 10;
  if (riskScore >= 70 && metadata.signal_count >= 3) confidence += 10;

  return clamp(confidence, 5, 100);
}

function generateReasons(features, campaign) {
  if (features.metadata.insufficient_data && !features.metadata.signal_count) {
    return ["Insufficient data for high-confidence analysis"];
  }
  if (features.metadata.gibberish_like) {
    return ["Input appears noisy or gibberish-heavy"];
  }

  const reasons = Object.entries(REASON_MAP)
    .filter(([featureName]) => features[featureName]?.present)
    .map(([, reason]) => reason);

  if (campaign.name) {
    reasons.push(`Matched high-risk lure family: ${campaign.name} (${campaign.hook} hook)`);
  }

  return reasons.length ? reasons : ["No strong threat indicators detected"];
}

function recommendActions(category, risk, campaignName) {
  const actions = [...(PLAYBOOKS[category] || PLAYBOOKS.Unknown)];
  if (risk === "High" && campaignName) {
    actions.push(`Flag this as a potential ${campaignName} campaign in your incident notes.`);
  }
  return actions.slice(0, 4);
}

function analyzeTextLocally(text) {
  const features = extractFeatures(text);
  let { riskScore, trustScore } = computeScore(features);
  const campaign = detectCampaign(features);
  if (campaign.severity === "High") {
    riskScore = Math.max(riskScore, 75);
    trustScore = clamp(100 - riskScore);
  }
  const category = classify(features, riskScore, campaign);
  const risk = determineRiskLevel(riskScore);
  const confidence = calculateConfidence(features, riskScore);
  const reasons = generateReasons(features, campaign);
  const actions = recommendActions(category, risk, campaign.name);

  return {
    score: trustScore,
    risk,
    category,
    campaign: campaign.name,
    hook: campaign.hook,
    confidence,
    reasons,
    actions,
  };
}

function renderMetrics() {
  const ratio = Math.round((state.highRiskScans / state.totalScans) * 100);
  elements.totalScans.textContent = state.totalScans.toLocaleString();
  elements.highRiskPercent.textContent = `${ratio}%`;
}

function resetRiskBadgeClasses(level) {
  const allBadgeClasses = Object.values(riskStyles).flatMap((style) => style.badge.split(" "));
  elements.riskBadge.classList.remove(...allBadgeClasses);
  elements.riskBadge.classList.add(...riskStyles[level].badge.split(" "));
}

function resetScoreBar(level, score) {
  elements.scoreBar.className = `score-bar ${riskStyles[level].bar}`;
  elements.scoreBar.style.width = `${Math.max(6, score)}%`;
}

function renderList(target, items, level) {
  target.innerHTML = "";
  items.forEach((itemText) => {
    const item = document.createElement("li");
    item.className = `reason-item ${riskStyles[level].reason}`;
    item.textContent = sanitizeText(itemText, 320);
    target.appendChild(item);
  });
}

function persistHistory() {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(state.history.slice(0, 8)));
}

function loadHistory() {
  try {
    state.history = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    state.history = [];
  }
}

function renderHistory() {
  if (!state.history.length) {
    elements.historyList.innerHTML =
      '<div class="table-empty">Your latest scans will appear here for quick storytelling during demos.</div>';
    return;
  }

  elements.historyList.innerHTML = "";
  state.history.forEach((entry) => {
    const card = document.createElement("article");
    card.className = "history-card";

    const meta = document.createElement("div");
    meta.className = "history-meta";
    meta.innerHTML = `<span>${sanitizeText(entry.risk, 16)} Risk</span><span>${sanitizeText(entry.category, 40)}</span>`;

    const text = document.createElement("div");
    text.className = "history-text";
    text.textContent = sanitizeText(entry.text, 180);

    card.append(meta, text);
    elements.historyList.appendChild(card);
  });
}

function pushHistory(entry) {
  state.history.unshift({
    text: sanitizeText(entry.text, 180),
    risk: sanitizeText(entry.risk, 16),
    category: sanitizeText(entry.category, 40),
  });
  state.history = state.history.slice(0, 8);
  persistHistory();
  renderHistory();
}

function updateDashboard(result, sourceText = "") {
  const level = sanitizeRiskLevel(result.risk);
  const score = sanitizeNumeric(result.score, 50);
  const confidence = sanitizeNumeric(result.confidence, 30);
  const category = sanitizeText(result.category, 40) || "Unknown";
  const campaign = sanitizeText(result.campaign, 48) || "None";
  const hook = sanitizeText(result.hook, 24) || "None";
  const reasons = Array.isArray(result.reasons) ? result.reasons : ["System fallback triggered"];
  const actions = Array.isArray(result.actions) && result.actions.length
    ? result.actions
    : ["Treat the result cautiously until it is independently verified."];

  elements.trustScore.textContent = String(score);
  elements.category.textContent = category;
  elements.campaign.textContent = campaign;
  elements.hook.textContent = hook;
  elements.confidence.textContent = `${confidence}%`;
  elements.riskBadge.textContent = `${level} Risk`;

  resetRiskBadgeClasses(level);
  resetScoreBar(level, score);
  renderList(elements.reasonsList, reasons, level);
  renderList(elements.actionsList, actions, level);

  state.totalScans += 1;
  if (level === "High") {
    state.highRiskScans += 1;
  }
  renderMetrics();

  if (sourceText) {
    pushHistory({ text: sourceText, risk: level, category });
  }
}

function setButtonLoading(button, label, isLoading) {
  if (isLoading) {
    button.dataset.originalLabel = button.textContent;
    button.disabled = true;
    button.textContent = label;
    return;
  }
  button.disabled = false;
  button.textContent = button.dataset.originalLabel || button.textContent;
}

function analyzeThreat() {
  const text = sanitizeText(elements.input.value, 1000);
  elements.input.value = text;
  if (!text) {
    updateDashboard(
      {
        score: 100,
        risk: "Low",
        category: "Unknown",
        confidence: 10,
        reasons: ["Please enter content to analyze"],
        actions: ["Provide a message, URL, or request before running analysis."],
      },
      ""
    );
    return;
  }

  setButtonLoading(elements.analyzeButton, "Analyzing...", true);
  const result = analyzeTextLocally(text);
  updateDashboard(result, text);
  setButtonLoading(elements.analyzeButton, "", false);
}

function renderBatchReport(report) {
  const total = sanitizeNumeric(report.total, 0);
  const high = sanitizeNumeric(report.summary?.High, 0);
  elements.batchTotal.textContent = String(total);
  elements.batchHigh.textContent = String(high);

  if (!Array.isArray(report.results) || !report.results.length) {
    elements.batchResults.innerHTML = '<div class="table-empty">No batch results available.</div>';
    return;
  }

  const rows = report.results
    .map(
      (item) => `
        <tr>
          <td>${sanitizeNumeric(item.id, 0)}</td>
          <td>${sanitizeText(item.text, 120)}</td>
          <td>${sanitizeText(item.risk, 16)}</td>
          <td>${sanitizeText(item.category, 32)}</td>
          <td>${sanitizeText(item.campaign, 40) || "None"}</td>
          <td>${sanitizeNumeric(item.score, 0)}</td>
        </tr>
      `
    )
    .join("");

  elements.batchResults.innerHTML = `
    <table class="triage-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Message</th>
          <th>Risk</th>
          <th>Category</th>
          <th>Lure Family</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function runBatchTriage() {
  const items = elements.batchInput.value
    .split("\n")
    .map((line) => sanitizeText(line, 1000))
    .filter(Boolean)
    .slice(0, 25);

  if (!items.length) {
    elements.batchResults.innerHTML = '<div class="table-empty">Add at least one line for batch analysis.</div>';
    return;
  }

  setButtonLoading(elements.batchButton, "Running...", true);

  const results = items.map((text, index) => ({
    id: index + 1,
    text,
    ...analyzeTextLocally(text),
  }));

  const summary = { High: 0, Medium: 0, Low: 0, Unknown: 0 };
  results.forEach((result) => {
    summary[result.risk] = (summary[result.risk] || 0) + 1;
    pushHistory({ text: result.text, risk: result.risk, category: result.category });
  });

  const report = { total: results.length, summary, results };
  state.batchReport = report;
  renderBatchReport(report);
  setButtonLoading(elements.batchButton, "", false);
}

function exportBatchReport() {
  if (!state.batchReport) {
    elements.batchResults.innerHTML =
      '<div class="table-empty">Run batch triage first to export a structured report.</div>';
    return;
  }

  const payload = {
    exportedAt: new Date().toISOString(),
    engine: "TrustLayer Engine v2 Browser Runtime",
    report: state.batchReport,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "trustlayer-batch-report.json";
  anchor.click();
  URL.revokeObjectURL(url);
}

elements.analyzeButton.addEventListener("click", analyzeThreat);
elements.batchButton.addEventListener("click", runBatchTriage);
elements.exportButton.addEventListener("click", exportBatchReport);
elements.sampleButton.addEventListener("click", () => {
  elements.input.value =
    "Your bank account will be blocked, click here immediately to verify your OTP at http://secure-bank-alert.com";
  analyzeThreat();
});

loadHistory();
renderHistory();
renderMetrics();
