const API_BASE = "http://127.0.0.1:8000";

// ============================================================
// DARKSHIELD PRE-NAVIGATION URL INTELLIGENCE
// ============================================================

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Only analyze the main page/frame.
  if (details.frameId !== 0) {
    return;
  }

  const url = details.url;

  if (!url || !/^https?:\/\//i.test(url)) {
    return;
  }

  const signals = inspectNavigationUrl(url);

  if (signals.length > 0) {
    console.log(
      "DarkShield pre-navigation URL signals:",
      {
        url,
        signals
      }
    );

    // Store the latest navigation evidence so content.js
    // can use it after the page loads.
    chrome.storage.session.set({
      darkshieldNavigationEvidence: {
        url,
        signals,
        timestamp: Date.now()
      }
    });
  } else {
    // Clear stale evidence from the previous page.
    chrome.storage.session.remove(
      "darkshieldNavigationEvidence"
    );
  }
});

// ============================================================
// URL INSPECTION
// ============================================================

function inspectNavigationUrl(rawUrl) {
  const signals = [];

  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    return signals;
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const fullUrl = parsed.href.toLowerCase();

  // ----------------------------------------------------------
  // IP ADDRESS INSTEAD OF DOMAIN
  // ----------------------------------------------------------

  const ipPattern =
    /^(\d{1,3}\.){3}\d{1,3}$/;

  if (ipPattern.test(hostname)) {
    signals.push({
      id: "ip_address_host",
      label: "IP address used as website host",
      evidence: hostname
    });
  }

  // ----------------------------------------------------------
  // NON-HTTPS
  // ----------------------------------------------------------

  if (
    parsed.protocol === "http:" &&
    hostname !== "localhost" &&
    hostname !== "127.0.0.1"
  ) {
    signals.push({
      id: "non_https_navigation",
      label: "Connection is not using HTTPS",
      evidence: parsed.protocol
    });
  }

  // ----------------------------------------------------------
  // EXCESSIVE HYPHENS
  // ----------------------------------------------------------

  const hyphenCount =
    (hostname.match(/-/g) || []).length;

  if (hyphenCount >= 3) {
    signals.push({
      id: "high_hyphen_domain",
      label: "Highly hyphenated domain",
      evidence: `${hyphenCount} hyphens`
    });
  }

  // ----------------------------------------------------------
  // UNUSUALLY LONG HOSTNAME
  // ----------------------------------------------------------

  if (hostname.length > 40) {
    signals.push({
      id: "long_hostname",
      label: "Unusually long hostname",
      evidence: `${hostname.length} characters`
    });
  }

  // ----------------------------------------------------------
  // EXCESSIVE DIGITS
  // ----------------------------------------------------------

 const isIpHost =
  /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

const digitCount =
  (hostname.match(/\d/g) || []).length;

if (!isIpHost && digitCount >= 4) {
  signals.push({
    id: "many_hostname_digits",
    label: "Unusual number of digits in domain",
    evidence: `${digitCount} digits`
  });
}

  // ----------------------------------------------------------
  // SENSITIVE URL WORDS
  // ----------------------------------------------------------

  const sensitiveWords = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "secure",
    "password",
    "reset",
    "payment",
    "checkout",
    "wallet",
    "confirm",
    "update",
    "unlock"
  ];

  const matchedSensitiveWords =
    sensitiveWords.filter(word =>
      fullUrl.includes(word)
    );

  if (matchedSensitiveWords.length >= 2) {
    signals.push({
      id: "multiple_sensitive_url_terms",
      label: "Multiple sensitive account/payment terms in URL",
      evidence: matchedSensitiveWords.join(", ")
    });
  }

  // ----------------------------------------------------------
  // @ SYMBOL
  // ----------------------------------------------------------

  if (parsed.href.includes("@")) {
    signals.push({
      id: "at_symbol_url",
      label: "Suspicious @ symbol in URL",
      evidence: "@"
    });
  }

  // ----------------------------------------------------------
  // SUSPICIOUS PORT
  // ----------------------------------------------------------

  if (
    parsed.port &&
    !["80", "443"].includes(parsed.port)
  ) {
    signals.push({
      id: "unusual_port",
      label: "Unusual web port",
      evidence: parsed.port
    });
  }

  // ----------------------------------------------------------
  // PUNYCODE / INTERNATIONALIZED DOMAIN
  // ----------------------------------------------------------

  if (hostname.includes("xn--")) {
    signals.push({
      id: "punycode_domain",
      label: "Internationalized/punycode domain detected",
      evidence: hostname
    });
  }

  // ----------------------------------------------------------
  // VERY DEEP SUBDOMAIN STRUCTURE
  // ----------------------------------------------------------

  const labels =
    hostname.split(".").filter(Boolean);

  if (labels.length >= 5) {
    signals.push({
      id: "deep_subdomain",
      label: "Unusually deep subdomain structure",
      evidence: `${labels.length} hostname labels`
    });
  }

  // ----------------------------------------------------------
  // SENSITIVE PATH
  // ----------------------------------------------------------

  const sensitivePathWords = [
    "login",
    "signin",
    "verify",
    "verification",
    "password",
    "payment",
    "checkout",
    "wallet",
    "account",
    "reset"
  ];

  const matchedPathWords =
    sensitivePathWords.filter(word =>
      pathname.includes(word)
    );

  if (matchedPathWords.length > 0) {
    signals.push({
      id: "sensitive_path",
      label: "Sensitive account/payment path",
      evidence: matchedPathWords.join(", ")
    });
  }

  return signals;
}

// ============================================================
// EXISTING BACKEND ANALYSIS
// ============================================================

chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {

    if (message?.type === "GET_NAVIGATION_EVIDENCE") {
      chrome.storage.session.get(
        ["darkshieldNavigationEvidence"],
        (result) => {
          sendResponse({
            ok: true,
            data: result?.darkshieldNavigationEvidence || null
          });
        }
      );

      return true;
    }

    if (message?.type !== "ANALYZE_PAGE") {
      return;
    }

    fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(message.payload)
    })
      .then(async (response) => {
        const data = await response.json();

        if (!response.ok) {
          throw new Error(
            data?.detail ||
            `Backend returned HTTP ${response.status}`
          );
        }

        sendResponse({
          ok: true,
          data
        });
      })
      .catch((error) => {
        console.error(
          "DarkShield backend error:",
          error
        );

        sendResponse({
          ok: false,
          error: error.message
        });
      });

    return true;
  }
);