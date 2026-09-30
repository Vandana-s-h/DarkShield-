(() => {
  "use strict";

  // ============================================================
  // CONSTANTS + SELF-GUARD
  // ============================================================

  //const DARKSHIELD_SITE_HOSTNAME = "eloquent-gumption-407aad.netlify.app";
  const DARKSHIELD_REPORT_URL = "https://cheerful-cannoli-d30797.netlify.app/"

  // The DarkShield website is the REPORT VIEWER. Never analyze it and
  // never show the overlay there. (A `return` is valid here because
  // this code is inside the IIFE function body.)
  if (window.location.hostname === "cheerful-cannoli-d30797.netlify.app") {
    return;
  }

  // ============================================================
  // DARKSHIELD BROWSER EXTENSION
  // Automatic webpage analysis + backend integration
  // ============================================================

  console.log("🛡️ DarkShield activated");

  // Prevent duplicate execution
  if (window.__darkShieldLoaded) {
    console.log("DarkShield already running on this page.");
    return;
  }

  window.__darkShieldLoaded = true;

  // ============================================================
  // 1. COLLECT PAGE EVIDENCE
  // ============================================================

  const pageData = collectPageData();

  console.log("DarkShield page data:", pageData);

  // ============================================================
  // 2. ANALYZE WITH BACKEND
  //    Local analyzer remains as fallback.
  // ============================================================

  requestBackendAnalysis(pageData);

  // ============================================================
  // COLLECT PAGE DATA
  // ============================================================

  function collectPageData() {
    const bodyText = document.body
      ? document.body.innerText || ""
      : "";

    const forms = Array.from(document.forms);

    const passwordFields = document.querySelectorAll(
      'input[type="password"]'
    ).length;

    const emailFields = document.querySelectorAll(
      'input[type="email"]'
    ).length;

    const textInputs = document.querySelectorAll(
      'input[type="text"], input:not([type])'
    ).length;

    const paymentFields = document.querySelectorAll(
      'input[name*="card" i], ' +
      'input[name*="cvv" i], ' +
      'input[name*="cvc" i], ' +
      'input[placeholder*="card" i], ' +
      'input[placeholder*="cvv" i], ' +
      'input[placeholder*="cvc" i]'
    ).length;

    const buttons = Array.from(
      document.querySelectorAll("button, input[type='submit']")
    )
      .map(element => {
        return (
          element.innerText ||
          element.value ||
          ""
        ).trim();
      })
      .filter(Boolean)
      .slice(0, 30);

    const links = Array.from(
      document.querySelectorAll("a[href]")
    )
      .map(link => link.href)
      .filter(Boolean)
      .slice(0, 100);

    // ----------------------------------------------------------
    // Convert actual DOM forms into Member 2's API format
    // ----------------------------------------------------------

    const formData = forms.slice(0, 20).map(form => {
      const inputs = Array.from(
        form.querySelectorAll("input, textarea, select")
      );

      const password = inputs.some(input =>
        input.type?.toLowerCase() === "password"
      );

      const email = inputs.some(input =>
        input.type?.toLowerCase() === "email" ||
        /email/i.test(
          `${input.name || ""} ${input.placeholder || ""}`
        )
      );

      const card = inputs.some(input =>
        /card|cardnumber|creditcard/i.test(
          `${input.name || ""} ${input.placeholder || ""} ${input.autocomplete || ""}`
        )
      );

      const cvv = inputs.some(input =>
        /cvv|cvc|security.?code/i.test(
          `${input.name || ""} ${input.placeholder || ""} ${input.autocomplete || ""}`
        )
      );

      const payment = card || cvv || inputs.some(input =>
        /payment|billing|upi|account/i.test(
          `${input.name || ""} ${input.placeholder || ""}`
        )
      );

      let type = "unknown";

      if (password || email) {
        type = "login";
      } else if (payment || card || cvv) {
        type = "payment";
      } else if (inputs.length > 0) {
        type = "form";
      }

      return {
        type,
        password,
        email,
        payment,
        card,
        cvv
      };
    });

    return {
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      title: document.title || "",

      text: bodyText.slice(0, 20000),

      // Backend expects forms as an array.
      forms: formData,

      // These remain available to the local fallback analyzer.
      formCount: forms.length,
      passwordFields,
      emailFields,
      textInputs,
      paymentFields,

      buttons,
      links
    };
  }

  // ============================================================
  // BACKEND REQUEST
  // ============================================================

  function requestBackendAnalysis(data) {
    const backendPayload = {
      url: data.url,
      title: data.title,
      text: data.text,
      forms: data.forms
    };

    console.log(
      "DarkShield sending backend payload:",
      backendPayload
    );

    chrome.runtime.sendMessage(
      {
        type: "ANALYZE_PAGE",
        payload: backendPayload
      },
      response => {
        // Chrome runtime error
        if (chrome.runtime.lastError) {
          console.warn(
            "DarkShield backend communication failed:",
            chrome.runtime.lastError.message
          );

          useLocalFallback(data);
          return;
        }

        // Backend unavailable
        if (!response || !response.ok) {
          console.warn(
            "DarkShield backend unavailable:",
            response?.error || "Unknown backend error"
          );

          useLocalFallback(data);
          return;
        }

        console.log(
          "DarkShield backend response:",
          response.data
        );

        const backendAnalysis =
          normalizeBackendAnalysis(response.data);

        showDarkShieldOverlay(
          data,
          backendAnalysis
        );
      }
    );
  }

  // ============================================================
  // NORMALIZE BACKEND RESPONSE
  // Converts Member 2's structured API response into the
  // format expected by the existing overlay.
  // ============================================================

  function normalizeBackendAnalysis(result) {
    const technicalSignals =
      normalizeSignals(result.technical_signals);

    const socialSignals =
      normalizeSignals(result.social_signals);

    const behaviorSignals =
      normalizeSignals(result.behavioral_signals);

    const manipulationMap =
      Array.isArray(result.manipulation_map)
        ? result.manipulation_map
            .filter(step => step && step.observed)
            .map(step => {
              const evidence =
                Array.isArray(step.evidence)
                  ? step.evidence
                  : [];

              if (evidence.length > 0) {
                return `${step.stage}: ${evidence.join(", ")}`;
              }

              return step.stage;
            })
        : [];

    return {
      score: Number(result.risk_score ?? 0),

      severity:
        result.severity ||
        "LOW",

      technicalSignals,

      socialSignals,

      behaviorSignals,

      attackIntent:
        result.attack_intent ||
        "No clear malicious intent",

      secondaryIntents:
        Array.isArray(result.secondary_intents)
          ? result.secondary_intents
          : [],

      manipulationMap:
        manipulationMap.length > 0
          ? manipulationMap
          : ["NO CLEAR MANIPULATION CHAIN"],

      recommendation:
        result.recommendation ||
        "Proceed carefully.",

      explanation:
        result.explanation ||
        "",

      scoreBreakdown:
        result.score_breakdown || null,

      source: "BACKEND"
    };
  }

  // ============================================================
  // NORMALIZE SIGNAL OBJECTS
  // ============================================================

  function normalizeSignals(signals) {
    if (!Array.isArray(signals)) {
      return [];
    }

    return signals.map(signal => {
      if (typeof signal === "string") {
        return signal;
      }

      const label =
        signal.label ||
        signal.id ||
        "Signal detected";

      const evidence =
        Array.isArray(signal.evidence)
          ? signal.evidence
          : [];

      if (evidence.length > 0) {
        return `${label} — Evidence: ${evidence.join(", ")}`;
      }

      return label;
    });
  }

  // ============================================================
  // LOCAL FALLBACK
  // ============================================================

  function useLocalFallback(data) {
    console.log(
      "DarkShield using local fallback analyzer."
    );

    const analysis = analyzePage(data);

    analysis.source = "LOCAL FALLBACK";

    showDarkShieldOverlay(
      data,
      analysis
    );
  }

  // ============================================================
  // LOCAL DARKSHIELD DETECTION ENGINE
  // ============================================================

  function analyzePage(data) {
    let score = 0;

    const technicalSignals = [];
    const socialSignals = [];
    const behaviorSignals = [];

    const url = data.url.toLowerCase();
    const hostname = data.hostname.toLowerCase();
    const text = data.text.toLowerCase();

    // ==========================================================
    // TECHNICAL URL SIGNALS
    // ==========================================================

    if (
      data.protocol === "http:" &&
      hostname !== "localhost" &&
      hostname !== "127.0.0.1"
    ) {
      score += 10;

      technicalSignals.push(
        "Connection is not using HTTPS"
      );
    }

    if (url.includes("@")) {
      score += 20;

      technicalSignals.push(
        "Suspicious URL structure"
      );
    }

    const ipPattern =
      /^(\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {
      score += 20;

      technicalSignals.push(
        "Website uses an IP address instead of a domain"
      );
    }

    if (hostname.length > 40) {
      score += 8;

      technicalSignals.push(
        "Unusually long domain name"
      );
    }

    const hyphenCount =
      (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 3) {
      score += 8;

      technicalSignals.push(
        "Highly hyphenated domain"
      );
    }

    const digitCount =
      (hostname.match(/\d/g) || []).length;

    if (digitCount >= 4) {
      score += 8;

      technicalSignals.push(
        "Unusual number of digits in domain"
      );
    }

    const sensitiveUrlWords = [
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
      "confirm"
    ];

    const matchingSensitiveWord =
      sensitiveUrlWords.find(
        word => url.includes(word)
      );

    if (matchingSensitiveWord) {
      score += 10;

      technicalSignals.push(
        "Sensitive account/payment URL"
      );
    }

    // ==========================================================
    // BRAND IMPERSONATION
    // ==========================================================

    const brands = [
      "paypal",
      "amazon",
      "apple",
      "google",
      "microsoft",
      "netflix",
      "instagram",
      "facebook",
      "whatsapp",
      "dhl",
      "fedex",
      "ups",
      "hdfc",
      "sbi",
      "icici",
      "india post"
    ];

    const mentionedBrand =
      brands.find(
        brand => text.includes(brand)
      );

    if (mentionedBrand) {
      const brandInHostname =
        hostname.includes(
          mentionedBrand.replace(/\s+/g, "")
        );

      if (!brandInHostname) {
        score += 15;

        technicalSignals.push(
          `Possible ${mentionedBrand} impersonation`
        );
      }
    }

    // ==========================================================
    // PASSWORD / CREDENTIAL COLLECTION
    // ==========================================================

    if (data.passwordFields > 0) {
      score += 20;

      behaviorSignals.push(
        "Credential collection detected"
      );
    }

    if (data.emailFields > 0) {
      score += 5;

      behaviorSignals.push(
        "Email collection detected"
      );
    }

    if (data.formCount > 0) {
      behaviorSignals.push(
        `${data.formCount} form detected`
      );
    }

    if (data.paymentFields > 0) {
      score += 20;

      behaviorSignals.push(
        "Payment information collection detected"
      );
    }

    // ==========================================================
    // SOCIAL ENGINEERING — URGENCY
    // ==========================================================

    const urgencyWords = [
      "urgent",
      "immediately",
      "act now",
      "act immediately",
      "expires today",
      "limited time",
      "verify now",
      "verify immediately",
      "last chance",
      "account will be suspended",
      "account will be closed",
      "your account has been suspended",
      "respond immediately"
    ];

    const urgencyDetected =
      urgencyWords.some(
        word => text.includes(word)
      );

    if (urgencyDetected) {
      score += 15;

      socialSignals.push(
        "Urgency / pressure language"
      );
    }

    // ==========================================================
    // SCARCITY
    // ==========================================================

    const scarcityWords = [
      "only 1 left",
      "only 2 left",
      "only 3 left",
      "few remaining",
      "limited stock",
      "selling fast",
      "almost sold out",
      "limited availability",
      "last few",
      "hurry"
    ];

    const scarcityDetected =
      scarcityWords.some(
        word => text.includes(word)
      );

    if (scarcityDetected) {
      score += 10;

      socialSignals.push(
        "Artificial scarcity"
      );
    }

    // ==========================================================
    // SOCIAL PROOF
    // ==========================================================

    const socialProofWords = [
      "people are viewing",
      "people are buying",
      "customers are buying",
      "people bought",
      "trending now",
      "popular right now",
      "someone just purchased",
      "people are watching",
      "people are interested",
      "people are checking out"
    ];

    const socialProofDetected =
      socialProofWords.some(
        word => text.includes(word)
      );

    if (socialProofDetected) {
      score += 10;

      socialSignals.push(
        "Possible social-proof manipulation"
      );
    }

    // ==========================================================
    // FEAR / THREAT
    // ==========================================================

    const fearWords = [
      "your account will be closed",
      "your account will be suspended",
      "legal action",
      "security alert",
      "unauthorized activity",
      "suspicious activity",
      "you will lose access",
      "failure to verify",
      "immediate action required"
    ];

    const fearDetected =
      fearWords.some(
        word => text.includes(word)
      );

    if (fearDetected) {
      score += 15;

      socialSignals.push(
        "Fear / threat-based pressure"
      );
    }

    // ==========================================================
    // PAYMENT LANGUAGE
    // ==========================================================

    const paymentWords = [
      "credit card",
      "debit card",
      "card number",
      "cvv",
      "cvc",
      "bank account",
      "payment",
      "upi",
      "transaction"
    ];

    const paymentLanguageDetected =
      paymentWords.some(
        word => text.includes(word)
      );

    if (paymentLanguageDetected) {
      score += 10;

      behaviorSignals.push(
        "Financial information requested"
      );
    }

    score = Math.min(score, 100);

    // ==========================================================
    // SEVERITY
    // ==========================================================

    let severity = "LOW";

    if (score >= 76) {
      severity = "CRITICAL";
    } else if (score >= 51) {
      severity = "HIGH";
    } else if (score >= 26) {
      severity = "MODERATE";
    }

    // ==========================================================
    // ATTACK INTENT
    // ==========================================================

    let attackIntent =
      "No clear malicious intent";

    if (
      data.passwordFields > 0 &&
      (
        urgencyDetected ||
        fearDetected ||
        data.paymentFields > 0
      )
    ) {
      attackIntent =
        "Credential Theft";

    } else if (
      data.paymentFields > 0 ||
      paymentLanguageDetected
    ) {
      attackIntent =
        "Financial Information Theft";

    } else if (
      urgencyDetected &&
      (
        scarcityDetected ||
        fearDetected
      )
    ) {
      attackIntent =
        "Forced User Action";

    } else if (
      data.passwordFields > 0
    ) {
      attackIntent =
        "Credential Collection";
    }

    // ==========================================================
    // MANIPULATION MAP
    // ==========================================================

    const manipulationMap = [];

    if (
      technicalSignals.some(
        signal =>
          signal.toLowerCase().includes("impersonation")
      )
    ) {
      manipulationMap.push(
        "IMPERSONATE"
      );
    }

    if (
      mentionedBrand ||
      socialSignals.length > 0
    ) {
      manipulationMap.push(
        "BUILD TRUST"
      );
    }

    if (urgencyDetected || fearDetected) {
      manipulationMap.push(
        "CREATE PRESSURE"
      );
    }

    if (scarcityDetected) {
      manipulationMap.push(
        "CREATE SCARCITY"
      );
    }

    if (
      data.passwordFields > 0 ||
      data.paymentFields > 0
    ) {
      manipulationMap.push(
        "REQUEST SENSITIVE DATA"
      );
    }

    if (
      attackIntent !==
      "No clear malicious intent"
    ) {
      manipulationMap.push(
        attackIntent.toUpperCase()
      );
    }

    if (manipulationMap.length === 0) {
      manipulationMap.push(
        "NO CLEAR MANIPULATION CHAIN"
      );
    }

    // ==========================================================
    // RECOMMENDATION
    // ==========================================================

    let recommendation =
      "Continue browsing normally.";

    if (score >= 76) {
      recommendation =
        "Do not enter credentials, payment information, or other sensitive data.";

    } else if (score >= 51) {
      recommendation =
        "Verify the website independently before entering sensitive information.";

    } else if (score >= 26) {
      recommendation =
        "Proceed carefully and verify important requests.";
    }

    return {
      score,
      severity,
      technicalSignals,
      socialSignals,
      behaviorSignals,
      attackIntent,
      manipulationMap,
      recommendation,
      explanation: "",
      secondaryIntents: [],
      scoreBreakdown: null,
      source: "LOCAL FALLBACK"
    };
  }

  // ============================================================
  // CREATE DARKSHIELD OVERLAY
  // ============================================================

  function showDarkShieldOverlay(data, analysis) {
    if (
      document.getElementById(
        "darkshield-overlay"
      )
    ) {
      return;
    }

    // ==========================================================
    // RISK CLASS
    // ==========================================================

    let riskClass = "low";
    let riskIcon = "🟢";

    if (analysis.score >= 76) {
      riskClass = "critical";
      riskIcon = "🔴";
    } else if (analysis.score >= 51) {
      riskClass = "high";
      riskIcon = "🟠";
    } else if (analysis.score >= 26) {
      riskClass = "moderate";
      riskIcon = "🟡";
    }

    // ==========================================================
    // SIGNAL HTML
    // ==========================================================

    function renderSignals(
      signals,
      type = "warning"
    ) {
      if (!signals || signals.length === 0) {
        return `
          <div class="darkshield-signal safe">
            <span>✓</span>
            <span>No major signals detected</span>
          </div>
        `;
      }

      return signals
        .map(signal => {
          return `
            <div class="darkshield-signal ${type}">
              <span>⚠</span>
              <span>${escapeHTML(signal)}</span>
            </div>
          `;
        })
        .join("");
    }

    // ==========================================================
    // MANIPULATION MAP
    // ==========================================================

    function renderManipulationMap() {
      const steps =
        analysis.manipulationMap || [];

      return steps
        .map((step, index) => {
          const arrow =
            index < steps.length - 1
              ? `
                <div class="darkshield-chain-arrow">
                  ↓
                </div>
              `
              : "";

          return `
            <div class="darkshield-chain-step">
              ${escapeHTML(step)}
            </div>

            ${arrow}
          `;
        })
        .join("");
    }

    // ==========================================================
    // EXTRA BACKEND DETAILS
    // ==========================================================

    const sourceLabel =
      analysis.source === "BACKEND"
        ? "BACKEND ANALYSIS"
        : "LOCAL FALLBACK ANALYSIS";

    const secondaryIntentHTML =
      analysis.secondaryIntents &&
      analysis.secondaryIntents.length > 0
        ? `
          <div class="darkshield-secondary-intents">
            <div class="darkshield-section-title">
              SECONDARY INTENTS
            </div>

            ${analysis.secondaryIntents
              .map(intent => `
                <div class="darkshield-signal warning">
                  <span>•</span>
                  <span>${escapeHTML(intent)}</span>
                </div>
              `)
              .join("")}
          </div>
        `
        : "";

    const explanationHTML =
      analysis.explanation
        ? `
          <div class="darkshield-section">
            <div class="darkshield-section-title">
              DARKSHIELD EXPLANATION
            </div>

            <div class="darkshield-explanation">
              ${escapeHTML(analysis.explanation)}
            </div>
          </div>
        `
        : "";

    const breakdown =
      analysis.scoreBreakdown;

    const breakdownHTML =
      breakdown
        ? `
          <div class="darkshield-section">
            <div class="darkshield-section-title">
              SCORE BREAKDOWN
            </div>

            <div class="darkshield-breakdown">
              <div>
                Technical:
                <strong>${escapeHTML(breakdown.technical)}</strong>
              </div>

              <div>
                Social:
                <strong>${escapeHTML(breakdown.social)}</strong>
              </div>

              <div>
                Behavioral:
                <strong>${escapeHTML(breakdown.behavioral)}</strong>
              </div>

              <div>
                Combination:
                <strong>${escapeHTML(breakdown.combination_bonus)}</strong>
              </div>
            </div>
          </div>
        `
        : "";

    // ==========================================================
    // CREATE OVERLAY
    // ==========================================================

    const overlay =
      document.createElement("div");

    overlay.id =
      "darkshield-overlay";

    overlay.innerHTML = `

      <div class="darkshield-card ${riskClass}">

        <div class="darkshield-header">

          <div class="darkshield-logo">
            🛡️
          </div>

          <div class="darkshield-brand">

            <div class="darkshield-title">
              DARKSHIELD
            </div>

            <div class="darkshield-subtitle">
              AI SECURITY LAYER
            </div>

          </div>

          <button
            id="darkshield-close"
            class="darkshield-close"
            type="button"
          >
            ×
          </button>

        </div>

        <div class="darkshield-status">

          <span class="darkshield-status-dot"></span>

          ${sourceLabel}

        </div>

        <div class="darkshield-risk">

          <div class="darkshield-risk-icon">
            ${riskIcon}
          </div>

          <div class="darkshield-risk-score">

            ${escapeHTML(analysis.score)}

            <span>/100</span>

          </div>

          <div class="darkshield-risk-label">

            ${escapeHTML(analysis.severity)} RISK

          </div>

        </div>

        <div class="darkshield-divider"></div>

        <div class="darkshield-section">

          <div class="darkshield-section-title">
            TECHNICAL SIGNALS
          </div>

          ${renderSignals(
            analysis.technicalSignals,
            "danger"
          )}

        </div>

        <div class="darkshield-section">

          <div class="darkshield-section-title">
            SOCIAL ENGINEERING
          </div>

          ${renderSignals(
            analysis.socialSignals,
            "warning"
          )}

        </div>

        <div class="darkshield-section">

          <div class="darkshield-section-title">
            SUSPICIOUS BEHAVIOR
          </div>

          ${renderSignals(
            analysis.behaviorSignals,
            "warning"
          )}

        </div>

        <div class="darkshield-intent">

          <div class="darkshield-section-title">
            ATTACK INTENT
          </div>

          <div class="darkshield-intent-value">

            🎯
            ${escapeHTML(
              analysis.attackIntent
            )}

          </div>

        </div>

        ${secondaryIntentHTML}

        <div class="darkshield-manipulation">

          <div class="darkshield-section-title">
            MANIPULATION MAP
          </div>

          <div class="darkshield-chain">

            ${renderManipulationMap()}

          </div>

        </div>

        ${explanationHTML}

        ${breakdownHTML}

        <div class="darkshield-warning">

          <strong>

            ${
              analysis.score >= 51
                ? "⚠ Think before you act."
                : "✓ No immediate high-risk indicators."
            }

          </strong>

          <div>

            ${escapeHTML(
              analysis.recommendation
            )}

          </div>

        </div>

        <div class="darkshield-actions">

          ${
            analysis.score >= 51
              ? `
                <button
                  id="darkshield-leave"
                  class="darkshield-button danger-button"
                  type="button"
                >
                  Leave Site
                </button>
              `
              : ""
          }

          <button
            id="darkshield-details"
            class="darkshield-button secondary-button"
            type="button"
          >
            Show Full Analysis
          </button>

        </div>

        <div class="darkshield-footer">

          DarkShield • Automatic Protection

        </div>

      </div>

    `;

    // ==========================================================
    // ADD TO PAGE
    // ==========================================================

    if (document.body) {
      document.body.appendChild(
        overlay
      );
    } else {
      document.addEventListener(
        "DOMContentLoaded",
        () => {
          document.body.appendChild(
            overlay
          );
        },
        { once: true }
      );
    }

    // ==========================================================
    // CLOSE
    // ==========================================================

    const closeButton =
      document.getElementById(
        "darkshield-close"
      );

    if (closeButton) {
      closeButton.addEventListener(
        "click",
        () => {
          overlay.remove();
        }
      );
    }

    // ==========================================================
    // LEAVE SITE
    // ==========================================================

    const leaveButton =
      document.getElementById(
        "darkshield-leave"
      );

    if (leaveButton) {
      leaveButton.addEventListener(
        "click",
        () => {
          if (
            window.history.length > 1
          ) {
            window.history.back();
          } else {
            window.location.href =
              "about:blank";
          }
        }
      );
    }

        // ==========================================================
    // FULL ANALYSIS
    // Transfers the SAME `analysis` object shown in this overlay.
    // No backend call, no local detector, no re-analysis.
    // ==========================================================

    const detailsButton =
      document.getElementById("darkshield-details");

    if (detailsButton) {
      detailsButton.addEventListener("click", () => {
        try {
          const report = {
            schema: "darkshield-extension-report",
            version: 1,
            createdAt: new Date().toISOString(),
            pageUrl: data.url,
            pageTitle: data.title,
            analysis: analysis
          };

          const encoded = encodeReportForUrl(report);

          window.open(
            DARKSHIELD_REPORT_URL + "#extension-report=" + encoded,
            "_blank"
          );
        } catch (error) {
          console.error(
            "DarkShield could not open the full report:",
            error
          );
        }
      });
    }
  }

  // ============================================================
  // ENCODE REPORT FOR URL HASH
  // UTF-8 safe (₹, →, ⚠ etc.), base64url, no deprecated APIs.
  // ============================================================

  function encodeReportForUrl(report) {
    const bytes =
      new TextEncoder().encode(JSON.stringify(report));

    let binary = "";
    const chunk = 0x8000;

    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(
        null,
        bytes.subarray(i, i + chunk)
      );
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  // ============================================================
  // HTML ESCAPE
  // ============================================================

  function escapeHTML(value) {
    const stringValue =
      String(value ?? "");

    return stringValue
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

})();
