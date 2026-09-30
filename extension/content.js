(() => {
  "use strict";

  // ============================================================
  // DARKSHIELD BROWSER EXTENSION
  // Automatic webpage analysis
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
  // 2. ANALYZE PAGE LOCALLY
  //    This will later be replaced/augmented by the backend.
  // ============================================================

  const analysis = analyzePage(pageData);

  console.log("DarkShield analysis:", analysis);


  // ============================================================
  // 3. SHOW SECURITY OVERLAY
  // ============================================================

  showDarkShieldOverlay(pageData, analysis);


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

    return {
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      title: document.title || "",

      text: bodyText.slice(0, 50000),

      forms: forms.length,

      passwordFields,
      emailFields,
      textInputs,
      paymentFields,

      buttons,
      links
    };
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

    // HTTP instead of HTTPS
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


    // @ symbol in URL
    if (url.includes("@")) {

      score += 20;

      technicalSignals.push(
        "Suspicious URL structure"
      );
    }


    // IP address instead of normal domain
    const ipPattern =
      /^(\d{1,3}\.){3}\d{1,3}$/;

    if (ipPattern.test(hostname)) {

      score += 20;

      technicalSignals.push(
        "Website uses an IP address instead of a domain"
      );
    }


    // Very long hostname
    if (hostname.length > 40) {

      score += 8;

      technicalSignals.push(
        "Unusually long domain name"
      );
    }


    // Many hyphens
    const hyphenCount =
      (hostname.match(/-/g) || []).length;

    if (hyphenCount >= 3) {

      score += 8;

      technicalSignals.push(
        "Highly hyphenated domain"
      );
    }


    // Many numbers
    const digitCount =
      (hostname.match(/\d/g) || []).length;

    if (digitCount >= 4) {

      score += 8;

      technicalSignals.push(
        "Unusual number of digits in domain"
      );
    }


    // Suspicious URL keywords
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


    // Email collection
    if (data.emailFields > 0) {

      score += 5;

      behaviorSignals.push(
        "Email collection detected"
      );
    }


    // Forms
    if (data.forms > 0) {

      behaviorSignals.push(
        `${data.forms} form detected`
      );
    }


    // Payment fields
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
    // SOCIAL ENGINEERING — SCARCITY
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
    // SOCIAL ENGINEERING — SOCIAL PROOF
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
    // FEAR / THREAT LANGUAGE
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


    // ==========================================================
    // CAP SCORE
    // ==========================================================

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

    let attackIntent = "No clear malicious intent";

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
      attackIntent !== "No clear malicious intent"
    ) {

      manipulationMap.push(
        attackIntent.toUpperCase()
      );
    }


    // Default map for low-risk pages
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


    // ==========================================================
    // RETURN STRUCTURED RESULT
    // ==========================================================

    return {

      score,

      severity,

      technicalSignals,

      socialSignals,

      behaviorSignals,

      attackIntent,

      manipulationMap,

      recommendation

    };
  }


  // ============================================================
  // CREATE DARKSHIELD OVERLAY
  // ============================================================

  function showDarkShieldOverlay(data, analysis) {

    // Avoid duplicates
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
    // SIGNAL HTML HELPERS
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
    // MANIPULATION MAP HTML
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
    // CREATE OVERLAY
    // ==========================================================

    const overlay =
      document.createElement("div");

    overlay.id =
      "darkshield-overlay";


    overlay.innerHTML = `

      <div class="darkshield-card ${riskClass}">

        <!-- HEADER -->

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


        <!-- STATUS -->

        <div class="darkshield-status">

          <span class="darkshield-status-dot"></span>

          AUTOMATIC PAGE ANALYSIS

        </div>


        <!-- RISK -->

        <div class="darkshield-risk">

          <div class="darkshield-risk-icon">
            ${riskIcon}
          </div>

          <div class="darkshield-risk-score">

            ${analysis.score}

            <span>/100</span>

          </div>

          <div class="darkshield-risk-label">

            ${analysis.severity} RISK

          </div>

        </div>


        <div class="darkshield-divider"></div>


        <!-- TECHNICAL SIGNALS -->

        <div class="darkshield-section">

          <div class="darkshield-section-title">

            TECHNICAL SIGNALS

          </div>

          ${renderSignals(
            analysis.technicalSignals,
            "danger"
          )}

        </div>


        <!-- SOCIAL ENGINEERING -->

        <div class="darkshield-section">

          <div class="darkshield-section-title">

            SOCIAL ENGINEERING

          </div>

          ${renderSignals(
            analysis.socialSignals,
            "warning"
          )}

        </div>


        <!-- SUSPICIOUS BEHAVIOR -->

        <div class="darkshield-section">

          <div class="darkshield-section-title">

            SUSPICIOUS BEHAVIOR

          </div>

          ${renderSignals(
            analysis.behaviorSignals,
            "warning"
          )}

        </div>


        <!-- ATTACK INTENT -->

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


        <!-- MANIPULATION MAP -->

        <div class="darkshield-manipulation">

          <div class="darkshield-section-title">

            MANIPULATION MAP

          </div>

          <div class="darkshield-chain">

            ${renderManipulationMap()}

          </div>

        </div>


        <!-- WARNING -->

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


        <!-- ACTIONS -->

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


        <!-- FOOTER -->

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
    // CLOSE BUTTON
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

          // Go back when possible.
          // If there is no previous page, navigate to a
          // harmless blank page.

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
    // FULL ANALYSIS BUTTON
    // ==========================================================

    const detailsButton =
      document.getElementById(
        "darkshield-details"
      );


    if (detailsButton) {

      detailsButton.addEventListener(
        "click",
        () => {

          console.log(
            "DarkShield full analysis:",
            analysis
          );


          // TEMPORARY
          //
          // Later this will open your main
          // DarkShield dashboard.
          //
          // We deliberately keep this simple
          // until the backend + dashboard URL
          // are connected.

          alert(
            "DarkShield Full Analysis\n\n" +
            "Risk Score: " +
            analysis.score +
            "/100\n\n" +
            "Severity: " +
            analysis.severity +
            "\n\n" +
            "Attack Intent: " +
            analysis.attackIntent
          );

        }
      );

    }

  }


  // ============================================================
  // HTML ESCAPE
  // Prevent page content from injecting HTML into the overlay.
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