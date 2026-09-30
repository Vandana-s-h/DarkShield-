const API_BASE = "http://127.0.0.1:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
          data?.detail || `Backend returned HTTP ${response.status}`
        );
      }

      sendResponse({
        ok: true,
        data
      });
    })
    .catch((error) => {
      console.error("DarkShield backend error:", error);

      sendResponse({
        ok: false,
        error: error.message
      });
    });

  return true;
});