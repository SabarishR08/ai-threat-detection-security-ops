// Popup logic: scan the current tab via backend and show result
const scanBtn = document.getElementById("scan-button");
const statusEl = document.getElementById("status-text");
const resultEl = document.getElementById("result-text");

function setStatus(text, color = "#bfbfbf") {
  statusEl.textContent = text;
  statusEl.style.color = color;
}

function setResult(text, color = "#00FFFF") {
  resultEl.textContent = text;
  resultEl.style.color = color;
}

async function getActiveTabUrl() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url || "";
}

async function scanCurrentTab() {
  try {
    setStatus("Grabbing current tab...");
    setResult("");
    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    const url = await getActiveTabUrl();
    if (!url || !(url.startsWith("http://") || url.startsWith("https://"))) {
      setStatus("Only http/https URLs can be scanned", "#ff9f0a");
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan URL";
      return;
    }

    setStatus("Contacting backend...");
    const resp = await fetch("http://localhost:5000/check-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!resp.ok) {
      setStatus(`Backend error ${resp.status}`, "#ff453a");
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan URL";
      return;
    }

    const data = await resp.json();
    const status = data.status || "Unknown";
    const severity = data.severity || "Unknown";
    const detectedBy = data.detected_by || "TI pipeline";

    setStatus("Scan complete", "#34c759");
    setResult(`${status} (severity: ${severity}) via ${detectedBy}`);
  } catch (err) {
    console.error("Popup scan error", err);
    setStatus("Scan failed", "#ff453a");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "Scan URL";
  }
}

scanBtn.addEventListener("click", scanCurrentTab);
