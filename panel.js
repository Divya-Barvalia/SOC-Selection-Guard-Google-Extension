import { analyzeSelection } from "./heuristics.js";

const STORAGE_KEY = "lastSelection";
const STORAGE_TS = "lastSelectionAt";

const manual = document.getElementById("manual");
const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");
const results = document.getElementById("results");
const summaryEl = document.getElementById("summary");
const severityEl = document.getElementById("severity");
const scoreEl = document.getElementById("score");
const maxScoreEl = document.getElementById("maxScore");
const sectionsEl = document.getElementById("sections");

function setSeverityClass(label) {
  severityEl.textContent = label;
  severityEl.className = "sev";
  const k = label.toLowerCase();
  if (k === "high") severityEl.classList.add("high");
  else if (k === "elevated") severityEl.classList.add("elevated");
  else severityEl.classList.add("low");
}

function render(data) {
  if (data.findings.empty) {
    results.hidden = true;
    return;
  }
  results.hidden = false;
  summaryEl.textContent = data.summary;
  setSeverityClass(data.severityLabel);
  scoreEl.textContent = String(data.score);
  maxScoreEl.textContent = String(data.maxScore);

  const f = data.findings;
  const parts = [];

  if (f.urls?.length) {
    let html = '<div class="sec"><h3>URLs</h3>';
    for (const u of f.urls) {
      html += `<div class="url-block">${escapeHtml(u.raw)}</div>`;
      if (!u.signals.length) {
        html += '<p class="empty-sec">No extra URL structure flags.</p>';
      } else {
        html += "<ul>";
        for (const s of u.signals) {
          html += `<li class="sig ${s.severity}">${escapeHtml(s.text)}</li>`;
        }
        html += "</ul>";
      }
    }
    html += "</div>";
    parts.push(html);
  }

  if (f.language?.length) {
    let html = '<div class="sec"><h3>Social-engineering language</h3><ul>';
    for (const l of f.language) {
      html += `<li class="sig medium">${escapeHtml(l.label)}</li>`;
    }
    html += "</ul></div>";
    parts.push(html);
  }

  if (f.ips?.length) {
    parts.push(
      `<div class="sec"><h3>IPv4 addresses</h3><ul>${f.ips
        .map((ip) => `<li class="sig medium">${escapeHtml(ip)}</li>`)
        .join("")}</ul><p class="empty-sec">Correlate with proxy/firewall/DNS logs and threat intel.</p></div>`,
    );
  }

  if (f.emails?.length) {
    parts.push(
      `<div class="sec"><h3>Email addresses in selection</h3><ul>${f.emails
        .map((e) => `<li>${escapeHtml(e)}</li>`)
        .join("")}</ul></div>`,
    );
  }

  if (f.bareDomains?.length) {
    const shown = f.bareDomains.slice(0, 15);
    parts.push(
      `<div class="sec"><h3>Domains (not full URLs)</h3><p class="muted">First ${shown.length} unique—check for lookalikes vs. your approved vendors.</p><ul>${shown
        .map((d) => `<li class="sig low">${escapeHtml(d)}</li>`)
        .join("")}</ul></div>`,
    );
  }

  if (f.base64Samples?.length) {
    parts.push(
      `<div class="sec"><h3>Base64-like strings</h3><p class="muted">May be benign; decode in a sandbox if relevant.</p><ul>${f.base64Samples
        .map((b) => `<li class="url-block">${escapeHtml(b.slice(0, 80))}${b.length > 80 ? "…" : ""}</li>`)
        .join("")}</ul></div>`,
    );
  }

  if (!parts.length) {
    parts.push(
      '<p class="empty-sec">No URLs or strong keyword hits. Expand selection or paste headers / full message source for richer context.</p>',
    );
  }

  sectionsEl.innerHTML = parts.join("");
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function run(text) {
  const data = analyzeSelection(text);
  render(data);
}

async function pullSessionSelection() {
  const s = await chrome.storage.session.get([STORAGE_KEY, STORAGE_TS]);
  const text = s[STORAGE_KEY];
  if (typeof text === "string" && text.trim()) {
    manual.value = text;
    run(text);
    await chrome.storage.session.remove([STORAGE_KEY, STORAGE_TS]);
  }
}

analyzeBtn.addEventListener("click", () => run(manual.value));
clearBtn.addEventListener("click", () => {
  manual.value = "";
  results.hidden = true;
});

chrome.storage.session.onChanged.addListener(() => {
  pullSessionSelection();
});

pullSessionSelection();
