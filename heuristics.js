/**
 * Local-only phishing / social-engineering heuristics for SOC triage.
 * Not a replacement for URL reputation services or EDR—signals for analyst review.
 */

const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly", "is.gd",
  "adf.ly", "rebrand.ly", "cutt.ly", "short.link", "rb.gy", "tiny.cc",
  "bl.ink", "soo.gd", "shorturl.at", "cli.re", "bitly.com", "tiny.one",
]);

const RISKY_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
  "buzz", "zip", "mov", "rest", "cam", "cyou", "icu", "casa", "bar",
  "beauty", "monster", "surf", "win", "date", "loan", "men",
]);

const URGENCY_PATTERNS = [
  { re: /\b(urgent|immediately|within\s+24\s*hours?|act\s+now|expires?\s+today)\b/gi, label: "Urgency / time pressure", weight: 2 },
  { re: /\b(verify\s+your\s+account|confirm\s+your\s+identity|validate\s+your\s+payment)\b/gi, label: "Account verification hook", weight: 3 },
  { re: /\b(suspended|locked|disabled|unusual\s+activity|security\s+alert)\b/gi, label: "Account state / alert language", weight: 2 },
  { re: /\b(wire\s+transfer|gift\s+card|bitcoin|cryptocurrency|send\s+funds)\b/gi, label: "Financial / irreversible payment", weight: 3 },
  { re: /\b(CEO|CFO|executive)\s+(asked|requests?|needs?)\b/gi, label: "Executive impersonation (BEC cue)", weight: 3 },
  { re: /\b(password|SSN|social\s+security|tax\s+id|PIN)\b.*\b(enter|provide|send|reply\s+with)\b/gi, label: "Credential / PII solicitation", weight: 4 },
  { re: /\b(click\s+here|open\s+attachment|download\s+and\s+run)\b/gi, label: "Execution / click directive", weight: 2 },
  { re: /\b(microsoft|google|apple|paypal|amazon|bank)\b.*\b(verify|update|restore)\b/gi, label: "Brand + account action (possible impersonation)", weight: 2 },
];

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;

/** Rough URL extraction (handles common cases in pasted IOCs and email bodies). */
const URL_RE = /\bhttps?:\/\/[^\s<>"'{}|\\^`\[\]]+/gi;
const BARE_DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

function tryParseUrl(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function tldFromHost(host) {
  const parts = host.toLowerCase().split(".");
  if (parts.length < 2) return "";
  return parts[parts.length - 1];
}

function analyzeUrl(raw) {
  const u = tryParseUrl(raw);
  if (!u) return { raw, signals: [{ text: "Malformed URL", severity: "low" }] };

  const signals = [];
  const host = u.hostname.toLowerCase();

  if (u.protocol === "http:") {
    signals.push({ text: "HTTP (not HTTPS)—credentials or forms could be observed in transit", severity: "medium" });
  }

  if (host.startsWith("xn--") || raw.includes("xn--")) {
    signals.push({ text: "Punycode / IDN hostname—possible homograph attack", severity: "high" });
  }

  if (IPV4_RE.test(host)) {
    signals.push({ text: "Host is a raw IPv4 address—common in phishing and malware C2", severity: "high" });
  }

  const tld = tldFromHost(host);
  if (RISKY_TLDS.has(tld)) {
    signals.push({ text: `TLD “.${tld}” is frequently abused—treat with elevated suspicion`, severity: "medium" });
  }

  if (u.username) {
    signals.push({
      text: "URL includes a userinfo username—often used to display a trusted brand while sending victims to another host",
      severity: "high",
    });
  }

  const segments = host.split(".");
  if (segments.length > 4) {
    signals.push({ text: "Many subdomain labels—possible cloaking or lookalike structure", severity: "low" });
  }

  if (SHORTENERS.has(host) || SHORTENERS.has(host.replace(/^www\./, ""))) {
    signals.push({ text: "Known URL shortener—destination is opaque until expanded", severity: "medium" });
  }

  if (u.port && u.port !== "80" && u.port !== "443") {
    signals.push({ text: `Non-default port ${u.port}—sometimes used to evade naive filters`, severity: "low" });
  }

  if (u.username || u.password) {
    signals.push({ text: "Embedded username/password in URL—unusual in legitimate mail", severity: "high" });
  }

  return { raw, normalized: u.href, host, signals };
}

function findUrls(text) {
  const found = new Set();
  const m = text.match(URL_RE);
  if (m) m.forEach((u) => found.add(u.trim()));
  return [...found];
}

function findBareDomains(text) {
  /** Avoid double-counting URLs */
  const withoutUrls = text.replace(URL_RE, " ");
  const m = withoutUrls.match(BARE_DOMAIN_RE) || [];
  return [...new Set(m.map((d) => d.toLowerCase()))].filter((d) => {
    if (d.length < 5) return false;
    const tld = tldFromHost(d);
    return tld.length >= 2 && tld.length <= 24;
  });
}

function languageHits(text) {
  const hits = [];
  for (const { re, label, weight } of URGENCY_PATTERNS) {
    re.lastIndex = 0;
    if (re.test(text)) {
      hits.push({ label, weight });
    }
  }
  return hits;
}

function base64Chunks(text) {
  const re = /\b[A-Za-z0-9+/]{40,}={0,2}\b/g;
  return (text.match(re) || []).slice(0, 5);
}

function extractIps(text) {
  const m = text.match(IPV4_RE) || [];
  return [...new Set(m)];
}

function extractEmails(text) {
  const re = /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi;
  return [...new Set((text.match(re) || []).map((e) => e.toLowerCase()))];
}

/**
 * @param {string} text
 * @returns {{ score: number, maxScore: number, findings: object }}
 */
export function analyzeSelection(text) {
  const trimmed = (text || "").trim();
  if (!trimmed) {
    return {
      score: 0,
      maxScore: 0,
      findings: { empty: true },
      summary: "No text selected.",
      severityLabel: "—",
    };
  }

  const urlResults = findUrls(trimmed).map(analyzeUrl);
  const domains = findBareDomains(trimmed);
  const lang = languageHits(trimmed);
  const ips = extractIps(trimmed);
  const emails = extractEmails(trimmed);
  const b64 = base64Chunks(trimmed);

  let score = 0;
  const maxHints = 40;

  for (const ur of urlResults) {
    for (const s of ur.signals) {
      if (s.severity === "high") score += 4;
      else if (s.severity === "medium") score += 2;
      else score += 1;
    }
  }

  for (const d of domains) {
    const tld = tldFromHost(d);
    if (RISKY_TLDS.has(tld)) score += 1;
  }

  for (const h of lang) {
    score += h.weight;
  }

  if (ips.length) score += Math.min(ips.length * 2, 6);
  if (b64.length) score += 2;
  if (emails.length > 3) score += 1;

  const capped = Math.min(score, maxHints);
  let severityLabel = "Low";
  if (capped >= 18) severityLabel = "High";
  else if (capped >= 8) severityLabel = "Elevated";

  const summaryParts = [];
  if (urlResults.length) summaryParts.push(`${urlResults.length} URL(s)`);
  if (domains.length) summaryParts.push(`${domains.length} domain mention(s)`);
  if (lang.length) summaryParts.push(`${lang.length} language pattern(s)`);
  if (ips.length) summaryParts.push(`${ips.length} IPv4`);
  if (emails.length) summaryParts.push(`${emails.length} email(s)`);
  if (b64.length) summaryParts.push("possible Base64");

  return {
    score: capped,
    maxScore: maxHints,
    severityLabel,
    summary: summaryParts.length ? summaryParts.join(" · ") : "Few automated signals—still review context and sender.",
    findings: {
      empty: false,
      urls: urlResults,
      bareDomains: domains.slice(0, 30),
      language: lang,
      ips,
      emails: emails.slice(0, 20),
      base64Samples: b64,
    },
  };
}
