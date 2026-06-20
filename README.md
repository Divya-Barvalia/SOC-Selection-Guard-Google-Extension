# SOC Selection Guard

A google extension made for an in browser security analysis of selected text, Ex: Emails

SOC Selection Guard helps security teams triage phishing and social-engineering attempts faster. Highlight any text — an email, a support ticket, a chat message, a list of IOCs — right-click, and get a breakdown of red flags like suspicious links, urgency tactics, and impersonation language. Everything happens locally in the browser, with no data sent to any external server.

Demo Video: Coming soon...

## Why this exists

Triage usually starts the same way: someone reads through an email looking for the usual red flags — a weird link, a pushy tone, a request for credentials. SOC Selection Guard turns that manual first pass into something instant and consistent, so analysts can spend their time on judgment calls instead of re-reading the same message three times looking for clues.

It's meant to sit alongside your existing tools, not replace them — a fast first filter that tells you what's worth a closer look.

## How it helps

- **Speeds up triage.** Instead of manually scanning a message, analysts get an automatic signal summary in seconds.
- **Standardizes the first pass.** Every analyst, regardless of experience level, gets the same baseline set of checks applied.
- **Works anywhere text appears.** Email clients, ticketing systems, Slack, browser-based webmail — anywhere you can select text in Chrome.
- **Keeps data local.** Nothing leaves the browser, which matters when the "suspicious" text might contain sensitive or confidential content.
- **Gives context, not just a verdict.** Results explain *why* something was flagged, helping less experienced analysts learn to spot the same patterns themselves.

## How you can start using it

1. Go to `chrome://extensions/`.
2. Make sure **Developer mode** is enabled (top right).
3. Save the code package folder somewhere on your machine.
4. Click **Load unpacked** and select the code package folder for the extension.
5. Make sure the extension is enabled.
## How it works, at a glance

1. Select suspicious text anywhere in the browser.
2. Right-click and choose the analyze option.
3. A side panel opens with a risk score and a plain-language breakdown of what was found — suspicious links, manipulation tactics, embedded IPs, and other extracted and relevant data that may help analyze a security incident for a SOC analyst in a SOC environment.

You can also paste text directly into the panel at any time, without needing to select anything on a page first.

## What it looks for

At a high level, the extension checks for the kinds of patterns analysts already look for manually:

- **Suspicious or disguised links** — things like mismatched domains, link shorteners, unusual hosting patterns, or links designed to look like a trusted brand.
- **Manipulation and pressure tactics** — urgent language, fake account warnings, requests for money or credentials, and impersonation of executives or known brands.
- **Other technical indicators** — raw IP addresses, email addresses, and encoded text that might be worth a second look.

These signals are combined into an overall risk rating to help prioritize what needs attention first.

## Privacy

The extension does not make any network calls. The text being analyzed is processed entirely on-device and only kept in temporary browser memory long enough to display results.

## Limitations

This is a triage aid, not a final verdict. It's built to catch common, well-known patterns — it won't catch every phishing attempt, and it may occasionally flag legitimate messages that happen to use similar language. It works best as one input alongside sender reputation, email headers, and your team's existing playbooks.
