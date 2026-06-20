const MENU_ID = "soc-selection-guard-analyze";
const STORAGE_KEY = "lastSelection";
const STORAGE_TS = "lastSelectionAt";

async function ensureContextMenu() {
  await chrome.contextMenus.removeAll();
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Analyze selection for phishing / SE signals (local)",
    contexts: ["selection"],
  });
}

chrome.runtime.onInstalled.addListener(() => {
  ensureContextMenu();
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
});

chrome.runtime.onStartup.addListener(() => {
  ensureContextMenu();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !tab?.windowId) return;
  const text = (info.selectionText || "").trim();
  await chrome.storage.session.set({
    [STORAGE_KEY]: text,
    [STORAGE_TS]: Date.now(),
  });
  try {
    await chrome.sidePanel.open({ windowId: tab.windowId });
  } catch (e) {
    console.warn("SOC Selection Guard: side panel open failed", e);
  }
});
