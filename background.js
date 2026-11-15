// Page Pilot background service worker.
// Clicking the toolbar icon (or Alt+Shift+P) does two things:
//   1. opens the Side Panel
//   2. gives Chrome's temporary "activeTab" grant for the current tab only
//      (no install-time website permission is needed for this "allow once" path).

chrome.runtime.onInstalled.addListener(() => {
  // We handle the click ourselves so that activeTab is granted on every click.
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
});

chrome.action.onClicked.addListener((tab) => {
  // Must be called synchronously inside the user gesture.
  chrome.sidePanel.open({ windowId: tab.windowId }).catch((e) => console.warn('sidePanel.open failed', e));
  // Tell an already-open panel that this tab is now accessible once.
  chrome.runtime.sendMessage({ type: 'activeTabGranted', tabId: tab.id }).catch(() => {});
});
