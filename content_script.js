// service_worker.js
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: '' });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'phisheyeResult') {
    const { verdict, reasons, url } = message.payload;

    // Save latest result
    chrome.storage.local.set({ lastResult: { verdict, reasons, url, time: Date.now() } });

    // Set badge text & color
    if (verdict === 'safe') {
      chrome.action.setBadgeText({ text: 'OK' });
      chrome.action.setBadgeBackgroundColor({ color: '#2ecc71' }); // green
    } else if (verdict === 'suspicious') {
      chrome.action.setBadgeText({ text: '!' });
      chrome.action.setBadgeBackgroundColor({ color: '#f1c40f' }); // yellow
    } else { // phishing
      chrome.action.setBadgeText({ text: 'X' });
      chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' }); // red
    }

    sendResponse({ received: true });
  }
  return true;
});
