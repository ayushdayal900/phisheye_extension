// popup.js
document.addEventListener('DOMContentLoaded', () => {
  const statusEl = document.getElementById('status');
  const urlEl = document.getElementById('url');
  const reasonsEl = document.getElementById('reasons');
  const openReportBtn = document.getElementById('openReport');
  const trustBtn = document.getElementById('trustPage');

  chrome.storage.local.get(['lastResult', 'trustedHosts'], (data) => {
    const last = data.lastResult || null;
    const trusted = data.trustedHosts || {};

    if (!last) {
      statusEl.innerText = 'No data yet — open a page to analyze.';
      return;
    }
    urlEl.innerText = last.url;
    const hostname = (new URL(last.url)).hostname;
    // trusted check
    if (trusted[hostname]) {
      statusEl.innerText = 'Trusted (user)';
      statusEl.style.color = '#2ecc71';
      reasonsEl.innerHTML = `<li>Marked trusted on ${new Date(trusted[hostname]).toLocaleString()}</li>`;
      return;
    }

    if (last.verdict === 'safe') {
      statusEl.innerText = 'Safe ✅';
      statusEl.style.color = '#2ecc71';
    } else if (last.verdict === 'suspicious') {
      statusEl.innerText = 'Suspicious ⚠️';
      statusEl.style.color = '#f1c40f';
    } else {
      statusEl.innerText = 'Phishing ❌';
      statusEl.style.color = '#e74c3c';
    }

    // show reasons
    reasonsEl.innerHTML = '';
    (last.reasons || []).forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsEl.appendChild(li);
    });

    openReportBtn.onclick = () => {
      // copy url to clipboard and open github issue template or mailto
      navigator.clipboard.writeText(last.url);
      alert('URL copied to clipboard — you can paste it into a bug report.');
    };

    trustBtn.onclick = () => {
      chrome.storage.local.get('trustedHosts', (d) => {
        const t = d.trustedHosts || {};
        t[hostname] = Date.now();
        chrome.storage.local.set({ trustedHosts: t }, () => {
          alert('Marked as trusted. Reload the page.');
          window.close();
        });
      });
    };
  });
});
