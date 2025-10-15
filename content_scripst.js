// content_script.js

(async function () {
  // small delay to let DOM load / favicon load
  await new Promise(res => setTimeout(res, 250));

  const url = window.location.href;
  const hostname = window.location.hostname;

  const reasons = [];

  // 1) HTTPS check
  if (location.protocol !== 'https:') {
    reasons.push('Page is not HTTPS');
  }

  // 2) Favicon domain mismatch check
  function getFaviconURL() {
    const rels = ['icon', 'shortcut icon', 'apple-touch-icon'];
    const links = Array.from(document.getElementsByTagName('link'));
    for (const l of links) {
      const rel = (l.getAttribute('rel') || '').toLowerCase();
      if (rels.includes(rel) && l.href) return l.href;
    }
    // fallback to /favicon.ico
    return location.origin + '/favicon.ico';
  }

  const faviconURL = getFaviconURL();
  try {
    const faviconHost = new URL(faviconURL, location.href).hostname;
    if (faviconHost && faviconHost !== hostname) {
      reasons.push('Favicon domain mismatch');
    }
  } catch (e) {
    // ignore parse errors
  }

  // 3) Form action mismatch and suspicious posting
  const forms = Array.from(document.forms);
  let suspiciousForm = false;
  forms.forEach(f => {
    const action = f.getAttribute('action') || '';
    if (!action) {
      // forms with no action post to same origin — OK
      return;
    }
    try {
      const actionUrl = new URL(action, location.href);
      if (actionUrl.hostname !== hostname) {
        suspiciousForm = true;
        reasons.push(`Form posts to different host: ${actionUrl.hostname}`);
      }
      // suspicious if action uses http while page is https
      if (location.protocol === 'https:' && actionUrl.protocol !== 'https:') {
        reasons.push('Form posts over insecure protocol');
      }
    } catch (e) {
      // malformed action might be suspicious
      reasons.push('Form action is malformed or unusual');
    }
  });

  // 4) DOM keyword heuristics (lack of domain name, deceptive words)
  const suspiciousKeywords = ['login here', 'verify account', 'update payment', 'enter credentials', 'confirm your account', 'account verification', 'sign in to continue', 'secure login'];
  const bodyText = document.body ? document.body.innerText.toLowerCase() : '';
  const foundKeywords = suspiciousKeywords.filter(k => bodyText.includes(k));
  if (foundKeywords.length) {
    reasons.push(`Suspicious phrases found: ${foundKeywords.slice(0,3).join(', ')}`);
  }

  // 5) Title vs domain mismatch (site title contains other brand)
  const title = (document.title || '').toLowerCase();
  const domainParts = hostname.replace(/^www\./, '').split('.');
  // if title contains well-known brand names not in domain, flag (minimal list)
  const brands = ['google', 'facebook', 'amazon', 'microsoft', 'paypal', 'netflix'];
  const brandHits = brands.filter(b => title.includes(b) && !hostname.includes(b));
  if (brandHits.length) {
    reasons.push(`Page title references brand(s) ${brandHits.join(', ')} but domain doesn't match`);
  }

  // 6) Embedded frames that may host forms
  const iframes = document.getElementsByTagName('iframe');
  if (iframes.length > 0) {
    reasons.push(`Page contains ${iframes.length} iframe(s)`);
  }

  // 7) Domain length/number obfuscation & Punycode
  if (hostname.length > 30) reasons.push('Unusually long domain name');
  if (hostname.includes('xn--')) reasons.push('Punycode (IDN) domain detected');

  // 8) Check for suspicious top-level path tokens e.g., /signin-security /account-verify
  const suspiciousPaths = ['/verify', '/account', '/signin', '/login', '/confirm', '/secure'];
  if (suspiciousPaths.some(p => location.pathname.toLowerCase().includes(p))) {
    // this is not by itself malicious, but combined with other signals it's meaningful
    reasons.push('URL path contains login/verify keywords');
  }

  // Combine heuristic score
  const weight = {
    'Page is not HTTPS': 3,
    'Favicon domain mismatch': 4,
    'Form posts to different host': 5,
    'Form posts over insecure protocol': 4,
    'Form action is malformed or unusual': 2,
    'Suspicious phrases found': 3,
    'Page contains iframe(s)': 2,
    'Unusually long domain name': 1,
    'Punycode (IDN) domain detected': 3,
    'URL path contains login/verify keywords': 1,
    'Page title references brand': 4
  };

  // compute score
  let score = 0;
  // simple map by checking which reason strings exist (approx)
  reasons.forEach(r => {
    for (const key in weight) {
      if (r.toLowerCase().includes(key.toLowerCase().split(' ')[0])) {
        score += weight[key];
        break;
      }
    }
  });

  // More robust score: presence of certain phrases maps to specific weights
  if (reasons.some(r => r.includes('Form posts to different host'))) score += 5;
  if (reasons.some(r => r.includes('Favicon domain mismatch'))) score += 3;
  if (reasons.some(r => r.includes('Page is not HTTPS'))) score += 3;
  if (reasons.some(r => r.includes('Punycode'))) score += 3;
  if (reasons.some(r => r.includes('Suspicious phrases found'))) score += 2;

  // Determine verdict
  // score thresholds: <3 safe, 3-6 suspicious, >6 phishing
  let verdict = 'safe';
  if (score >= 7) verdict = 'phishing';
  else if (score >= 3) verdict = 'suspicious';

  // Send the result to background
  chrome.runtime.sendMessage({
    type: 'phisheyeResult',
    payload: { verdict, reasons, url }
  }, function (resp) {
    // no-op
  });

  // Optionally show lightweight banner on page when phishing detected
  if (verdict === 'phishing') {
    const banner = document.createElement('div');
    banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#e74c3c;color:white;padding:10px 12px;z-index:999999;font-family:Arial,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,0.2);';
    banner.innerText = 'PhishEye Warning — This page looks like a phishing page. Do NOT enter credentials.';
    const closeBtn = document.createElement('button');
    closeBtn.innerText = 'Dismiss';
    closeBtn.style.cssText = 'margin-left:12px;background:#fff;color:#e74c3c;border:none;padding:6px 8px;border-radius:4px;cursor:pointer;';
    closeBtn.onclick = () => banner.remove();
    banner.appendChild(closeBtn);
    document.documentElement.prepend(banner);
  }

})();
