// URL and Content Security Analyzer for QRShield

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'cutt.ly', 'rebrand.ly', 'v.gd', 'shorturl.at',
  'tiny.cc', 'rb.gy', 'shorte.st', 'bc.vc', 'clck.ru'
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'loan', 'buzz', 'rest', 'work', 'tokyo',
  'fit', 'surf', 'gq', 'cf', 'ml', 'tk', 'ga', 'icu', 'cam',
  'monster', 'quest', 'racing', 'country', 'stream', 'download', 'win'
]);

const MONITORED_BRANDS = [
  { name: 'PayPal', domain: 'paypal.com' },
  { name: 'Google', domain: 'google.com' },
  { name: 'Apple', domain: 'apple.com' },
  { name: 'Microsoft', domain: 'microsoft.com' },
  { name: 'Amazon', domain: 'amazon.com' },
  { name: 'Netflix', domain: 'netflix.com' },
  { name: 'Facebook', domain: 'facebook.com' },
  { name: 'Instagram', domain: 'instagram.com' },
  { name: 'WhatsApp', domain: 'whatsapp.com' },
  { name: 'Chase Bank', domain: 'chase.com' },
  { name: 'Wells Fargo', domain: 'wellsfargo.com' },
  { name: 'Bank of America', domain: 'bankofamerica.com' },
  { name: 'Binance', domain: 'binance.com' },
  { name: 'Coinbase', domain: 'coinbase.com' },
  { name: 'Steam', domain: 'steampowered.com' },
  { name: 'Telegram', domain: 'telegram.org' }
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'security', 'wallet',
  'recover', 'password', 'account-update', 'banking', 'free-gift',
  'claim-reward', 'airdrop', 'bonus', 'update-billing', 'authenticate',
  'confirm-identity', 'urgent', 'suspended'
];

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^\[?[a-fA-F0-9:]+\]?$/;

/**
 * Detect the type of content stored in the QR code
 */
export function detectContentType(rawContent) {
  const trimmed = (rawContent || '').trim();
  if (!trimmed) return { type: 'EMPTY', value: '' };

  if (/^https?:\/\//i.test(trimmed)) {
    return { type: 'URL', value: trimmed };
  }
  if (/^WIFI:/i.test(trimmed)) {
    return { type: 'WIFI', value: trimmed };
  }
  if (/^mailto:/i.test(trimmed)) {
    return { type: 'EMAIL', value: trimmed };
  }
  if (/^tel:/i.test(trimmed)) {
    return { type: 'TEL', value: trimmed };
  }
  if (/^(smsto|sms):/i.test(trimmed)) {
    return { type: 'SMS', value: trimmed };
  }
  // Check if it looks like a domain without protocol (e.g., www.example.com or example.com/path)
  if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$/i.test(trimmed)) {
    return { type: 'URL', value: `https://${trimmed}` };
  }

  return { type: 'TEXT', value: trimmed };
}

/**
 * Analyze a URL for security risks and malicious patterns
 */
export function analyzeUrl(inputUrl) {
  let parsed;
  try {
    parsed = new URL(inputUrl);
  } catch {
    return {
      isValidUrl: false,
      riskScore: 60,
      verdict: 'SUSPICIOUS',
      summary: 'The provided content resembles a malformed or invalid URL.',
      findings: [
        {
          severity: 'danger',
          title: 'Malformed URL',
          description: 'The URL structure could not be parsed safely by standard web standards.'
        }
      ]
    };
  }

  const findings = [];
  let score = 0;

  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const rawUrl = parsed.href;

  // 1. Protocol check
  if (protocol === 'https:') {
    findings.push({
      severity: 'safe',
      title: 'HTTPS Encryption Enabled',
      description: 'The destination uses TLS/SSL encryption for secure transmission.'
    });
  } else if (protocol === 'http:') {
    score += 20;
    findings.push({
      severity: 'warning',
      title: 'Unencrypted Connection (HTTP)',
      description: 'The link uses HTTP instead of HTTPS. Data entered on this website can be intercepted or altered by attackers on public networks.'
    });
  } else if (['javascript:', 'data:', 'file:', 'blob:'].includes(protocol)) {
    score += 55;
    findings.push({
      severity: 'danger',
      title: 'High-Risk Protocol Detected',
      description: `The URL uses a dangerous protocol (${protocol}) which can execute arbitrary code or load unverified local files.`
    });
  }

  // 2. IP address as host check
  const isIp = IPV4_REGEX.test(hostname) || IPV6_REGEX.test(hostname);
  if (isIp) {
    score += 40;
    findings.push({
      severity: 'danger',
      title: 'Direct IP Address Destination',
      description: `The URL points to a raw IP address (${hostname}) instead of a verified registered domain. This is frequently used by phishing kits and command-and-control servers.`
    });
  }

  // 3. Shortened URL check
  if (SHORTENER_DOMAINS.has(hostname) || Array.from(SHORTENER_DOMAINS).some(d => hostname.endsWith('.' + d))) {
    score += 25;
    findings.push({
      severity: 'warning',
      title: 'Obfuscated Link (URL Shortener)',
      description: `The link uses a URL shortening service (${hostname}) to hide its true destination. Attackers frequently use shorteners to mask malicious landing pages.`
    });
  }

  // 4. Punycode / IDN Homograph check (e.g. xn--)
  if (hostname.includes('xn--')) {
    score += 35;
    findings.push({
      severity: 'danger',
      title: 'Punycode / Homograph Impersonation Risk',
      description: 'The domain uses internationalized characters (punycode). Attackers use visually identical letters (e.g., Cyrillic "а" instead of Latin "a") to spoof legitimate sites.'
    });
  }

  // 5. Misleading credentials / @ symbol in URL
  if (parsed.username || parsed.password || rawUrl.includes('@')) {
    score += 45;
    findings.push({
      severity: 'danger',
      title: 'Misleading Authentication Structure (@ Trick)',
      description: 'The URL contains an "@" sign, which can deceive users into thinking they are visiting one domain while actually sending them to another.'
    });
  }

  // 6. Suspicious / High-risk TLD
  const domainParts = hostname.split('.');
  const tld = domainParts[domainParts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 20;
    findings.push({
      severity: 'warning',
      title: 'High-Risk Top Level Domain (TLD)',
      description: `The domain ends with .${tld}, a TLD statistically associated with high rates of spam, disposable domains, and phishing scams.`
    });
  }

  // 7. Brand Impersonation / Typosquatting
  for (const brand of MONITORED_BRANDS) {
    const brandLower = brand.name.toLowerCase().replace(/\s+/g, '');
    const officialDomain = brand.domain.toLowerCase();

    const mentionsBrand = hostname.includes(brandLower);
    const isOfficial = hostname === officialDomain || hostname.endsWith('.' + officialDomain);

    if (mentionsBrand && !isOfficial) {
      score += 50;
      findings.push({
        severity: 'danger',
        title: `Possible Brand Impersonation (${brand.name})`,
        description: `The domain references "${brand.name}", but does NOT belong to the official domain (${brand.domain}). This strongly indicates a credential theft or phishing site.`
      });
      break;
    }
  }

  // 8. Excessive Subdomains (Deep chaining)
  if (domainParts.length > 4 && !isIp) {
    score += 15;
    findings.push({
      severity: 'warning',
      title: 'Excessive Subdomain Chaining',
      description: 'The URL has multiple layers of subdomains, which is often used to camouflage attacker-controlled infrastructure.'
    });
  }

  // 9. Suspicious keywords in path or query
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => pathname.includes(kw) || search.includes(kw));
  if (foundKeywords.length > 0) {
    score += 15;
    findings.push({
      severity: 'warning',
      title: 'Sensitive Action Keywords Detected',
      description: `The URL contains keywords often targeted by phishers: [${foundKeywords.slice(0, 3).join(', ')}]. Exercise caution if prompted for login or personal details.`
    });
  }

  // 10. Non-standard web ports
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    score += 15;
    findings.push({
      severity: 'warning',
      title: `Non-Standard Port (:${parsed.port})`,
      description: `The URL connects to a non-standard port (${parsed.port}) rather than the standard web ports (80/443).`
    });
  }

  // Clamp score
  score = Math.min(100, Math.max(0, score));

  // Determine overall verdict
  let verdict = 'SAFE';
  let summary = 'No high-risk indicators were identified. The destination appears standard, but always exercise healthy digital caution.';

  if (score >= 50) {
    verdict = 'DANGEROUS';
    summary = 'High-risk security warnings detected! This destination shows multiple indicators of phishing, malware, or brand spoofing.';
  } else if (score >= 20) {
    verdict = 'SUSPICIOUS';
    summary = 'Potential warning signs detected. Review the destination carefully before proceeding or submitting any sensitive information.';
  }

  return {
    isValidUrl: true,
    riskScore: score,
    verdict,
    summary,
    parsedUrl: {
      href: parsed.href,
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      pathname: parsed.pathname,
      search: parsed.search,
      port: parsed.port || (protocol === 'https:' ? '443' : '80')
    },
    findings
  };
}

/**
 * General analyzer for any QR payload (URL, text, WiFi, etc.)
 */
export function analyzePayload(rawContent) {
  const detected = detectContentType(rawContent);

  if (detected.type === 'URL') {
    const urlAnalysis = analyzeUrl(detected.value);
    return {
      contentType: 'URL',
      rawContent,
      ...urlAnalysis
    };
  }

  if (detected.type === 'WIFI') {
    return {
      contentType: 'WIFI',
      rawContent,
      riskScore: 25,
      verdict: 'SUSPICIOUS',
      summary: 'This QR code configures a Wi-Fi network connection automatically. Untrusted Wi-Fi can expose your device traffic to man-in-the-middle interception.',
      findings: [
        {
          severity: 'warning',
          title: 'Wi-Fi Network Configuration',
          description: 'Connecting to unfamiliar Wi-Fi networks may allow local network eavesdropping or redirection.'
        }
      ]
    };
  }

  return {
    contentType: detected.type,
    rawContent,
    riskScore: 5,
    verdict: 'SAFE',
    summary: `QR code contains plain ${detected.type.toLowerCase()} content. No automated web redirection detected.`,
    findings: [
      {
        severity: 'safe',
        title: `Decoded ${detected.type} Content`,
        description: 'The QR code contains text or direct contact data without an active web URL link.'
      }
    ]
  };
}

