/**
 * ScamCheck — URL Safety Checker
 * Combines local heuristics + Google Safe Browsing + VirusTotal
 */

// ===== SUSPICIOUS PATTERNS =====
const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.club', '.work', '.buzz', '.surf', '.monster',
    '.icu', '.cam', '.rest', '.beauty', '.hair', '.skin', '.quest',
    '.click', '.link', '.gdn', '.loan', '.racing', '.download',
    '.win', '.bid', '.stream', '.trade', '.date', '.faith',
    '.review', '.science', '.party', '.cricket', '.accountant',
    '.tk', '.ml', '.ga', '.cf', '.gq'
];

const SCAM_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'banking', 'paypal', 'amazon',
    'apple', 'microsoft', 'google', 'facebook', 'netflix', 'support',
    'helpdesk', 'wallet', 'crypto', 'bitcoin', 'claim', 'reward',
    'prize', 'winner', 'lucky', 'free-gift', 'giveaway', 'offer',
    'limited-time', 'urgent', 'suspend', 'blocked', 'unauthorized',
    'password', 'credential', 'ssn', 'social-security'
];

const LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
    'twitter.com', 'x.com', 'instagram.com', 'linkedin.com', 'reddit.com',
    'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'paypal.com', 'netflix.com', 'spotify.com', 'whatsapp.com',
    'zoom.us', 'dropbox.com', 'adobe.com', 'wordpress.org', 'mozilla.org',
    'cloudflare.com', 'aws.amazon.com', 'docs.google.com', 'drive.google.com',
    'mail.google.com', 'outlook.com', 'live.com', 'office.com',
    'yahoo.com', 'bing.com', 'duckduckgo.com', 'archive.org',
    'medium.com', 'notion.so', 'figma.com', 'canva.com',
    'twitch.tv', 'discord.com', 'telegram.org', 'signal.org'
];

const BRAND_TYPOSQUATS = {
    'google': ['g00gle', 'gooogle', 'googie', 'googe', 'googl3', 'goolge'],
    'facebook': ['faceb00k', 'facebok', 'faceboook', 'facebk', 'faecbook'],
    'amazon': ['amaz0n', 'amazom', 'arnazon', 'amazonn', 'amzon'],
    'apple': ['app1e', 'appie', 'aple', 'applle'],
    'microsoft': ['micr0soft', 'mircosoft', 'microsft', 'microsoftt'],
    'paypal': ['paypa1', 'paypai', 'paypl', 'payypal', 'peypal'],
    'netflix': ['netf1ix', 'netflixx', 'netfIix', 'netflx'],
    'instagram': ['instagran', 'lnstagram', 'instgram', 'instagarm'],
    'whatsapp': ['whatsap', 'watsapp', 'whatsaap', 'whatssapp'],
    'twitter': ['twiter', 'twltter', 'twtter', 'twlttr']
};

// ===== URL PARSING =====
function parseURL(input) {
    let url = input.trim();
    
    // Add protocol if missing
    if (!/^https?:\/\//i.test(url)) {
        url = 'http://' + url;
    }

    try {
        const parsed = new URL(url);
        return {
            full: parsed.href,
            hostname: parsed.hostname.toLowerCase(),
            pathname: parsed.pathname,
            search: parsed.search,
            protocol: parsed.protocol,
            port: parsed.port,
            isValid: true
        };
    } catch {
        return { isValid: false };
    }
}

function extractDomain(hostname) {
    // Remove www prefix
    let domain = hostname.replace(/^www\./, '');
    return domain;
}

function getRegistrableDomain(hostname) {
    // Simple extraction: last two parts for most TLDs, last three for co.uk etc.
    const parts = hostname.split('.');
    const ccSLDs = ['co', 'com', 'org', 'net', 'gov', 'edu', 'ac'];
    
    if (parts.length >= 3 && ccSLDs.includes(parts[parts.length - 2])) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

// ===== HEURISTIC CHECKS =====
function runHeuristics(parsed) {
    const results = [];
    const hostname = parsed.hostname;
    const domain = extractDomain(hostname);
    const registrable = getRegistrableDomain(domain);
    const fullURL = parsed.full.toLowerCase();

    // 1. IP address as hostname
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
        results.push({
            check: 'IP Address URL',
            status: 'fail',
            detail: 'This URL uses a raw IP address instead of a domain name — legitimate sites almost never do this.',
            weight: 5
        });
    }

    // 2. Suspicious TLD
    const tld = '.' + domain.split('.').pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
        results.push({
            check: 'Suspicious domain extension',
            status: 'warn',
            detail: `The "${tld}" extension is commonly used by scam and spam websites.`,
            weight: 2
        });
    }

    // 3. Excessive subdomains (more than 3 levels)
    const subdomainCount = hostname.split('.').length;
    if (subdomainCount > 4) {
        results.push({
            check: 'Excessive subdomains',
            status: 'warn',
            detail: `This URL has ${subdomainCount - 2} subdomains — scammers often stack subdomains to hide the real destination.`,
            weight: 2
        });
    }

    // 4. Known scam keywords in URL
    const matchedKeywords = SCAM_KEYWORDS.filter(kw => {
        // Check if keyword is in domain part (more suspicious) or path
        return domain.includes(kw) && !LEGITIMATE_DOMAINS.some(ld => registrable === ld);
    });
    
    if (matchedKeywords.length >= 2) {
        results.push({
            check: 'Suspicious keywords in URL',
            status: 'warn',
            detail: `The domain contains keywords often used in phishing: "${matchedKeywords.slice(0, 3).join('", "')}"`,
            weight: 2
        });
    } else if (matchedKeywords.length === 1) {
        results.push({
            check: 'Suspicious keyword in URL',
            status: 'warn',
            detail: `The domain contains "${matchedKeywords[0]}" which is sometimes used in phishing URLs.`,
            weight: 1
        });
    }

    // 5. Brand typosquatting detection
    for (const [brand, typos] of Object.entries(BRAND_TYPOSQUATS)) {
        for (const typo of typos) {
            if (domain.includes(typo)) {
                results.push({
                    check: 'Lookalike domain',
                    status: 'fail',
                    detail: `This domain looks like it's impersonating ${brand.charAt(0).toUpperCase() + brand.slice(1)} — a common phishing technique.`,
                    weight: 4
                });
                break;
            }
        }
        // Also check if brand name is in a non-official domain
        if (domain.includes(brand) && !LEGITIMATE_DOMAINS.some(ld => registrable === ld || registrable.endsWith('.' + ld))) {
            results.push({
                check: 'Brand name in unofficial domain',
                status: 'warn',
                detail: `Contains "${brand}" but is not the official ${brand} website.`,
                weight: 2
            });
        }
    }

    // 6. Very long URL (often used to hide real destination)
    if (parsed.full.length > 200) {
        results.push({
            check: 'Unusually long URL',
            status: 'warn',
            detail: 'This URL is suspiciously long — sometimes used to hide the real destination in the address bar.',
            weight: 1
        });
    }

    // 7. URL contains @ symbol (used to trick browsers)
    if (parsed.full.includes('@')) {
        results.push({
            check: 'Deceptive @ symbol',
            status: 'fail',
            detail: 'The URL contains an "@" symbol which can be used to redirect you to a different site than what appears in the address bar.',
            weight: 5
        });
    }

    // 8. HTTP instead of HTTPS (non-secure)
    if (parsed.protocol === 'http:' && !ipPattern.test(hostname)) {
        results.push({
            check: 'Not secure (HTTP)',
            status: 'warn',
            detail: 'This site doesn\'t use HTTPS encryption. Most legitimate sites use HTTPS.',
            weight: 1
        });
    }

    // 9. Known safe domain check
    if (LEGITIMATE_DOMAINS.some(ld => registrable === ld)) {
        results.push({
            check: 'Known legitimate domain',
            status: 'pass',
            detail: `${registrable} is a well-known, established website.`,
            weight: -3
        });
    }

    // 10. Unusual port
    if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
        results.push({
            check: 'Unusual port number',
            status: 'warn',
            detail: `Uses port ${parsed.port} — legitimate sites typically use standard ports.`,
            weight: 1
        });
    }

    // 11. Homograph attack detection (mixed scripts)
    if (/xn--/.test(hostname)) {
        results.push({
            check: 'Internationalized domain (punycode)',
            status: 'warn',
            detail: 'This domain uses international characters that could be disguising a lookalike URL.',
            weight: 2
        });
    }

    // 12. Data URI or javascript URI
    if (/^(data|javascript):/i.test(parsed.full)) {
        results.push({
            check: 'Dangerous URI scheme',
            status: 'fail',
            detail: 'This is not a normal website link — it could execute code on your device.',
            weight: 5
        });
    }

    // 13. URL shortener detection
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'ow.ly', 'buff.ly', 'rb.gy', 'shorturl.at', 'cutt.ly'];
    if (shorteners.some(s => registrable === s || domain === s)) {
        results.push({
            check: 'URL shortener',
            status: 'warn',
            detail: 'This is a shortened URL — the real destination is hidden. Be cautious about clicking shortened links from unknown sources.',
            weight: 2
        });
    }

    return results;
}

// ===== GOOGLE SAFE BROWSING API =====
async function checkGoogleSafeBrowsing(url) {
    if (!CONFIG.APIS_ENABLED || !CONFIG.GOOGLE_SAFE_BROWSING_KEY) {
        return { available: false, reason: 'API key not configured' };
    }

    try {
        const response = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.GOOGLE_SAFE_BROWSING_KEY}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client: { clientId: 'scamcheck', clientVersion: '1.0.0' },
                    threatInfo: {
                        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        platformTypes: ['ANY_PLATFORM'],
                        threatEntryTypes: ['URL'],
                        threatEntries: [{ url }]
                    }
                })
            }
        );

        if (!response.ok) {
            return { available: false, reason: `API error (${response.status})` };
        }

        const data = await response.json();
        const threats = data.matches || [];

        if (threats.length > 0) {
            const threatTypes = threats.map(t => {
                switch (t.threatType) {
                    case 'SOCIAL_ENGINEERING': return 'phishing/social engineering';
                    case 'MALWARE': return 'malware';
                    case 'UNWANTED_SOFTWARE': return 'unwanted software';
                    default: return 'harmful content';
                }
            });
            return {
                available: true,
                flagged: true,
                threats: [...new Set(threatTypes)],
                detail: `Google Safe Browsing flagged this URL for: ${[...new Set(threatTypes)].join(', ')}`
            };
        }

        return { available: true, flagged: false, detail: 'No threats found in Google Safe Browsing database' };
    } catch (err) {
        return { available: false, reason: 'Network error' };
    }
}

// ===== VIRUSTOTAL API =====
async function checkVirusTotal(url) {
    if (!CONFIG.APIS_ENABLED || !CONFIG.VIRUSTOTAL_KEY) {
        return { available: false, reason: 'API key not configured' };
    }

    try {
        // VirusTotal v3 — URL scan
        const urlId = btoa(url).replace(/=/g, '');
        const response = await fetch(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            {
                headers: { 'x-apikey': CONFIG.VIRUSTOTAL_KEY }
            }
        );

        if (response.status === 404) {
            // URL not in database — submit for scanning
            const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
                method: 'POST',
                headers: {
                    'x-apikey': CONFIG.VIRUSTOTAL_KEY,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: `url=${encodeURIComponent(url)}`
            });

            if (!submitResponse.ok) {
                return { available: false, reason: 'Submission failed' };
            }

            return {
                available: true,
                flagged: false,
                pending: true,
                detail: 'URL submitted to VirusTotal for scanning — no prior results available'
            };
        }

        if (!response.ok) {
            return { available: false, reason: `API error (${response.status})` };
        }

        const data = await response.json();
        const stats = data.data?.attributes?.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = Object.values(stats).reduce((a, b) => a + b, 0);

        if (malicious > 0 || suspicious > 0) {
            return {
                available: true,
                flagged: true,
                malicious,
                suspicious,
                total,
                detail: `${malicious + suspicious} out of ${total} security vendors flagged this URL`
            };
        }

        return {
            available: true,
            flagged: false,
            total,
            detail: `${total} security vendors checked — none flagged this URL`
        };
    } catch (err) {
        return { available: false, reason: 'Network error' };
    }
}

// ===== VERDICT AGGREGATION =====
function aggregateVerdict(heuristics, googleResult, vtResult) {
    let score = 0;
    const details = [];
    let apisUsed = 0;
    let apisAvailable = 0;

    // Heuristic score
    for (const h of heuristics) {
        score += h.weight;
    }

    // Google Safe Browsing
    if (googleResult.available) {
        apisAvailable++;
        apisUsed++;
        if (googleResult.flagged) {
            score += 5;
            details.push({ label: 'Google Safe Browsing', value: `⚠️ ${googleResult.detail}`, status: 'fail' });
        } else {
            score -= 1;
            details.push({ label: 'Google Safe Browsing', value: '✅ No threats found', status: 'pass' });
        }
    } else {
        details.push({ label: 'Google Safe Browsing', value: `⏭️ Skipped (${googleResult.reason})`, status: 'skip' });
    }

    // VirusTotal
    if (vtResult.available) {
        apisAvailable++;
        apisUsed++;
        if (vtResult.flagged) {
            score += vtResult.malicious >= 3 ? 4 : 2;
            details.push({ label: 'VirusTotal', value: `⚠️ ${vtResult.detail}`, status: 'fail' });
        } else {
            score -= 1;
            details.push({ label: 'VirusTotal', value: vtResult.pending ? '⏳ Scanning (no prior results)' : '✅ Clean', status: vtResult.pending ? 'skip' : 'pass' });
        }
    } else {
        details.push({ label: 'VirusTotal', value: `⏭️ Skipped (${vtResult.reason})`, status: 'skip' });
    }

    // Add heuristic details
    for (const h of heuristics) {
        details.push({ label: h.check, value: h.detail, status: h.status });
    }

    // Determine verdict
    let verdict, reason;
    
    if (score >= 5) {
        verdict = 'scam';
        const topIssue = heuristics.find(h => h.status === 'fail') || heuristics.find(h => h.weight >= 2) || heuristics[0];
        reason = topIssue 
            ? topIssue.detail 
            : (googleResult.flagged ? googleResult.detail : vtResult.flagged ? vtResult.detail : 'Multiple red flags detected — this URL is very likely dangerous.');
    } else if (score >= 2) {
        verdict = 'suspicious';
        const topIssue = heuristics.find(h => h.status === 'warn') || heuristics[0];
        reason = topIssue
            ? topIssue.detail + ' Proceed with caution.'
            : 'Some warning signs detected — be careful with this link.';
    } else {
        verdict = 'safe';
        const safeCheck = heuristics.find(h => h.status === 'pass');
        reason = safeCheck
            ? safeCheck.detail + ' No issues found.'
            : 'No red flags detected. This link appears to be safe.';
    }

    return {
        verdict,
        reason,
        score,
        details,
        apisUsed,
        limitedCheck: apisUsed === 0
    };
}

// ===== MAIN CHECK FUNCTION =====
async function checkURL() {
    const input = document.getElementById('url-input');
    const btn = document.getElementById('check-btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoading = btn.querySelector('.btn-loading');
    const resultCard = document.getElementById('result-card');
    const errorMsg = document.getElementById('error-msg');

    // Reset
    resultCard.hidden = true;
    errorMsg.hidden = true;
    resultCard.className = 'result-card';

    const rawURL = input.value.trim();
    if (!rawURL) {
        showError('Please paste a URL to check.');
        input.focus();
        return;
    }

    // Parse URL
    const parsed = parseURL(rawURL);
    if (!parsed.isValid) {
        showError('That doesn\'t look like a valid URL. Try pasting the full link including http:// or https://');
        return;
    }

    // Show loading
    btn.disabled = true;
    btnText.hidden = true;
    btnLoading.hidden = false;

    try {
        // Run all checks
        const heuristics = runHeuristics(parsed);
        const [googleResult, vtResult] = await Promise.all([
            checkGoogleSafeBrowsing(parsed.full),
            checkVirusTotal(parsed.full)
        ]);

        const result = aggregateVerdict(heuristics, googleResult, vtResult);
        displayResult(result);
    } catch (err) {
        showError('Something went wrong while checking. Please try again.');
        console.error('Check error:', err);
    } finally {
        btn.disabled = false;
        btnText.hidden = false;
        btnLoading.hidden = true;
    }
}

// ===== DISPLAY FUNCTIONS =====
function displayResult(result) {
    const card = document.getElementById('result-card');
    const badge = document.getElementById('verdict-badge');
    const icon = document.getElementById('verdict-icon');
    const text = document.getElementById('verdict-text');
    const reason = document.getElementById('verdict-reason');
    const summary = document.getElementById('checks-summary');
    const details = document.getElementById('check-details');

    // Set verdict class
    card.className = `result-card ${result.verdict}`;

    // Badge
    const verdicts = {
        safe: { icon: '✅', text: 'Safe' },
        suspicious: { icon: '⚠️', text: 'Suspicious' },
        scam: { icon: '🚨', text: 'Dangerous' }
    };
    icon.textContent = verdicts[result.verdict].icon;
    text.textContent = verdicts[result.verdict].text;

    // Reason
    reason.textContent = result.reason;

    // Limited check notice
    summary.innerHTML = '';
    if (result.limitedCheck) {
        summary.innerHTML = `
            <div class="limited-notice">
                ℹ️ Limited check — using local heuristics only (no API keys configured)
            </div>
        `;
    }

    // Check tags
    const tagStatuses = { pass: '✓', warn: '!', fail: '✗', skip: '–' };
    const tags = result.details
        .filter(d => d.status !== 'skip')
        .map(d => `<span class="check-tag ${d.status}">${tagStatuses[d.status]} ${d.label}</span>`)
        .join('');
    summary.innerHTML += tags;

    // Detailed breakdown
    details.innerHTML = result.details
        .map(d => `
            <div class="detail-item">
                <span class="detail-label">${d.label}:</span> ${d.value}
            </div>
        `)
        .join('');

    card.hidden = false;
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showError(msg) {
    const errorEl = document.getElementById('error-msg');
    errorEl.textContent = msg;
    errorEl.hidden = false;
}
