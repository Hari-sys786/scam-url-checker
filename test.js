/**
 * Automated test runner for ScamCheck heuristics
 * Run with: node test.js
 */

// Load checker functions by evaluating the source
const fs = require('fs');

// Mock CONFIG
global.CONFIG = { APIS_ENABLED: false, HEURISTIC_ONLY: true, GOOGLE_SAFE_BROWSING_KEY: '', VIRUSTOTAL_KEY: '' };

// Mock browser globals
global.btoa = (str) => Buffer.from(str).toString('base64');
global.document = { getElementById: () => ({}) };
global.fetch = async () => ({ ok: false });

// Load checker source
const checkerSource = fs.readFileSync('./checker.js', 'utf8');
eval(checkerSource);

// Test cases
const tests = [
    // === SAFE URLs ===
    { url: 'https://wikipedia.org', expected: 'safe', label: 'Wikipedia - known safe' },
    { url: 'https://bbc.com/news', expected: 'safe', label: 'BBC News - known safe' },
    { url: 'https://github.com', expected: 'safe', label: 'GitHub - known safe' },
    { url: 'https://google.com', expected: 'safe', label: 'Google - known safe' },
    { url: 'https://stackoverflow.com/questions', expected: 'safe', label: 'StackOverflow - known safe' },

    // === SCAM / DANGEROUS URLs ===
    { url: 'http://192.168.1.100/login/paypal', expected: 'scam', label: 'IP-based phishing URL' },
    { url: 'http://g00gle-login.xyz/verify', expected: 'scam', label: 'Google typosquat + suspicious TLD' },
    { url: 'http://amaz0n-secure-verify.tk/account', expected: 'scam', label: 'Amazon typosquat + .tk TLD' },
    { url: 'http://paypa1-verification.club/login', expected: 'scam', label: 'PayPal typosquat + .club TLD' },
    { url: 'http://secure.login.verify.account.microsoft.com.evil.xyz/update', expected: 'scam', label: 'Excessive subdomains + brand impersonation' },

    // === SUSPICIOUS URLs ===
    { url: 'http://free-prizes-winner.xyz', expected: 'scam', label: 'Suspicious TLD + scam keywords' },
    { url: 'http://check-your-account-now.top', expected: 'suspicious', label: 'Suspicious TLD + urgency keywords' },
    { url: 'https://bit.ly/3xYz123', expected: 'suspicious', label: 'URL shortener - hidden destination' },

    // === EDGE CASES ===
    { url: 'https://tinyurl.com/abc123', expected: 'suspicious', label: 'TinyURL shortener' },
    { url: 'https://example.co.uk', expected: 'safe', label: 'Legitimate .co.uk domain' },
    { url: 'https://münchen.de', expected: 'suspicious', label: 'International TLD (IDN) - punycode triggers caution' },
    { url: 'http://xn--mnchen-3ya.de', expected: 'suspicious', label: 'Punycode domain' },
    { url: 'https://user@evil.com', expected: 'scam', label: 'Deceptive @ symbol in URL' },
];

// Run tests
console.log('🛡️  ScamCheck Heuristic Tests\n' + '='.repeat(60));

let passed = 0;
let failed = 0;
const results = [];

for (const test of tests) {
    const parsed = parseURL(test.url);
    if (!parsed.isValid) {
        console.log(`❌ PARSE FAIL | ${test.label} | ${test.url}`);
        failed++;
        results.push({ ...test, actual: 'parse-error', pass: false });
        continue;
    }

    const heuristics = runHeuristics(parsed);
    
    // Mock API results (unavailable)
    const mockApi = { available: false, reason: 'Test mode' };
    const verdict = aggregateVerdict(heuristics, mockApi, mockApi);

    const match = verdict.verdict === test.expected;
    const icon = match ? '✅' : '❌';
    const status = match ? 'PASS' : 'FAIL';
    
    console.log(`${icon} ${status} | ${test.label}`);
    console.log(`   URL: ${test.url}`);
    console.log(`   Expected: ${test.expected} | Got: ${verdict.verdict} (score: ${verdict.score})`);
    if (!match) {
        console.log(`   Heuristics: ${heuristics.map(h => h.check + '(' + h.weight + ')').join(', ') || 'none'}`);
    }
    console.log('');

    if (match) passed++;
    else failed++;
    results.push({ ...test, actual: verdict.verdict, score: verdict.score, pass: match });
}

console.log('='.repeat(60));
console.log(`Results: ${passed} passed, ${failed} failed, ${tests.length} total`);

// Generate test-results.md
let md = '# Test Results\n\n';
md += '| # | URL | Label | Expected | Actual | Score | Result |\n';
md += '|---|-----|-------|----------|--------|-------|--------|\n';
results.forEach((r, i) => {
    md += `| ${i+1} | \`${r.url}\` | ${r.label} | ${r.expected} | ${r.actual} | ${r.score || 'N/A'} | ${r.pass ? '✅ Pass' : '❌ Fail'} |\n`;
});
md += `\n**Summary:** ${passed}/${tests.length} passed\n`;
md += `\nAll tests run with heuristics only (no API keys).\n`;

fs.writeFileSync('./test-results.md', md);
console.log('\n📝 test-results.md generated');

process.exit(failed > 0 ? 1 : 0);
