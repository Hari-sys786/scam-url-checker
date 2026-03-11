# Test Results

| # | URL | Label | Expected | Actual | Score | Result |
|---|-----|-------|----------|--------|-------|--------|
| 1 | `https://wikipedia.org` | Wikipedia - known safe | safe | safe | -3 | ✅ Pass |
| 2 | `https://bbc.com/news` | BBC News - known safe | safe | safe | -3 | ✅ Pass |
| 3 | `https://github.com` | GitHub - known safe | safe | safe | -3 | ✅ Pass |
| 4 | `https://google.com` | Google - known safe | safe | safe | -3 | ✅ Pass |
| 5 | `https://stackoverflow.com/questions` | StackOverflow - known safe | safe | safe | -3 | ✅ Pass |
| 6 | `http://192.168.1.100/login/paypal` | IP-based phishing URL | scam | scam | 5 | ✅ Pass |
| 7 | `http://g00gle-login.xyz/verify` | Google typosquat + suspicious TLD | scam | scam | 8 | ✅ Pass |
| 8 | `http://amaz0n-secure-verify.tk/account` | Amazon typosquat + .tk TLD | scam | scam | 9 | ✅ Pass |
| 9 | `http://paypa1-verification.club/login` | PayPal typosquat + .club TLD | scam | scam | 8 | ✅ Pass |
| 10 | `http://secure.login.verify.account.microsoft.com.evil.xyz/update` | Excessive subdomains + brand impersonation | scam | scam | 9 | ✅ Pass |
| 11 | `http://free-prizes-winner.xyz` | Suspicious TLD + scam keywords | scam | scam | 5 | ✅ Pass |
| 12 | `http://check-your-account-now.top` | Suspicious TLD + urgency keywords | suspicious | suspicious | 4 | ✅ Pass |
| 13 | `https://bit.ly/3xYz123` | URL shortener - hidden destination | suspicious | suspicious | 2 | ✅ Pass |
| 14 | `https://tinyurl.com/abc123` | TinyURL shortener | suspicious | suspicious | 2 | ✅ Pass |
| 15 | `https://example.co.uk` | Legitimate .co.uk domain | safe | safe | N/A | ✅ Pass |
| 16 | `https://münchen.de` | International TLD (IDN) - punycode triggers caution | suspicious | suspicious | 2 | ✅ Pass |
| 17 | `http://xn--mnchen-3ya.de` | Punycode domain | suspicious | suspicious | 3 | ✅ Pass |
| 18 | `https://user@evil.com` | Deceptive @ symbol in URL | scam | scam | 5 | ✅ Pass |

**Summary:** 18/18 passed

All tests run with heuristics only (no API keys).
