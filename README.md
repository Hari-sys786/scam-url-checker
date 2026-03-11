# 🛡️ ScamCheck — Is This Link Safe?

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![GitHub Pages](https://img.shields.io/badge/demo-live-green.svg)](https://panda-dev.github.io/scam-url-checker/)

**Free, no-login web app that tells you if a link is safe or dangerous — in plain English.** Paste any suspicious URL and get an instant SAFE / SUSPICIOUS / DANGEROUS verdict with a clear explanation anyone can understand.

## How It Works

ScamCheck runs three layers of analysis on every URL:

1. **Local heuristics** — checks for IP-based URLs, suspicious domain extensions (.xyz, .tk, etc.), excessive subdomains, brand typosquatting, scam keyword patterns, deceptive `@` symbols, and URL shorteners
2. **Google Safe Browsing** — queries Google's threat database for known phishing, malware, and social engineering sites
3. **VirusTotal** — cross-references 70+ security vendors for additional threat intelligence

All signals are combined into a single color-coded verdict. If APIs are unavailable, heuristics alone are used with a notice.

## Setup

1. Clone: `git clone https://github.com/panda-dev/scam-url-checker.git`
2. Open `index.html` in your browser — works immediately with heuristic checks
3. *(Optional)* Add API keys in `config.js` for enhanced checking:
   - [Google Safe Browsing](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) — free, 10K requests/day
   - [VirusTotal](https://www.virustotal.com/gui/join-us) — free account, 500 requests/day

## Contributing

PRs welcome! Ideas: add more heuristic patterns, improve typosquat detection, support email text analysis, add browser extension wrapper.

## License

MIT — use it however you want.
