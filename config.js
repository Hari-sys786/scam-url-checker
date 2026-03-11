/**
 * ScamCheck Configuration
 * 
 * For local development, replace the placeholder keys below.
 * For production (GitHub Pages), these are loaded as-is.
 * 
 * Get your free API keys:
 * - Google Safe Browsing: https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com
 * - VirusTotal: https://www.virustotal.com/gui/join-us (free account → API key in profile)
 */

const CONFIG = {
    // Google Safe Browsing API v4 (free: 10,000 requests/day)
    GOOGLE_SAFE_BROWSING_KEY: '',

    // VirusTotal API v3 (free: 4 requests/minute, 500/day)
    VIRUSTOTAL_KEY: '',

    // Set to true to enable API calls (requires valid keys above)
    APIS_ENABLED: false,

    // Heuristic-only mode works without any API keys
    HEURISTIC_ONLY: true
};
