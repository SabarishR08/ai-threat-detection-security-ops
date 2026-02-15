/**
 * Manifest V3 Service Worker for Suspicious URL Detector
 * OPTIMIZED: Instant pattern-based blocking + async deep scanning
 * 
 * Strategy:
 * 1. Fast pre-check (pattern matching) → instant tab close if suspicious
 * 2. Background deep scan (VT/GSB/PT) → runs after tab close, no user delay
 */

// Cached domain reputation (prevents repeated scanning)
const domainCache = new Map();
const CACHE_TTL = 3600000; // 1 hour
const CACHE_MAX_ENTRIES = 1000; // keep storage bounded for speed
const ACTIVITY_ENDPOINT = "http://localhost:5000/api/tab-activity";
const ACTIVITY_DEBOUNCE_MS = 100; // tighter debounce for faster reactions
let lastActivity = { tabId: null, url: null, when: 0 };

// Instantly suspicious patterns (0.1ms detection)
const INSTANT_BLOCK_PATTERNS = [
    // Common phishing/malware indicators
    /phishing|malware|ransomware|trojan/i,
    // IP addresses (often malicious)
    /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    // Suspicious TLDs
    /\.(ru|cn|work|xyz|top|download|review|trade|pw)$/i,
    // Domain reputation (known bad domains)
    /smartserviceprovider\.duckdns\.org|marquettesavngs\.com|z-mail-webauth\.netlify\.app/i,
    // Port indicators (suspicious non-standard ports)
    /:([5-9]\d{3,})/,
    // Double-dash obfuscation
    /--/,
    // Excessive subdomains (often phishing)
    /^[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\./i,
];

/**
 * Heuristic fast check: common phishing cues in path/host
 * More aggressive to speed demo closes.
 * @param {string} url
 * @returns {boolean}
 */
function isHeuristicallySuspicious(url) {
    try {
        const u = new URL(url);
        const host = u.hostname.toLowerCase();
        const path = (u.pathname + u.search).toLowerCase();
        const keywords = [/login/, /verify/, /update/, /secure/, /account/, /payment/, /wallet/];
        const tlds = [/\.app$/, /\.click$/, /\.link$/, /\.cfd$/, /\.zip$/];
        const manyLabels = (host.split('.').length >= 4);
        const keywordHit = keywords.some(k => k.test(path));
        const tldHit = tlds.some(t => t.test(host));
        return (manyLabels && keywordHit) || (keywordHit && tldHit);
    } catch {
        return false;
    }
}

/**
 * Quick reputation check from cache
 * @param {string} domain - domain to check
 * @returns {string|null} - "Malicious", "Suspicious", or null if unknown
 */
function getCachedReputation(domain) {
    const cached = domainCache.get(domain);
    if (!cached) return null;

    // Check if cache expired
    if (Date.now() - cached.timestamp > CACHE_TTL) {
        domainCache.delete(domain);
        return null;
    }

    return cached.status;
}

/**
 * Store reputation in cache
 * @param {string} domain - domain to cache
 * @param {string} status - "Malicious" or "Safe"
 */
function setCachedReputation(domain, status) {
    const entry = { status, timestamp: Date.now() };
    domainCache.set(domain, entry);
    // persist entry for faster decisions across service-worker restarts
    persistCacheEntry(domain, entry);
    pruneCache();
}

/**
 * Prune in-memory cache to keep it under CACHE_MAX_ENTRIES
 */
function pruneCache() {
    try {
        if (domainCache.size <= CACHE_MAX_ENTRIES) return;
        // sort keys by timestamp ascending and delete oldest
        const entries = Array.from(domainCache.entries());
        entries.sort((a, b) => a[1].timestamp - b[1].timestamp);
        const toRemove = entries.slice(0, entries.length - CACHE_MAX_ENTRIES);
        for (const [k] of toRemove) domainCache.delete(k);
    } catch (e) {
        // ignore
    }
}

/**
 * Persist a single cache entry into chrome.storage.local
 * This keeps the worker able to make instant decisions after restart.
 */
function persistCacheEntry(domain, entry) {
    if (!chrome.storage || !chrome.storage.local) return;
    try {
        chrome.storage.local.get(['domainCache'], (result) => {
            const stored = result.domainCache || {};
            stored[domain] = entry;
            // Optional: prune stored map by timestamp if too large
            const keys = Object.keys(stored);
            if (keys.length > CACHE_MAX_ENTRIES) {
                keys.sort((a, b) => stored[a].timestamp - stored[b].timestamp);
                const keep = keys.slice(keys.length - CACHE_MAX_ENTRIES);
                const newStored = {};
                for (const k of keep) newStored[k] = stored[k];
                chrome.storage.local.set({ domainCache: newStored });
            } else {
                chrome.storage.local.set({ domainCache: stored });
            }
        });
    } catch (e) {
        // ignore storage errors
    }
}

/**
 * Load persisted cache into memory (prune expired entries)
 */
function loadCacheFromStorage() {
    if (!chrome.storage || !chrome.storage.local) return;
    try {
        chrome.storage.local.get(['domainCache'], (result) => {
            const stored = result.domainCache || {};
            const now = Date.now();
            for (const [domain, entry] of Object.entries(stored)) {
                if (now - entry.timestamp <= CACHE_TTL) {
                    domainCache.set(domain, entry);
                }
            }
            pruneCache();
        });
    } catch (e) {
        // ignore
    }
}

/**
 * Sync recent threat lookup results from backend into extension cache.
 * This copies what users search in Threat Lookup into the extension's domain cache.
 */
function syncRecentThreatsFromServer(limit = 50) {
    // Best-effort; don't block anything
    try {
        fetch("http://localhost:5000/api/recent_threats?limit=" + encodeURIComponent(limit), { cache: 'no-store' })
            .then(resp => {
                if (!resp.ok) return null;
                return resp.json();
            })
            .then(data => {
                if (!data || !Array.isArray(data.results)) return;
                for (const entry of data.results) {
                    try {
                        const domain = extractDomain(entry.url || "");
                        if (!domain) continue;
                        const status = entry.status || (entry.details && entry.details.virustotal && entry.details.virustotal.status) || "Unknown";
                        // Map some variants to normalized statuses used by the extension
                        const normalized = (typeof status === 'string') ?
                            (status.charAt(0).toUpperCase() + status.slice(1)) : String(status);
                        setCachedReputation(domain, normalized);
                    } catch (e) {
                        // ignore per-entry errors
                    }
                }
            })
            .catch(() => {});
    } catch (e) {
        // ignore
    }
}

/**
 * Extract domain/IP from URL
 * @param {string} url - full URL
 * @returns {string} - domain or IP
 */
function extractDomain(url) {
    try {
        return new URL(url).hostname;
    } catch {
        return "";
    }
}

/**
 * Check if a hostname/IP is localhost (safe)
 * @param {string} hostname - hostname or IP from URL
 * @returns {boolean} - true if localhost
 */
function isLocalhost(hostname) {
    if (!hostname) return false;
    
    // Check common localhost patterns
    return (
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "0.0.0.0" ||
        hostname === "::1" ||  // IPv6 localhost
        hostname === "[::1]" ||
        hostname.startsWith("127.") ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("172.16.") ||
        hostname.startsWith("172.31.")
    );
}

/**
 * Pre-check: Fast pattern-based detection (instant decision)
 * @param {string} url - URL to check
 * @returns {boolean} - true if instantly suspicious
 */
function isInstantlySuspicious(url) {
    // Check against pattern list
    return INSTANT_BLOCK_PATTERNS.some(pattern => pattern.test(url)) || isHeuristicallySuspicious(url);
}

/**
 * Deep scan: Send to Flask backend for VT/GSB/PhishTank verification
 * Runs ASYNC without waiting (tab already closed)
 * @param {string} url - URL to scan
 * @param {number} tabId - tab ID (for logging)
 */
function deepScanInBackground(url, tabId) {
    const domain = extractDomain(url);

    // Skip if already cached as safe
    const cached = getCachedReputation(domain);
    if (cached === "Safe") {
        return;
    }

    // Perform deep scan in background (don't wait)
    fetch("http://localhost:5000/check-url", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
    })
    .then(response => {
        if (!response.ok) {
            console.warn(`Backend returned ${response.status}`);
            return null;
        }
        return response.json();
    })
    .then(data => {
        if (!data || !data.status) return;

        // Cache the result
        setCachedReputation(domain, data.status);

        // If malicious and tab still exists, close it
        const closeableStatuses = ["Malicious", "Phishing", "Suspicious"];

        if (closeableStatuses.includes(data.status)) {
            console.log(`🚨 Deep scan blocked (${data.status}): ${url}`);
            chrome.tabs.remove(tabId);
            return;
        }

        if (data.status === "Suspicious") {
            console.warn(`⚠️ Deep scan flagged as suspicious: ${url}`);
        }
    })
    .catch(err => {
        console.error(`Background scan error for ${url}:`, err);
    });
}

/**
 * Main listener: monitors all tab updates
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only process when page is LOADING (instant) or COMPLETE (fallback)
    if (!["loading", "complete"].includes(changeInfo.status) || !tab.url) {
        return;
    }

    const url = tab.url;

    // Skip non-HTTP URLs
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        return;
    }

    // EXCEPTION: Skip localhost/private IPs (local development)
    const hostname = extractDomain(url);
    if (isLocalhost(hostname)) {
        console.log(`ℹ️ Skipping localhost/private IP: ${url}`);
        return;
    }


    // ⚡ INSTANT CHECK: Pattern-based pre-filtering (0.1ms) OR cache (Malicious/Suspicious/Phishing)
    const cached = getCachedReputation(hostname);
    if (isInstantlySuspicious(url) || ["Malicious", "Phishing", "Suspicious"].includes(cached)) {
        console.log(`🚨 Instant block (pattern/cached): ${url}`);
        // Directly remove the tab for minimal latency (avoid extra async get)
        try {
            chrome.tabs.remove(tabId);
        } catch (e) {
            // ignore: tab may already be gone or permission issues
        }
        // Still scan in background for logging
        deepScanInBackground(url, tabId);
        return;
    }

    // 🔄 BACKGROUND SCAN: Deep verification (async, non-blocking)
    deepScanInBackground(url, tabId);
});

    // EARLY NAVIGATION: use webNavigation to catch navigations earlier than tab update
    if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
        chrome.webNavigation.onBeforeNavigate.addListener((details) => {
            try {
                // Only main frame navigations
                if (details.frameId !== 0) return;

                const url = details.url;
                if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return;

                const hostname = extractDomain(url);
                if (isLocalhost(hostname)) return;

                const cached = getCachedReputation(hostname);
                if (isInstantlySuspicious(url) || ["Malicious", "Phishing", "Suspicious"].includes(cached)) {
                    console.log(`🚨 Early nav block (onBeforeNavigate): ${url}`);
                    try { chrome.tabs.remove(details.tabId); } catch (e) {}
                    deepScanInBackground(url, details.tabId);
                    return;
                }

                // Load persisted cache and perform an initial sync from backend
                loadCacheFromStorage();
                // Try an immediate sync at startup
                syncRecentThreatsFromServer(100);
                // Periodically sync (every 10s) to copy any recent threat lookup into the extension cache
                setInterval(syncRecentThreatsFromServer, 10000);

                // Otherwise schedule background deep scan (non-blocking)
                deepScanInBackground(url, details.tabId);
            } catch (e) {
                // ignore
            }
        });
    }

/**
 * Tab switch detection: onActivated
 * Sends lightweight activity event and optionally triggers fast checks.
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
    try {
        const tab = await chrome.tabs.get(activeInfo.tabId);
        if (!tab || !tab.url) return;
        const url = tab.url;

        // Only http(s)
        if (!url.startsWith("http://") && !url.startsWith("https://")) return;

        const now = Date.now();
        if (lastActivity.tabId === activeInfo.tabId && lastActivity.url === url && (now - lastActivity.when) < ACTIVITY_DEBOUNCE_MS) {
            return; // debounce identical activity
        }
        lastActivity = { tabId: activeInfo.tabId, url, when: now };

        const hostname = extractDomain(url);
        if (isLocalhost(hostname)) return;

        // Fire-and-forget activity log
        fetch(ACTIVITY_ENDPOINT, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, title: tab.title || "", action: "switch" })
        }).catch(() => {});

        // Quick cached decision: if malicious, close immediately
        const cached = getCachedReputation(hostname);
        if (cached === "Malicious") {
            chrome.tabs.remove(activeInfo.tabId);
            return;
        }

        // Optional instant pattern check on switch
        if (isInstantlySuspicious(url)) {
            chrome.tabs.remove(activeInfo.tabId);
            deepScanInBackground(url, activeInfo.tabId);
            return;
        }
        // Otherwise, run deep scan in background without blocking
        deepScanInBackground(url, activeInfo.tabId);
    } catch (e) {
        // ignore
    }
});

/**
 * Optional: Listen for action button clicks
 * Can add manual scanning capability
 */
chrome.action.onClicked.addListener(() => {
    console.log("Extension icon clicked - ready for user interactions");
});


