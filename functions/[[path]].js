// ==================== CONFIG ====================
let UPSTREAM_PRIMARY = 'https://bu0eg1tdzu.cloudflare-gateway.com/dns-query';
let UPSTREAM_FALLBACK = 'https://rhpcv957tj.cloudflare-gateway.com/dns-query';
let UPSTREAM_GEO_BYPASS = 'https://dns.mullvad.net/dns-query'; // Re-resolve without ECS when geo-block returns loopback
let UPSTREAM_TIMEOUT = 5000;

// Refresh interval for ALL lists (blocklist, allowlists, private TLDs, redirect rules)
let ALL_LISTS_REFRESH_INTERVAL = 3600000; // 1 hour

let AD_BLOCK_ENABLED = true;
let BLOCKLIST_URL = '/rules/blocklists.txt';
let ALLOWLIST_URL = '/rules/allowlists.txt';

let ECS_INJECTION_ENABLED = true;
let ECS_PREFIX_V4 = 24;
let ECS_PREFIX_V6 = 48;

// Block query types early to save Cloudflare Pages requests
let BLOCK_ANY = true;    // TYPE 255 — ANY queries
let BLOCK_AAAA = true;   // TYPE 28  — IPv6 queries
let BLOCK_PTR = true;    // TYPE 12  — Reverse DNS
let BLOCK_HTTPS = true;  // TYPE 65  — HTTPS record queries

// Block private/internal TLDs and router domains
let BLOCK_PRIVATE_TLD = true;
let PRIVATE_TLD_URL = '/rules/private_tlds.txt';

// DNS redirect/rewrite (local CNAME overrides)
let DNS_REDIRECT_ENABLED = true;
let REDIRECT_RULES_URL = '/rules/redirect_rules.txt';

// Dedicated Mullvad Upstream Domains
let MULLVAD_UPSTREAM_ENABLED = true;
let MULLVAD_UPSTREAM_URL = '/rules/mullvad_upstream.txt';

// /debug endpoint — set to true only when needed, false by default to avoid unnecessary requests
let DEBUG_ENABLED = false;

// Pre-compiled regex patterns for performance
const IPV4_MAPPED_REGEX = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i;
const IPV6_VALID_REGEX = /^[0-9a-f:]+$/i;
const IPV6_GROUP_REGEX = /^[0-9a-f]+$/i;

// ==================== STATE ====================
let adBlocklist = new Set();
let adAllowlist = new Set();
let privateTlds = new Set();
let redirectRules = new Map(); // domain → target domain
let mullvadUpstreamDomains = new Set();
let blocklistLastFetch = 0;
let blocklistPromise = null;
let blocklistsFetched = false; // Track if lists have been fetched at least once

// ==================== CONFIG MANAGEMENT ====================
function getCurrentConfig() {
  return {
    UPSTREAM_PRIMARY, UPSTREAM_FALLBACK, UPSTREAM_GEO_BYPASS, UPSTREAM_TIMEOUT,
    ALL_LISTS_REFRESH_INTERVAL,
    AD_BLOCK_ENABLED, BLOCKLIST_URL, ALLOWLIST_URL,
    ECS_INJECTION_ENABLED, ECS_PREFIX_V4, ECS_PREFIX_V6,
    BLOCK_ANY, BLOCK_AAAA, BLOCK_PTR, BLOCK_HTTPS,
    BLOCK_PRIVATE_TLD, PRIVATE_TLD_URL,
    DNS_REDIRECT_ENABLED, REDIRECT_RULES_URL,
    MULLVAD_UPSTREAM_ENABLED, MULLVAD_UPSTREAM_URL,
    DEBUG_ENABLED
  };
}

function applyConfig(cfg) {
  if (cfg.UPSTREAM_PRIMARY !== undefined) UPSTREAM_PRIMARY = String(cfg.UPSTREAM_PRIMARY);
  if (cfg.UPSTREAM_FALLBACK !== undefined) UPSTREAM_FALLBACK = String(cfg.UPSTREAM_FALLBACK);
  if (cfg.UPSTREAM_GEO_BYPASS !== undefined) UPSTREAM_GEO_BYPASS = String(cfg.UPSTREAM_GEO_BYPASS);
  if (cfg.UPSTREAM_TIMEOUT !== undefined) UPSTREAM_TIMEOUT = Number(cfg.UPSTREAM_TIMEOUT) || 5000;
  if (cfg.ALL_LISTS_REFRESH_INTERVAL !== undefined) ALL_LISTS_REFRESH_INTERVAL = Number(cfg.ALL_LISTS_REFRESH_INTERVAL) || 3600000;
  if (cfg.AD_BLOCK_ENABLED !== undefined) AD_BLOCK_ENABLED = Boolean(cfg.AD_BLOCK_ENABLED);
  if (cfg.BLOCKLIST_URL !== undefined) BLOCKLIST_URL = String(cfg.BLOCKLIST_URL);
  if (cfg.ALLOWLIST_URL !== undefined) ALLOWLIST_URL = String(cfg.ALLOWLIST_URL);
  if (cfg.ECS_INJECTION_ENABLED !== undefined) ECS_INJECTION_ENABLED = Boolean(cfg.ECS_INJECTION_ENABLED);
  if (cfg.ECS_PREFIX_V4 !== undefined) ECS_PREFIX_V4 = Number(cfg.ECS_PREFIX_V4) || 24;
  if (cfg.ECS_PREFIX_V6 !== undefined) ECS_PREFIX_V6 = Number(cfg.ECS_PREFIX_V6) || 48;
  if (cfg.BLOCK_ANY !== undefined) BLOCK_ANY = Boolean(cfg.BLOCK_ANY);
  if (cfg.BLOCK_AAAA !== undefined) BLOCK_AAAA = Boolean(cfg.BLOCK_AAAA);
  if (cfg.BLOCK_PTR !== undefined) BLOCK_PTR = Boolean(cfg.BLOCK_PTR);
  if (cfg.BLOCK_HTTPS !== undefined) BLOCK_HTTPS = Boolean(cfg.BLOCK_HTTPS);
  if (cfg.BLOCK_PRIVATE_TLD !== undefined) BLOCK_PRIVATE_TLD = Boolean(cfg.BLOCK_PRIVATE_TLD);
  if (cfg.PRIVATE_TLD_URL !== undefined) PRIVATE_TLD_URL = String(cfg.PRIVATE_TLD_URL);
  if (cfg.DNS_REDIRECT_ENABLED !== undefined) DNS_REDIRECT_ENABLED = Boolean(cfg.DNS_REDIRECT_ENABLED);
  if (cfg.REDIRECT_RULES_URL !== undefined) REDIRECT_RULES_URL = String(cfg.REDIRECT_RULES_URL);
  if (cfg.MULLVAD_UPSTREAM_ENABLED !== undefined) MULLVAD_UPSTREAM_ENABLED = Boolean(cfg.MULLVAD_UPSTREAM_ENABLED);
  if (cfg.MULLVAD_UPSTREAM_URL !== undefined) MULLVAD_UPSTREAM_URL = String(cfg.MULLVAD_UPSTREAM_URL);
  if (cfg.DEBUG_ENABLED !== undefined) DEBUG_ENABLED = Boolean(cfg.DEBUG_ENABLED);
  BLOCKED_QTYPES = getBlockedQtypes();
  if (cfg.BLOCKLIST_URL !== undefined || cfg.ALLOWLIST_URL !== undefined ||
      cfg.PRIVATE_TLD_URL !== undefined || cfg.REDIRECT_RULES_URL !== undefined ||
      cfg.MULLVAD_UPSTREAM_URL !== undefined) {
    blocklistLastFetch = 0;
    blocklistsFetched = false;
  }
}

let configLoaded = false;
async function loadConfig(env) {
  if (configLoaded) return;
  configLoaded = true;
  if (!env?.DNS_GATEWAY_KV) return;
  try {
    const saved = await env.DNS_GATEWAY_KV.get('dns_gateway_config', 'json');
    if (saved) applyConfig(saved);
  } catch {}
}

async function saveConfigToKV(env, updates) {
  applyConfig(updates);
  if (!env?.DNS_GATEWAY_KV) return;
  try {
    await env.DNS_GATEWAY_KV.put('dns_gateway_config', JSON.stringify(getCurrentConfig()));
  } catch {}
}

function getCurrentStats(env, adminUser) {
  return {
    blocklistSize: adBlocklist.size,
    allowlistSize: adAllowlist.size,
    privateTldsSize: privateTlds.size,
    redirectRulesSize: redirectRules.size,
    mullvadDomainsSize: mullvadUpstreamDomains.size,
    lastFetch: blocklistLastFetch ? new Date(blocklistLastFetch).toISOString() : 'never',
    hasKV: !!env?.DNS_GATEWAY_KV,
    hasAuth: !!adminUser,
    needsSetup: !!env?.DNS_GATEWAY_KV && !adminUser
  };
}

// ==================== AUTH ====================
async function createAuthToken(password) {
  const exp = Date.now() + 86400000;
  const data = new TextEncoder().encode(String(exp));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return exp + '.' + [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyAuthToken(token, password) {
  try {
    const dotIdx = token.indexOf('.');
    if (dotIdx === -1) return false;
    const expStr = token.substring(0, dotIdx);
    const sig = token.substring(dotIdx + 1);
    const exp = parseInt(expStr);
    if (isNaN(exp) || Date.now() > exp) return false;
    const data = new TextEncoder().encode(expStr);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const expected = await crypto.subtle.sign('HMAC', key, data);
    const expectedHex = [...new Uint8Array(expected)].map(b => b.toString(16).padStart(2, '0')).join('');
    return sig === expectedHex;
  } catch { return false; }
}

async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Domain validation regex — matches extract_domains() in update_lists.sh
const DOMAIN_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Extract and clean domains from raw list text (AdBlock, hosts, plain domain formats)
// Mirrors the awk extract_domains() logic in update_lists.sh
function extractDomains(text) {
  const domains = new Set();
  for (const rawLine of text.split('\n')) {
    // Skip empty lines and comment lines
    if (!rawLine.trim() || /^[!#]/.test(rawLine.trim())) continue;
    let line = rawLine.toLowerCase();
    // Strip AdBlock exception prefix: @@|| or @@|
    line = line.replace(/^@@\|\|?/, '');
    // Strip AdBlock domain prefix: || or |
    line = line.replace(/^\|\|?/, '');
    // Strip everything after ^ (AdBlock separator)
    line = line.replace(/\^.*/, '');
    // Strip inline comments (# or !)
    line = line.replace(/[#!].*/, '');
    // Strip paths
    line = line.replace(/\/.*/, '');
    // Strip port numbers
    line = line.replace(/:.*/, '');
    // Strip hosts-file IP prefix (0.0.0.0, 127.0.0.1, etc.)
    line = line.replace(/^[0-9.]+\s+/, '');
    // Trim whitespace
    line = line.trim();
    // Validate domain format and deduplicate
    if (line && DOMAIN_REGEX.test(line)) domains.add(line);
  }
  return domains;
}

async function fetchList(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return new Set();
    return extractDomains(await res.text());
  } catch { return new Set(); }
}

async function fetchRedirectRules(url) {
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return new Map();
    const text = await res.text();
    const rules = new Map();
    for (const line of text.split('\n')) {
      const d = line.trim();
      if (!d || d.startsWith('#') || d.startsWith('!')) continue;
      const parts = d.split(/\s+/);
      if (parts.length === 2) rules.set(parts[0].toLowerCase(), parts[1].toLowerCase());
    }
    return rules;
  } catch { return new Map(); }
}

async function refreshBlocklists(baseUrl, env) {
  // Skip refresh if:
  // 1. Already fetched at least once AND
  // 2. Within refresh interval
  if (blocklistsFetched && Date.now() - blocklistLastFetch < ALL_LISTS_REFRESH_INTERVAL) return;

  if (blocklistPromise) return blocklistPromise;

  blocklistPromise = (async () => {
    try {
      const bUrl = new URL(BLOCKLIST_URL, baseUrl).toString();
      const aUrl = new URL(ALLOWLIST_URL, baseUrl).toString();
      const pUrl = new URL(PRIVATE_TLD_URL, baseUrl).toString();
      const rUrl = new URL(REDIRECT_RULES_URL, baseUrl).toString();
      const mUrl = new URL(MULLVAD_UPSTREAM_URL, baseUrl).toString();

      const [block, allow, privateList, redirRules, mullvadList] = await Promise.all([
        AD_BLOCK_ENABLED ? fetchList(bUrl) : Promise.resolve(new Set()),
        AD_BLOCK_ENABLED ? fetchList(aUrl) : Promise.resolve(new Set()),
        BLOCK_PRIVATE_TLD ? fetchList(pUrl) : Promise.resolve(new Set()),
        DNS_REDIRECT_ENABLED ? fetchRedirectRules(rUrl) : Promise.resolve(new Map()),
        MULLVAD_UPSTREAM_ENABLED ? fetchList(mUrl) : Promise.resolve(new Set())
      ]);

      // Always update state, even if lists are empty (to prevent infinite re-fetch)
      if (AD_BLOCK_ENABLED) { adBlocklist = block; adAllowlist = allow; }
      if (BLOCK_PRIVATE_TLD) { privateTlds = privateList; }
      if (DNS_REDIRECT_ENABLED) { redirectRules = redirRules; }
      if (MULLVAD_UPSTREAM_ENABLED) { mullvadUpstreamDomains = mullvadList; }

      // Merge custom domains from KV
      if (env?.DNS_GATEWAY_KV) {
        try {
          const custom = await env.DNS_GATEWAY_KV.get('custom_domains', 'json');
          if (custom) {
            if (custom.blocklist) custom.blocklist.forEach(d => adBlocklist.add(d));
            if (custom.allowlist) custom.allowlist.forEach(d => adAllowlist.add(d));
            if (custom.private_tlds) custom.private_tlds.forEach(d => privateTlds.add(d));
            if (custom.redirect_rules) custom.redirect_rules.forEach(r => redirectRules.set(r.source.toLowerCase(), r.target.toLowerCase()));
            if (custom.mullvad_upstream) custom.mullvad_upstream.forEach(d => mullvadUpstreamDomains.add(d));
          }
        } catch {}
        // Fetch custom external URLs (user-added list subscriptions)
        try {
          const customUrls = await env.DNS_GATEWAY_KV.get('custom_urls', 'json');
          if (customUrls) {
            const fetches = [];
            if (customUrls.blocklist) customUrls.blocklist.forEach(u => fetches.push(fetchList(u).then(s => s.forEach(d => adBlocklist.add(d)))));
            if (customUrls.allowlist) customUrls.allowlist.forEach(u => fetches.push(fetchList(u).then(s => s.forEach(d => adAllowlist.add(d)))));
            await Promise.allSettled(fetches);
          }
        } catch {}
      }

      blocklistLastFetch = Date.now();
      blocklistsFetched = true; // Mark as fetched to prevent infinite re-fetch
    } finally { blocklistPromise = null; }
  })();

  return blocklistPromise;
}

// Extract QTYPE from first question section
function extractQtype(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return null;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return null;
    let off = 12;
    while (off < v.length) {
      const len = v[off];
      if (len === 0) { off++; break; }
      if ((len & 0xC0) === 0xC0) { off += 2; break; }
      off += len + 1;
    }
    if (off + 2 > v.length) return null;
    return (v[off] << 8) | v[off + 1];
  } catch { return null; }
}

// Build set of blocked query types from config
function getBlockedQtypes() {
  const blocked = new Set();
  if (BLOCK_ANY) blocked.add(255);
  if (BLOCK_AAAA) blocked.add(28);
  if (BLOCK_PTR) blocked.add(12);
  if (BLOCK_HTTPS) blocked.add(65);
  return blocked;
}
let BLOCKED_QTYPES = getBlockedQtypes();

// Parse all question domains
function extractAllDomains(buf) {
  const domains = [];
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return domains;
    const qd = (v[4] << 8) | v[5];
    if (qd === 0) return domains;
    let off = 12;
    for (let q = 0; q < qd; q++) {
      const labels = [];
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off++;
        if (off + len > v.length) return domains;
        let label = '';
        for (let i = 0; i < len; i++) label += String.fromCharCode(v[off + i]);
        labels.push(label);
        off += len;
      }
      off += 4; // QTYPE + QCLASS
      if (labels.length > 0) domains.push(labels.join('.').toLowerCase());
    }
  } catch { }
  return domains;
}

function hasLoopbackInAnswer(buf) {
  try {
    const v = new Uint8Array(buf);
    if (v.length < 12) return false;
    const qd = (v[4] << 8) | v[5];
    const an = (v[6] << 8) | v[7];
    if (an === 0) return false;

    let off = 12;
    // Skip Question Section
    for (let i = 0; i < qd; i++) {
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      off += 4; // Type + Class
    }

    // Parse Answer Section
    for (let i = 0; i < an; i++) {
      // Skip Name (can be compressed)
      while (off < v.length) {
        const len = v[off];
        if (len === 0) { off++; break; }
        if ((len & 0xC0) === 0xC0) { off += 2; break; }
        off += len + 1;
      }
      if (off + 10 > v.length) break;
      const type = (v[off] << 8) | v[off + 1];
      const cls = (v[off + 2] << 8) | v[off + 3];
      const rdlen = (v[off + 8] << 8) | v[off + 9];
      off += 10;
      if (type === 1 && cls === 1 && rdlen === 4) { // Type A, Class IN, Length 4
        if (v[off] === 127 && v[off + 1] === 0 && v[off + 2] === 0 && v[off + 3] === 1) return true;
      }
      off += rdlen;
    }
  } catch { }
  return false;
}

function isDomainBlocked(domain) {
  if (!domain || adBlocklist.size === 0) return false;

  // EXACT MATCH ONLY - Check allowlist first (priority)
  if (adAllowlist.has(domain)) return false;

  // EXACT MATCH ONLY - Check blocklist
  if (adBlocklist.has(domain)) return true;

  return false;
}

// Check if domain matches private TLD list (suffix match)
function isDomainPrivate(domain) {
  if (!domain || privateTlds.size === 0) return false;

  // Exact match (e.g. query for "localhost" or "192.168.1.1")
  if (privateTlds.has(domain)) return true;

  // Suffix match: efficient with substring + indexOf
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (privateTlds.has(domain.substring(pos + 1))) return true;
    pos++; // Move past the dot
  }

  return false;
}

// Check if domain matches Mullvad upstream list (suffix match including subdomains)
function isMullvadDomain(domain) {
  if (!domain || mullvadUpstreamDomains.size === 0) return false;
  if (mullvadUpstreamDomains.has(domain)) return true;
  let pos = 0;
  while ((pos = domain.indexOf('.', pos)) !== -1) {
    if (mullvadUpstreamDomains.has(domain.substring(pos + 1))) return true;
    pos++;
  }
  return false;
}

// Build NXDOMAIN response (RCODE=3) - Domain does not exist
// Mirrors query flags (Opcode, AA, TC, RD) per RFC 1035
function buildNxdomain(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    // Malformed query → SERVFAIL
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82; // QR=1, Opcode=0, AA=1, TC=0, RD=0, RA=1, RCODE=2
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4; // QTYPE + QCLASS
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F); // QR=1, mirror Opcode/AA/TC/RD from query
  res[3] = 0x80 | 0x03;           // RA=1, RCODE=3 (NXDOMAIN)
  res[4] = 0; res[5] = 1; // QDCOUNT=1
  res[6] = 0; res[7] = 0; // ANCOUNT=0
  res[8] = 0; res[9] = 0; // NSCOUNT=0
  res[10] = 0; res[11] = 0; // ARCOUNT=0
  return res.buffer;
}

// NODATA response: RCODE=0 (NOERROR), ANCOUNT=0 — domain exists but no records of this type
function buildNodata(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x80;
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F); // QR=1, mirror flags
  res[3] = 0x80;                  // RA=1, RCODE=0 (NOERROR)
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0; // ANCOUNT=0
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}

function buildServfail(query) {
  const v = new Uint8Array(query);
  if (v.length < 12) {
    const sf = new Uint8Array(12);
    sf[2] = 0x84; sf[3] = 0x82; // QR=1, AA=1, RA=1, RCODE=2
    return sf.buffer;
  }
  let qEnd = 12;
  while (qEnd < v.length) {
    const len = v[qEnd];
    if (len === 0) { qEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qEnd += 2; break; }
    qEnd += len + 1;
  }
  qEnd += 4;
  const res = new Uint8Array(qEnd);
  res.set(v.slice(0, qEnd));
  res[2] = 0x80 | (v[2] & 0x7F); // QR=1, mirror Opcode/AA/TC/RD
  res[3] = 0x80 | 0x02;           // RA=1, RCODE=2 (SERVFAIL)
  res[4] = 0; res[5] = 1;
  res[6] = 0; res[7] = 0;
  res[8] = 0; res[9] = 0;
  res[10] = 0; res[11] = 0;
  return res.buffer;
}

// ==================== ECS INJECTION ====================
// Inject EDNS Client Subnet (ECS) into DNS query per RFC 7871
// Adds client subnet info for geo-optimized CDN responses
function injectECS(query, clientIP) {
  if (!ECS_INJECTION_ENABLED || !clientIP || clientIP === 'unknown') return query;
  try {
    const v = new Uint8Array(query);
    if (v.length < 12) return query;

    // Strip existing OPT records
    const clean = stripOPT(v);

    // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
    const ipv4Mapped = clientIP.match(IPV4_MAPPED_REGEX);
    if (ipv4Mapped) clientIP = ipv4Mapped[1];

    // Build ECS data
    let family, prefixLen, addrBytes;
    if (clientIP.includes(':')) {
      family = 2; prefixLen = ECS_PREFIX_V6;
      const allBytes = ipv6ToBytes(clientIP);
      if (!allBytes) return query; // Invalid IPv6 address, skip ECS injection
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = allBytes.slice(0, byteLen);
    } else {
      family = 1; prefixLen = ECS_PREFIX_V4;
      const parts = clientIP.split('.');
      if (parts.length !== 4) return query;
      const byteLen = Math.ceil(prefixLen / 8);
      addrBytes = parts.slice(0, byteLen).map(Number);
    }

    // Mask unused trailing bits per RFC 7871 (e.g., /24 prefix → mask last byte)
    if (addrBytes.length > 0 && prefixLen % 8 !== 0) {
      const maskBits = prefixLen % 8;
      const mask = (0xFF << (8 - maskBits)) & 0xFF;
      addrBytes[addrBytes.length - 1] &= mask;
    }

    const ecsLen = 4 + addrBytes.length;
    const ecs = new Uint8Array(4 + ecsLen);
    ecs[0] = 0; ecs[1] = 8; // option code 8 (ECS)
    ecs[2] = (ecsLen >> 8) & 0xFF; ecs[3] = ecsLen & 0xFF;
    ecs[4] = (family >> 8) & 0xFF; ecs[5] = family & 0xFF;
    ecs[6] = prefixLen; ecs[7] = 0; // scope = 0
    for (let i = 0; i < addrBytes.length; i++) ecs[8 + i] = addrBytes[i];

    // OPT record
    const opt = new Uint8Array(11 + ecs.length);
    opt[0] = 0; // root
    opt[1] = 0; opt[2] = 41; // type OPT
    opt[3] = 16; opt[4] = 0; // UDP 4096
    opt[5] = 0; opt[6] = 0; opt[7] = 0; opt[8] = 0; // ext RCODE
    opt[9] = (ecs.length >> 8) & 0xFF; opt[10] = ecs.length & 0xFF;
    opt.set(ecs, 11);

    // Increment ARCOUNT to account for new OPT record
    const currentArCount = (clean[10] << 8) | clean[11];
    const newArCount = currentArCount + 1;

    const result = new Uint8Array(clean.length + opt.length);
    result.set(clean);
    result.set(opt, clean.length);
    result[10] = (newArCount >> 8) & 0xFF;
    result[11] = newArCount & 0xFF;
    return result.buffer;
  } catch { return query; }
}

// Strip existing OPT (EDNS) records from DNS query
// Validates rdata bounds and correctly rebuilds ARCOUNT
function stripOPT(view) {
  let off = 12;
  const qd = (view[4] << 8) | view[5];
  for (let i = 0; i < qd && off < view.length; i++) {
    while (off < view.length) {
      const l = view[off];
      if (l === 0) { off++; break; }
      if ((l & 0xC0) === 0xC0) { off += 2; break; }
      off += l + 1;
    }
    off += 4;
  }
  const an = (view[6] << 8) | view[7];
  const ns = (view[8] << 8) | view[9];
  for (let i = 0; i < an + ns && off < view.length; i++) {
    while (off < view.length) {
      const l = view[off];
      if (l === 0) { off++; break; }
      if ((l & 0xC0) === 0xC0) { off += 2; break; }
      off += l + 1;
    }
    if (off + 10 > view.length) break;
    off += 10 + ((view[off + 8] << 8) | view[off + 9]);
  }
  // Parse AR section: iterate each record, keep non-OPT, drop TYPE=41
  const ar = (view[10] << 8) | view[11];
  let arOff = off;
  const keptRecords = [];
  for (let i = 0; i < ar && arOff < view.length; i++) {
    const recStart = arOff;
    // Skip Name
    while (arOff < view.length) {
      const l = view[arOff];
      if (l === 0) { arOff++; break; }
      if ((l & 0xC0) === 0xC0) { arOff += 2; break; }
      arOff += l + 1;
    }
    if (arOff + 10 > view.length) break;
    const type = (view[arOff] << 8) | view[arOff + 1];
    const rdlen = (view[arOff + 8] << 8) | view[arOff + 9];
    // Validate rdata length fits within buffer bounds
    if (arOff + 10 + rdlen > view.length) break;
    arOff += 10 + rdlen;
    if (type !== 41) {
      keptRecords.push(view.subarray(recStart, arOff));
    }
  }
  // Rebuild buffer without OPT records
  let totalLen = off;
  for (const rec of keptRecords) totalLen += rec.length;
  const r = new Uint8Array(totalLen);
  r.set(view.subarray(0, off));
  let writeOff = off;
  for (const rec of keptRecords) {
    r.set(rec, writeOff);
    writeOff += rec.length;
  }
  // Set ARCOUNT to number of kept additional records (excluding removed OPT)
  r[10] = (keptRecords.length >> 8) & 0xFF;
  r[11] = keptRecords.length & 0xFF;
  return r;
}

// Convert IPv6 address string to 16-byte array
// Validates format, handles :: compression, rejects invalid input
function ipv6ToBytes(ip) {
  try {
    if (!ip || typeof ip !== 'string') return null;
    if (!IPV6_VALID_REGEX.test(ip)) return null;

    const halves = ip.split('::');
    if (halves.length > 2) return null; // Multiple :: is invalid

    const left = halves[0] ? halves[0].split(':').filter(x => x) : [];
    const right = halves.length > 1 && halves[1] ? halves[1].split(':').filter(x => x) : [];
    const totalGroups = left.length + right.length;
    if (totalGroups > 8) return null;

    // Validate each group
    for (const g of [...left, ...right]) {
      if (g.length > 4 || !IPV6_GROUP_REGEX.test(g)) return null;
    }

    const missing = 8 - totalGroups;
    const full = [...left, ...Array(missing).fill('0'), ...right];
    const bytes = [];
    for (const s of full) {
      const v = parseInt(s || '0', 16);
      if (isNaN(v)) return null;
      bytes.push((v >> 8) & 0xFF, v & 0xFF);
    }
    return bytes;
  } catch { return null; }
}

// ==================== DNS REDIRECT ====================
// Encode domain string to DNS wire format (e.g. "www.example.com" → [3,w,w,w,7,e,x,a,m,p,l,e,3,c,o,m,0])
function encodeDomainName(domain) {
  const labels = domain.split('.');
  const parts = [];
  for (const label of labels) {
    if (label.length === 0) continue;
    parts.push(label.length);
    for (let i = 0; i < label.length; i++) parts.push(label.charCodeAt(i));
  }
  parts.push(0); // root terminator
  return new Uint8Array(parts);
}

// Rewrite QNAME in query buffer to target domain
function rewriteQname(query, targetDomain) {
  const v = new Uint8Array(query);
  if (v.length < 12) return query;
  let qnameEnd = 12;
  while (qnameEnd < v.length) {
    const len = v[qnameEnd];
    if (len === 0) { qnameEnd++; break; }
    if ((len & 0xC0) === 0xC0) { qnameEnd += 2; break; }
    qnameEnd += len + 1;
  }
  const targetWire = encodeDomainName(targetDomain);
  const afterQname = v.subarray(qnameEnd); // QTYPE + QCLASS + rest
  const result = new Uint8Array(12 + targetWire.length + afterQname.length);
  result.set(v.subarray(0, 12));
  result.set(targetWire, 12);
  result.set(afterQname, 12 + targetWire.length);
  return result.buffer;
}

// Rebuild response: original QNAME + CNAME(original→target) + answer records from upstream
// Avoids pointer corruption by writing all names uncompressed (except CNAME NAME uses 0xC00C)
function buildRedirectResponse(originalQuery, upstreamResponse, originalDomain, targetDomain) {
  const uv = new Uint8Array(upstreamResponse);
  const qv = new Uint8Array(originalQuery);
  if (uv.length < 12 || qv.length < 12) return upstreamResponse;

  // Parse upstream: skip question section
  let uOff = 12;
  const uQd = (uv[4] << 8) | uv[5];
  for (let i = 0; i < uQd; i++) {
    while (uOff < uv.length) {
      const l = uv[uOff];
      if (l === 0) { uOff++; break; }
      if ((l & 0xC0) === 0xC0) { uOff += 2; break; }
      uOff += l + 1;
    }
    uOff += 4;
  }

  // Extract answer records: skip compressed NAME, read TYPE/CLASS/TTL/RDATA raw
  const anCount = (uv[6] << 8) | uv[7];
  const ansRecords = [];
  for (let i = 0; i < anCount && uOff < uv.length; i++) {
    while (uOff < uv.length) {
      const l = uv[uOff];
      if (l === 0) { uOff++; break; }
      if ((l & 0xC0) === 0xC0) { uOff += 2; break; }
      uOff += l + 1;
    }
    if (uOff + 10 > uv.length) break;
    const type = (uv[uOff] << 8) | uv[uOff + 1];
    const cls = (uv[uOff + 2] << 8) | uv[uOff + 3];
    const ttl = ((uv[uOff + 4] << 24) | (uv[uOff + 5] << 16) | (uv[uOff + 6] << 8) | uv[uOff + 7]) >>> 0;
    const rdlen = (uv[uOff + 8] << 8) | uv[uOff + 9];
    uOff += 10;
    if (uOff + rdlen > uv.length) break;
    ansRecords.push({ type, cls, ttl, rdata: uv.slice(uOff, uOff + rdlen) });
    uOff += rdlen;
  }

  // Find end of original query's question section
  let oQEnd = 12;
  while (oQEnd < qv.length) {
    const l = qv[oQEnd];
    if (l === 0) { oQEnd++; break; }
    if ((l & 0xC0) === 0xC0) { oQEnd += 2; break; }
    oQEnd += l + 1;
  }
  oQEnd += 4; // QTYPE + QCLASS

  const targetWire = encodeDomainName(targetDomain);

  // Calculate total size
  const cnameSize = 2 + 10 + targetWire.length; // ptr + fixed fields + rdata
  let ansSize = 0;
  for (const rec of ansRecords) ansSize += targetWire.length + 10 + rec.rdata.length;

  const res = new Uint8Array(oQEnd + cnameSize + ansSize);

  // Header + question from original query
  res.set(qv.subarray(0, oQEnd));
  res[2] = 0x80 | (qv[2] & 0x7F); // QR=1, mirror flags
  res[3] = uv[3]; // RA + RCODE from upstream
  res[4] = 0; res[5] = 1; // QDCOUNT = 1
  const newAnCount = 1 + ansRecords.length;
  res[6] = (newAnCount >> 8) & 0xFF;
  res[7] = newAnCount & 0xFF;
  res[8] = 0; res[9] = 0;   // NSCOUNT = 0
  res[10] = 0; res[11] = 0; // ARCOUNT = 0

  let off = oQEnd;

  // CNAME record: NAME = pointer 0xC00C (original QNAME at byte 12)
  res[off++] = 0xC0; res[off++] = 0x0C;
  res[off++] = 0x00; res[off++] = 0x05; // TYPE = CNAME
  res[off++] = 0x00; res[off++] = 0x01; // CLASS = IN
  res[off++] = 0x00; res[off++] = 0x00;
  res[off++] = 0x01; res[off++] = 0x2C; // TTL = 300
  res[off++] = (targetWire.length >> 8) & 0xFF;
  res[off++] = targetWire.length & 0xFF;
  res.set(targetWire, off); off += targetWire.length;

  // Answer records from upstream with uncompressed target domain NAME
  for (const rec of ansRecords) {
    res.set(targetWire, off); off += targetWire.length; // NAME
    res[off++] = (rec.type >> 8) & 0xFF; res[off++] = rec.type & 0xFF;
    res[off++] = (rec.cls >> 8) & 0xFF; res[off++] = rec.cls & 0xFF;
    res[off++] = (rec.ttl >> 24) & 0xFF; res[off++] = (rec.ttl >> 16) & 0xFF;
    res[off++] = (rec.ttl >> 8) & 0xFF; res[off++] = rec.ttl & 0xFF;
    res[off++] = (rec.rdata.length >> 8) & 0xFF; res[off++] = rec.rdata.length & 0xFF;
    res.set(rec.rdata, off); off += rec.rdata.length;
  }

  return res.buffer;
}

// ==================== DNS FORWARDING ====================
async function forwardQuery(query, upstream) {
  const res = await fetch(upstream, {
    method: 'POST',
    headers: { 'Content-Type': 'application/dns-message', 'Accept': 'application/dns-message' },
    body: query,
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT)
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.arrayBuffer();
}

// Resolve DNS query with fallback and geo-bypass logic
// Returns SERVFAIL on upstream errors, NXDOMAIN for geo-blocked domains
async function resolveQuery(query, clientIP) {
  const processed = injectECS(query, clientIP);
  let result;
  try {
    result = await forwardQuery(processed, UPSTREAM_PRIMARY);
  } catch {
    try {
      result = await forwardQuery(processed, UPSTREAM_FALLBACK);
    } catch {
      // Both primary and fallback upstream failed
      return buildServfail(query);
    }
  }

  // If response contains 127.0.0.1, re-resolve via geo-bypass upstream (without ECS geo-lock)
  if (result && hasLoopbackInAnswer(result)) {
    try {
      const respMullvad = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
      if (!hasLoopbackInAnswer(respMullvad)) return respMullvad;
      // Mullvad success nhưng vẫn có loopback → geo-block thực sự
      return buildNxdomain(query);
    } catch {
      // Mullvad upstream failed (timeout or network error)
      return buildServfail(query);
    }
  }

  return result;
}

// ==================== HELPERS ====================
// Ensure blocklists are loaded (await on first load, background refresh after)
async function ensureBlocklistsLoaded(url, context) {
  if (!blocklistsFetched) {
    // First time: await to ensure lists are loaded
    await refreshBlocklists(url, context?.env);
  } else if (context) {
    // Already fetched: background refresh only
    context.waitUntil(refreshBlocklists(url, context?.env));
  }
}

// ==================== HANDLERS ====================
async function handleDNSQuery(request, context) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Accept' };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  let query;
  if (request.method === 'POST') {
    query = await request.arrayBuffer();
  } else if (request.method === 'GET') {
    const dns = new URL(request.url).searchParams.get('dns');
    if (!dns) return new Response('Missing dns parameter', { status: 400, headers: cors });
    const b64 = dns.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
    query = Uint8Array.from(atob(padded), c => c.charCodeAt(0)).buffer;
  } else {
    return new Response('Method not allowed', { status: 405, headers: cors });
  }

  // Block unwanted query types early to save upstream requests
  if (BLOCKED_QTYPES.size > 0) {
    const qtype = extractQtype(query);
    if (qtype !== null && BLOCKED_QTYPES.has(qtype)) {
      return new Response(buildNodata(query), {
        headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Type': String(qtype) }
      });
    }
  }

  // Load data if any domain-based filter is enabled
  if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED || MULLVAD_UPSTREAM_ENABLED) {
    await ensureBlocklistsLoaded(request.url, context);

    // Parse domains once for both filters
    const domains = extractAllDomains(query);
    for (const domain of domains) {
      if (!domain) continue;

      // Mullvad Dedicated Upstream
      if (MULLVAD_UPSTREAM_ENABLED && isMullvadDomain(domain)) {
        try {
          const processed = injectECS(query, clientIP);
          const data = await forwardQuery(processed, UPSTREAM_GEO_BYPASS);
          return new Response(data, {
            headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad' }
          });
        } catch {
          return new Response(buildServfail(query), {
            headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Upstream': 'Mullvad-Failed' }
          });
        }
      }

      // Private TLD check (NXDOMAIN)
      if (BLOCK_PRIVATE_TLD && isDomainPrivate(domain)) {
        return new Response(buildNxdomain(query), {
          headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked-Private': domain }
        });
      }

      // Ad block check (NXDOMAIN)
      if (AD_BLOCK_ENABLED && isDomainBlocked(domain)) {
        return new Response(buildNxdomain(query), {
          headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Blocked': domain }
        });
      }

      // DNS redirect: rewrite QNAME, forward to upstream, rebuild response with CNAME + answers
      if (DNS_REDIRECT_ENABLED && redirectRules.has(domain)) {
        const targetDomain = redirectRules.get(domain);
        try {
          const rewritten = rewriteQname(query, targetDomain);
          const upstreamData = await resolveQuery(rewritten, clientIP);
          const redirected = buildRedirectResponse(query, upstreamData, domain, targetDomain);
          return new Response(redirected, {
            headers: { ...cors, 'Content-Type': 'application/dns-message', 'X-Redirected': `${domain} -> ${targetDomain}` }
          });
        } catch {
          // Redirect failed, fall through to normal resolution
        }
      }
    }
  }

  // Forward to upstream
  try {
    const data = await resolveQuery(query, clientIP);
    return new Response(data, {
      headers: { ...cors, 'Content-Type': 'application/dns-message' }
    });
  } catch {
    return new Response('Upstream error', { status: 502, headers: cors });
  }
}

// ==================== ROUTING ====================
async function handleRequest(request, context) {
  await loadConfig(context.env);
  const path = new URL(request.url).pathname;

  if (path === '/dns-query') return handleDNSQuery(request, context);

  if (path === '/debug') {
    if (!DEBUG_ENABLED) return new Response('Not Found', { status: 404 });
    if (AD_BLOCK_ENABLED || BLOCK_PRIVATE_TLD || DNS_REDIRECT_ENABLED) {
      await ensureBlocklistsLoaded(request.url, context);
    }
    return new Response(JSON.stringify({
      upstreams: { primary: UPSTREAM_PRIMARY, fallback: UPSTREAM_FALLBACK, geoBypass: UPSTREAM_GEO_BYPASS },
      adBlock: { enabled: AD_BLOCK_ENABLED, blocklist: adBlocklist.size, allowlist: adAllowlist.size, lastFetch: blocklistLastFetch ? new Date(blocklistLastFetch).toISOString() : 'never' },
      ecs: { enabled: ECS_INJECTION_ENABLED, prefixV4: `/${ECS_PREFIX_V4}`, prefixV6: `/${ECS_PREFIX_V6}` },
      blockedTypes: { ANY: BLOCK_ANY, AAAA: BLOCK_AAAA, PTR: BLOCK_PTR, HTTPS: BLOCK_HTTPS },
      privateTld: { enabled: BLOCK_PRIVATE_TLD, entries: privateTlds.size },
      dnsRedirect: { enabled: DNS_REDIRECT_ENABLED, rules: redirectRules.size },
      mullvadUpstream: { enabled: MULLVAD_UPSTREAM_ENABLED, entries: mullvadUpstreamDomains.size }
    }, null, 2), { headers: { 'Content-Type': 'application/json' } });
  }

  if (path === '/apple') {
    const host = new URL(request.url).hostname;
    const dohUrl = `https://${host}/dns-query`;
    const uuid1 = crypto.randomUUID();
    const uuid2 = crypto.randomUUID();
    const uuid3 = crypto.randomUUID();
    const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${dohUrl}</string>
            </dict>
            <key>PayloadDescription</key>
            <string>Configures device to use Serverless Edge DNS Gateway</string>
            <key>PayloadDisplayName</key>
            <string>Serverless Edge DNS Gateway</string>
            <key>PayloadIdentifier</key>
            <string>com.cloudflare.${uuid1}.dnsSettings.managed</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>${uuid3}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>This profile enables encrypted DNS (DNS over HTTPS) on iOS, iPadOS, and macOS devices.</string>
    <key>PayloadDisplayName</key>
    <string>Serverless Edge DNS Gateway - ${host}</string>
    <key>PayloadIdentifier</key>
    <string>com.cloudflare.${uuid2}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>${uuid2}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
    return new Response(profile, {
      headers: {
        'Content-Type': 'application/x-apple-aspen-config',
        'Content-Disposition': `attachment; filename="${host}.mobileconfig"`
      }
    });
  }

  // ==================== ADMIN API ====================
  if (path.startsWith('/api/')) {
    const apiHeaders = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: apiHeaders });

    // Load admin user from KV
    const adminUser = context.env?.DNS_GATEWAY_KV ? await context.env.DNS_GATEWAY_KV.get('admin_user', 'json').catch(() => null) : null;

    // POST /api/register — First-user-is-admin
    if (path === '/api/register' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ error: 'KV not configured. Bind DNS_GATEWAY_KV namespace.' }), { status: 503, headers: apiHeaders });
      if (adminUser) return new Response(JSON.stringify({ error: 'Admin account already exists' }), { status: 403, headers: apiHeaders });
      try {
        const body = await request.json();
        if (!body.username || !body.password || body.password.length < 6) {
          return new Response(JSON.stringify({ error: 'Username and password (min 6 chars) required' }), { status: 400, headers: apiHeaders });
        }
        const salt = crypto.randomUUID();
        const passwordHash = await hashPassword(body.password, salt);
        const user = { username: body.username, passwordHash, salt, createdAt: new Date().toISOString() };
        await context.env.DNS_GATEWAY_KV.put('admin_user', JSON.stringify(user));
        const authToken = await createAuthToken(passwordHash);
        return new Response(JSON.stringify({ token: authToken, username: user.username }), { headers: apiHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Registration failed' }), { status: 400, headers: apiHeaders });
      }
    }

    // POST /api/auth — Login
    if (path === '/api/auth' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ token: 'open', noAuth: true }), { headers: apiHeaders });
      if (!adminUser) return new Response(JSON.stringify({ needsSetup: true }), { headers: apiHeaders });
      try {
        const body = await request.json();
        const inputHash = await hashPassword(body.password, adminUser.salt);
        if (body.username === adminUser.username && inputHash === adminUser.passwordHash) {
          const authToken = await createAuthToken(adminUser.passwordHash);
          return new Response(JSON.stringify({ token: authToken, username: adminUser.username }), { headers: apiHeaders });
        }
      } catch {}
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers: apiHeaders });
    }

    // Auth middleware — require login if admin user exists
    if (adminUser) {
      const authHeader = request.headers.get('Authorization');
      const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!bearerToken || !await verifyAuthToken(bearerToken, adminUser.passwordHash)) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: apiHeaders });
      }
    }

    // GET /api/config — Read current config + stats
    if (path === '/api/config' && request.method === 'GET') {
      return new Response(JSON.stringify({ config: getCurrentConfig(), stats: getCurrentStats(context.env, adminUser) }), { headers: apiHeaders });
    }

    // POST /api/config — Update config (partial)
    if (path === '/api/config' && request.method === 'POST') {
      try {
        const updates = await request.json();
        await saveConfigToKV(context.env, updates);
        return new Response(JSON.stringify({ ok: true, config: getCurrentConfig(), stats: getCurrentStats(context.env, adminUser) }), { headers: apiHeaders });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: apiHeaders });
      }
    }

    // GET /api/lists — Read custom domain lists
    if (path === '/api/lists' && request.method === 'GET') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({}), { headers: apiHeaders });
      const custom = await context.env.DNS_GATEWAY_KV.get('custom_domains', 'json').catch(() => null) || {};
      return new Response(JSON.stringify(custom), { headers: apiHeaders });
    }

    // POST /api/lists/add — Add entries to a list
    if (path === '/api/lists/add' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ error: 'KV not configured' }), { status: 503, headers: apiHeaders });
      try {
        const body = await request.json();
        const { type, entries } = body;
        const validTypes = ['blocklist', 'allowlist', 'private_tlds', 'mullvad_upstream', 'redirect_rules'];
        if (!validTypes.includes(type) || !Array.isArray(entries)) return new Response(JSON.stringify({ error: 'Invalid type or entries' }), { status: 400, headers: apiHeaders });
        const custom = await context.env.DNS_GATEWAY_KV.get('custom_domains', 'json').catch(() => null) || {};
        if (!custom[type]) custom[type] = [];
        if (type === 'redirect_rules') {
          for (const e of entries) {
            if (e.source && e.target && !custom[type].find(r => r.source === e.source.toLowerCase())) {
              custom[type].push({ source: e.source.toLowerCase(), target: e.target.toLowerCase() });
            }
          }
        } else {
          for (const e of entries) {
            const d = String(e).trim().toLowerCase();
            if (d && DOMAIN_REGEX.test(d) && !custom[type].includes(d)) custom[type].push(d);
          }
        }
        await context.env.DNS_GATEWAY_KV.put('custom_domains', JSON.stringify(custom));
        blocklistLastFetch = 0; blocklistsFetched = false;
        return new Response(JSON.stringify({ ok: true, lists: custom }), { headers: apiHeaders });
      } catch { return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: apiHeaders }); }
    }

    // POST /api/lists/remove — Remove entries from a list
    if (path === '/api/lists/remove' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ error: 'KV not configured' }), { status: 503, headers: apiHeaders });
      try {
        const body = await request.json();
        const { type, entries } = body;
        const validTypes = ['blocklist', 'allowlist', 'private_tlds', 'mullvad_upstream', 'redirect_rules'];
        if (!validTypes.includes(type) || !Array.isArray(entries)) return new Response(JSON.stringify({ error: 'Invalid type or entries' }), { status: 400, headers: apiHeaders });
        const custom = await context.env.DNS_GATEWAY_KV.get('custom_domains', 'json').catch(() => null) || {};
        if (!custom[type]) return new Response(JSON.stringify({ ok: true, lists: custom }), { headers: apiHeaders });
        if (type === 'redirect_rules') {
          const removeSet = new Set(entries.map(e => String(e).toLowerCase()));
          custom[type] = custom[type].filter(r => !removeSet.has(r.source));
        } else {
          const removeSet = new Set(entries.map(e => String(e).trim().toLowerCase()));
          custom[type] = custom[type].filter(d => !removeSet.has(d));
        }
        await context.env.DNS_GATEWAY_KV.put('custom_domains', JSON.stringify(custom));
        blocklistLastFetch = 0; blocklistsFetched = false;
        return new Response(JSON.stringify({ ok: true, lists: custom }), { headers: apiHeaders });
      } catch { return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: apiHeaders }); }
    }

    // GET /api/urls — Read custom external list URLs
    if (path === '/api/urls' && request.method === 'GET') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({}), { headers: apiHeaders });
      const urls = await context.env.DNS_GATEWAY_KV.get('custom_urls', 'json').catch(() => null) || {};
      return new Response(JSON.stringify(urls), { headers: apiHeaders });
    }

    // POST /api/urls/add — Add external list URL
    if (path === '/api/urls/add' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ error: 'KV not configured' }), { status: 503, headers: apiHeaders });
      try {
        const body = await request.json();
        const { type, url } = body;
        if (!['blocklist', 'allowlist'].includes(type) || !url) return new Response(JSON.stringify({ error: 'Invalid type or url' }), { status: 400, headers: apiHeaders });
        const urls = await context.env.DNS_GATEWAY_KV.get('custom_urls', 'json').catch(() => null) || {};
        if (!urls[type]) urls[type] = [];
        const u = url.trim();
        if (u && !urls[type].includes(u)) urls[type].push(u);
        await context.env.DNS_GATEWAY_KV.put('custom_urls', JSON.stringify(urls));
        blocklistLastFetch = 0; blocklistsFetched = false;
        return new Response(JSON.stringify({ ok: true, urls }), { headers: apiHeaders });
      } catch { return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: apiHeaders }); }
    }

    // POST /api/urls/remove — Remove external list URL
    if (path === '/api/urls/remove' && request.method === 'POST') {
      if (!context.env?.DNS_GATEWAY_KV) return new Response(JSON.stringify({ error: 'KV not configured' }), { status: 503, headers: apiHeaders });
      try {
        const body = await request.json();
        const { type, url } = body;
        if (!['blocklist', 'allowlist'].includes(type) || !url) return new Response(JSON.stringify({ error: 'Invalid type or url' }), { status: 400, headers: apiHeaders });
        const urls = await context.env.DNS_GATEWAY_KV.get('custom_urls', 'json').catch(() => null) || {};
        if (urls[type]) urls[type] = urls[type].filter(u => u !== url);
        await context.env.DNS_GATEWAY_KV.put('custom_urls', JSON.stringify(urls));
        blocklistLastFetch = 0; blocklistsFetched = false;
        return new Response(JSON.stringify({ ok: true, urls }), { headers: apiHeaders });
      } catch { return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: apiHeaders }); }
    }

    // GET /api/rules-content — Read rule files content
    if (path === '/api/rules-content' && request.method === 'GET') {
      const baseUrl = new URL(request.url).origin;
      const result = {};
      const files = { allowlists: ALLOWLIST_URL, private_tlds: PRIVATE_TLD_URL, redirect_rules: REDIRECT_RULES_URL, mullvad_upstream: MULLVAD_UPSTREAM_URL };
      await Promise.all(Object.entries(files).map(async ([name, fileUrl]) => {
        try {
          const res = await fetch(new URL(fileUrl, baseUrl).toString(), { signal: AbortSignal.timeout(5000) });
          result[name] = res.ok ? await res.text() : '# Error loading file';
        } catch { result[name] = '# Error loading file'; }
      }));
      return new Response(JSON.stringify(result), { headers: apiHeaders });
    }

    return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers: apiHeaders });
  }

  // Unknown route — return 404 (landing page served as static index.html)
  return new Response('Not Found', { status: 404 });
}

export async function onRequest(context) {
  return handleRequest(context.request, context);
}
