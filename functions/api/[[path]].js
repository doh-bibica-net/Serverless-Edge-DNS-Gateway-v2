/**
 * Serverless Edge DNS Gateway — API Backend
 * Cloudflare Pages Function: functions/api/[[path]].js
 *
 * KV keys used (all in DNS_GATEWAY_KV):
 *   cfg              → JSON object  — all gateway settings
 *   auth:admin       → JSON object  — { username, hash, salt }
 *   token:<tok>      → JSON object  — { username, expires }  (TTL 7d)
 *   list:blocklist        → JSON array of domain strings
 *   list:allowlist        → JSON array of domain strings
 *   list:redirect_rules   → JSON array of { source, target }
 *   list:private_tlds     → JSON array of domain strings
 *   list:mullvad_upstream → JSON array of domain strings
 *   urls:blocklist   → JSON array of subscription URL strings
 *   urls:allowlist   → JSON array of subscription URL strings
 *   stats:lastFetch  → ISO date string
 */

// ─── Default gateway configuration ────────────────────────────────────────────
const DEFAULT_CONFIG = {
  // Features
  AD_BLOCK_ENABLED:          true,
  ECS_INJECTION_ENABLED:     true,
  BLOCK_PRIVATE_TLD:         true,
  DNS_REDIRECT_ENABLED:      false,
  MULLVAD_UPSTREAM_ENABLED:  false,
  DEBUG_ENABLED:             false,
  // Query type filters
  BLOCK_ANY:   true,
  BLOCK_AAAA:  false,
  BLOCK_PTR:   false,
  BLOCK_HTTPS: false,
  // Upstreams
  UPSTREAM_PRIMARY:    'https://cloudflare-dns.com/dns-query',
  UPSTREAM_FALLBACK:   'https://dns.google/dns-query',
  UPSTREAM_GEO_BYPASS: 'https://1.1.1.1/dns-query',
  UPSTREAM_TIMEOUT:              5000,
  ECS_PREFIX_V4:                   24,
  ECS_PREFIX_V6:                   48,
  ALL_LISTS_REFRESH_INTERVAL: 3600000,
  // Static source URLs (optional — shown as read-only info in admin)
  BLOCKLIST_URL:       '',
  ALLOWLIST_URL:       '',
  PRIVATE_TLD_URL:     '',
  MULLVAD_UPSTREAM_URL:'',
  REDIRECT_RULES_URL:  '',
};

// ─── Token TTL ─────────────────────────────────────────────────────────────────
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// ──────────────────────────────────────────────────────────────────────────────
export async function onRequest(context) {
  const { request, env } = context;
  const url    = new URL(request.url);
  const method = request.method.toUpperCase();

  // Strip leading /api/ to get the sub-path, e.g. "config", "lists/add"
  const path = url.pathname.replace(/^\/+api\/+/, '').replace(/\/+$/, '');

  // ── CORS pre-flight ──────────────────────────────────────────────────────────
  const CORS = {
    'Access-Control-Allow-Origin':  '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  // ── Helpers ──────────────────────────────────────────────────────────────────
  const json = (data, status = 200) =>
    new Response(JSON.stringify(data), {
      status,
      headers: { ...CORS, 'Content-Type': 'application/json' },
    });

  // ── KV guard ─────────────────────────────────────────────────────────────────
  if (!env.DNS_GATEWAY_KV) {
    return json({ error: 'KV namespace DNS_GATEWAY_KV is not bound' }, 503);
  }
  const KV = env.DNS_GATEWAY_KV;

  // ── KV wrappers ──────────────────────────────────────────────────────────────
  const kvGet  = async (key, fallback = null) => {
    const raw = await KV.get(key);
    return raw !== null ? JSON.parse(raw) : fallback;
  };
  const kvPut  = (key, val, opts) => KV.put(key, JSON.stringify(val), opts);

  const getConfig   = ()        => kvGet('cfg', { ...DEFAULT_CONFIG });
  const saveConfig  = (cfg)     => kvPut('cfg', cfg);
  const getAdmin    = ()        => kvGet('auth:admin', null);
  const getList     = (type)    => kvGet(`list:${type}`, []);
  const saveList    = (type, v) => kvPut(`list:${type}`, v);
  const getUrls     = (type)    => kvGet(`urls:${type}`, []);
  const saveUrls    = (type, v) => kvPut(`urls:${type}`, v);

  const getAllLists = async () => {
    const [blocklist, allowlist, redirect_rules, private_tlds, mullvad_upstream] =
      await Promise.all([
        getList('blocklist'),
        getList('allowlist'),
        getList('redirect_rules'),
        getList('private_tlds'),
        getList('mullvad_upstream'),
      ]);
    return { blocklist, allowlist, redirect_rules, private_tlds, mullvad_upstream };
  };

  const getAllUrls = async () => {
    const [blocklist, allowlist] = await Promise.all([
      getUrls('blocklist'), getUrls('allowlist'),
    ]);
    return { blocklist, allowlist };
  };

  // ── Auth helpers ─────────────────────────────────────────────────────────────
  const hashPassword = async (password, salt) => {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100_000, hash: 'SHA-256' },
      key, 256,
    );
    return Array.from(new Uint8Array(bits))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const generateToken = () => {
    const buf = new Uint8Array(32);
    crypto.getRandomValues(buf);
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const verifyToken = async (raw) => {
    if (!raw || raw === 'open') return null;
    const data = await kvGet(`token:${raw}`, null);
    if (!data) return null;
    if (data.expires && Date.now() > data.expires) {
      await KV.delete(`token:${raw}`);
      return null;
    }
    return data.username;
  };

  const requireAuth = async () => {
    const header = request.headers.get('Authorization') || '';
    const tok    = header.replace(/^Bearer\s+/i, '').trim();
    return verifyToken(tok);
  };

  // ── Build stats object ────────────────────────────────────────────────────────
  const buildStats = async (admin) => {
    const [lists, lastFetch] = await Promise.all([
      getAllLists(),
      KV.get('stats:lastFetch'),
    ]);
    return {
      hasKV:             true,
      hasAuth:           !!admin,
      needsSetup:        !admin,
      blocklistSize:     lists.blocklist.length,
      allowlistSize:     lists.allowlist.length,
      redirectRulesSize: lists.redirect_rules.length,
      privateTldsSize:   lists.private_tlds.length,
      mullvadDomainsSize:lists.mullvad_upstream.length,
      lastFetch:         lastFetch || 'never',
    };
  };

  // ──────────────────────────────────────────────────────────────────────────────
  //  ROUTES
  // ──────────────────────────────────────────────────────────────────────────────

  // GET /api/config ─────────────────────────────────────────────────────────────
  if (path === 'config' && method === 'GET') {
    const admin = await getAdmin();

    // First-run: no admin → return setup prompt (no auth needed)
    if (!admin) {
      const [cfg, stats] = await Promise.all([getConfig(), buildStats(null)]);
      return json({ config: cfg, stats });
    }

    // Admin exists → require valid token
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    const [cfg, stats] = await Promise.all([getConfig(), buildStats(admin)]);
    return json({ config: cfg, stats });
  }

  // POST /api/config ────────────────────────────────────────────────────────────
  if (path === 'config' && method === 'POST') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    let updates;
    try { updates = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const cfg = await getConfig();
    // Merge updates — only known keys + type-safe coercion for numbers
    for (const [k, v] of Object.entries(updates)) {
      if (k in DEFAULT_CONFIG || k in cfg) {
        cfg[k] = typeof DEFAULT_CONFIG[k] === 'number' ? Number(v) || 0 : v;
      }
    }
    await saveConfig(cfg);
    const admin = await getAdmin();
    const stats = await buildStats(admin);
    return json({ config: cfg, stats });
  }

  // POST /api/register ──────────────────────────────────────────────────────────
  if (path === 'register' && method === 'POST') {
    // Only allowed when no admin exists (first-run setup)
    const existing = await getAdmin();
    if (existing) return json({ error: 'Admin account already exists' }, 400);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { username, password } = body;
    if (!username || !password)         return json({ error: 'Username and password required' }, 400);
    if (username.length < 3)            return json({ error: 'Username must be at least 3 characters' }, 400);
    if (password.length < 6)            return json({ error: 'Password must be at least 6 characters' }, 400);

    const salt  = generateToken().slice(0, 16);
    const hash  = await hashPassword(password, salt);
    const token = generateToken();

    await Promise.all([
      kvPut('auth:admin', { username, hash, salt }),
      kvPut(`token:${token}`, { username, expires: Date.now() + TOKEN_TTL_MS },
            { expirationTtl: Math.floor(TOKEN_TTL_MS / 1000) }),
    ]);

    return json({ token, username });
  }

  // POST /api/auth ──────────────────────────────────────────────────────────────
  if (path === 'auth' && method === 'POST') {
    const admin = await getAdmin();
    if (!admin) return json({ needsSetup: true });

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { username, password } = body;
    if (!username || !password) return json({ error: 'Username and password required' }, 400);

    const hash = await hashPassword(password, admin.salt);
    if (username !== admin.username || hash !== admin.hash) {
      // Constant-time comparison isn't critical here but avoid early-return
      return json({ error: 'Invalid username or password' }, 401);
    }

    const token = generateToken();
    await kvPut(
      `token:${token}`,
      { username, expires: Date.now() + TOKEN_TTL_MS },
      { expirationTtl: Math.floor(TOKEN_TTL_MS / 1000) },
    );

    return json({ token, username });
  }

  // GET /api/lists ──────────────────────────────────────────────────────────────
  if (path === 'lists' && method === 'GET') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);
    return json(await getAllLists());
  }

  // POST /api/lists/add ─────────────────────────────────────────────────────────
  if (path === 'lists/add' && method === 'POST') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { type, entries } = body;
    const VALID_TYPES = ['blocklist', 'allowlist', 'redirect_rules', 'private_tlds', 'mullvad_upstream'];
    if (!VALID_TYPES.includes(type)) return json({ error: 'Invalid list type' }, 400);
    if (!Array.isArray(entries) || entries.length === 0) return json({ error: 'entries must be a non-empty array' }, 400);

    const list = await getList(type);

    if (type === 'redirect_rules') {
      for (const e of entries) {
        if (!e.source || !e.target) continue;
        if (!list.find(r => r.source === e.source)) {
          list.push({ source: e.source.toLowerCase(), target: e.target.toLowerCase() });
        }
      }
    } else {
      for (const e of entries) {
        const domain = String(e).trim().toLowerCase();
        if (domain && !list.includes(domain)) list.push(domain);
      }
    }

    await saveList(type, list);
    return json({ lists: await getAllLists() });
  }

  // POST /api/lists/remove ──────────────────────────────────────────────────────
  if (path === 'lists/remove' && method === 'POST') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { type, entries } = body;
    if (!Array.isArray(entries)) return json({ error: 'entries must be an array' }, 400);

    let list = await getList(type);

    if (type === 'redirect_rules') {
      const toRemove = new Set(entries.map(e => String(e).toLowerCase()));
      list = list.filter(r => !toRemove.has(r.source));
    } else {
      const toRemove = new Set(entries.map(e => String(e).toLowerCase()));
      list = list.filter(d => !toRemove.has(d));
    }

    await saveList(type, list);
    return json({ lists: await getAllLists() });
  }

  // GET /api/urls ───────────────────────────────────────────────────────────────
  if (path === 'urls' && method === 'GET') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);
    return json(await getAllUrls());
  }

  // POST /api/urls/add ──────────────────────────────────────────────────────────
  if (path === 'urls/add' && method === 'POST') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { type, url: urlToAdd } = body;
    if (!['blocklist', 'allowlist'].includes(type)) return json({ error: 'Invalid type' }, 400);
    if (!urlToAdd || !/^https?:\/\//i.test(urlToAdd)) return json({ error: 'Invalid URL' }, 400);

    const urls = await getUrls(type);
    if (!urls.includes(urlToAdd)) urls.push(urlToAdd);
    await saveUrls(type, urls);

    return json({ urls: await getAllUrls() });
  }

  // POST /api/urls/remove ───────────────────────────────────────────────────────
  if (path === 'urls/remove' && method === 'POST') {
    const username = await requireAuth();
    if (!username) return json({ error: 'Unauthorized' }, 401);

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Invalid JSON' }, 400); }

    const { type, url: urlToRemove } = body;
    const urls = (await getUrls(type)).filter(u => u !== urlToRemove);
    await saveUrls(type, urls);

    return json({ urls: await getAllUrls() });
  }

  // ── 404 ──────────────────────────────────────────────────────────────────────
  return json({ error: `Unknown endpoint: ${method} /api/${path}` }, 404);
}
