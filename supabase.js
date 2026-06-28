const SUPABASE_URL = 'https://lzsjnsiokasozeipvszj.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx6c2puc2lva2Fzb3plaXB2c3pqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODA2OTIyNzcsImV4cCI6MjA5NjI2ODI3N30.7ofTXdFFQIPZS55fyg0FHjWCy0LFZl3X6LkLGCgDgcc';

// ── Security: HTML escaping to prevent XSS ─────────────────────────────────
// Use this for ANY user-supplied data rendered into innerHTML
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
window.esc = esc;

// ── Core request ──────────────────────────────────────────────────────────────
async function supabaseRequest(path, options = {}) {
  const headers = {
    'apikey': SUPABASE_ANON_KEY,
    'Content-Type': 'application/json',
    ...options.headers
  };
  // Token stored in module-scoped variable, NOT on window
  const token = _getToken();
  headers['Authorization'] = token
    ? `Bearer ${token}`
    : `Bearer ${SUPABASE_ANON_KEY}`;

  const res = await fetch(`${SUPABASE_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ message: res.statusText }));
    throw new Error(err.message || err.error_description || `HTTP ${res.status}`);
  }
  const ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

// ── Token storage (sessionStorage preferred over localStorage) ───────────────
// sessionStorage: cleared when tab closes — safer than localStorage
// Falls back to localStorage for "remember me" across tabs (staff portals need this)
let _memToken = null;
let _memUser  = null;

function _storeToken(token, user, persistent = true) {
  _memToken = token;
  _memUser  = user;
  // Use sessionStorage for guests, localStorage for staff (persistent login)
  try {
    sessionStorage.setItem('sb_token', token);
    sessionStorage.setItem('sb_user',  JSON.stringify(user));
    if (persistent) {
      localStorage.setItem('sb_token', token);
      localStorage.setItem('sb_user',  JSON.stringify(user));
    }
  } catch(e) {}
}

function _clearToken() {
  _memToken = null;
  _memUser  = null;
  try {
    sessionStorage.removeItem('sb_token');
    sessionStorage.removeItem('sb_user');
    localStorage.removeItem('sb_token');
    localStorage.removeItem('sb_user');
    // Clear legacy keys from old version
    localStorage.removeItem('shalabya_token');
    localStorage.removeItem('shalabya_user');
  } catch(e) {}
}

function _isExpired(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload.exp && payload.exp * 1000 < Date.now() + 5000; // 5s buffer
  } catch(e) { return false; }
}

function _getToken() {
  if (_memToken) {
    if (_isExpired(_memToken)) { _clearToken(); return null; }
    return _memToken;
  }
  try {
    const t = sessionStorage.getItem('sb_token') || localStorage.getItem('sb_token') || localStorage.getItem('shalabya_token');
    if (t) {
      if (_isExpired(t)) { _clearToken(); return null; }
      _memToken = t;
      return t;
    }
  } catch(e) {}
  return null;
}

function _getUser() {
  if (_memUser) return _memUser;
  try {
    const u = sessionStorage.getItem('sb_user') || localStorage.getItem('sb_user') || localStorage.getItem('shalabya_user');
    if (u) { _memUser = JSON.parse(u); return _memUser; }
  } catch(e) {}
  return null;
}

// ── Query builder ─────────────────────────────────────────────────────────────
function buildQuery(table) {
  const state = {
    _select: '*',
    _filters: [],
    _orders:  [],
    _limit:   null
  };

  function buildURL() {
    let qs = `select=${encodeURIComponent(state._select)}`;
    state._filters.forEach(f => { qs += '&' + f; });
    if (state._orders.length) qs += '&order=' + state._orders.join(',');
    if (state._limit)         qs += '&limit=' + state._limit;
    return `/rest/v1/${table}?${qs}`;
  }

  function flush() {
    return supabaseRequest(buildURL(), { method: 'GET' });
  }

  function chain(newState) {
    Object.assign(state, newState);
    const proxy = {
      select: (cols)      => chain({ _select: cols }),
      eq:    (col, val)   => chain({ _filters: [...state._filters, `${col}=eq.${encodeURIComponent(val)}`] }),
      neq:   (col, val)   => chain({ _filters: [...state._filters, `${col}=neq.${encodeURIComponent(val)}`] }),
      gte:   (col, val)   => chain({ _filters: [...state._filters, `${col}=gte.${encodeURIComponent(val)}`] }),
      lte:   (col, val)   => chain({ _filters: [...state._filters, `${col}=lte.${encodeURIComponent(val)}`] }),
      in:    (col, vals)  => chain({ _filters: [...state._filters, `${col}=in.(${vals.map(v => encodeURIComponent(v)).join(',')})`] }),
      order: (col, { ascending = true } = {}) => chain({ _orders: [...state._orders, `${col}.${ascending ? 'asc' : 'desc'}`] }),
      limit: (n)          => chain({ _limit: n }),
      then:  (res, rej)   => flush().then(res, rej),
      catch: (rej)        => flush().catch(rej)
    };
    Object.assign(state, newState);
    return proxy;
  }

  return {
    select: (cols = '*') => chain({ _select: cols }),
    then:  (res, rej)    => flush().then(res, rej),
    catch: (rej)         => flush().catch(rej)
  };
}

// ── db object ─────────────────────────────────────────────────────────────────
const db = {
  from: (table) => ({
    select: (cols = '*') => buildQuery(table).select(cols),

    insert: (data) => supabaseRequest(`/rest/v1/${table}`, {
      method: 'POST',
      headers: { 'Prefer': 'return=representation' },
      body: JSON.stringify(data)
    }),

    update: (data) => ({
      eq: (col, val) => supabaseRequest(
        `/rest/v1/${table}?${col}=eq.${encodeURIComponent(val)}`,
        { method: 'PATCH', headers: { 'Prefer': 'return=representation' }, body: JSON.stringify(data) }
      )
    }),

    delete: () => ({
      eq: (col, val) => supabaseRequest(
        `/rest/v1/${table}?${col}=eq.${encodeURIComponent(val)}`,
        { method: 'DELETE' }
      )
    })
  }),

  rpc: (fn, params = {}) => supabaseRequest(`/rest/v1/rpc/${fn}`, {
    method: 'POST', body: JSON.stringify(params)
  }),

  auth: {
    signInWithPassword: async ({ email, password }) => {
      const res = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { 'apikey': SUPABASE_ANON_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error_description || data.message || 'Login failed');
      _storeToken(data.access_token, data.user, true);
      return data;
    },
    signOut: async () => {
      await supabaseRequest('/auth/v1/logout', { method: 'POST' }).catch(() => {});
      _clearToken();
    },
    getSession: () => {
      const token = _getToken();
      const user  = _getUser();
      if (token && user) return { token, user };
      return null;
    },
    getUser: () => _getUser()
  }
};

// Expose only db and esc — NOT the raw key or URL
window.db  = db;
window.esc = esc;
// SUPABASE_URL and SUPABASE_ANON_KEY intentionally NOT on window
