/* ==========================================================================
   Private vault layer.
   • Supabase Auth (email + password) for identity and roles
   • Supabase Storage (private bucket) holds ONLY ciphertext
   • AES-256-GCM, key = PBKDF2-SHA256(passphrase, salt, 600k) — derived in the
     browser, kept in memory as a non-extractable CryptoKey, never persisted.
   ========================================================================== */
(() => {
  'use strict';
  const CFG = window.PC_CONFIG || {};
  const $ = (s, r = document) => r.querySelector(s);
  const root = document.getElementById('vault');
  const calcEl = document.getElementById('calc');
  const enc = new TextEncoder(), dec = new TextDecoder();
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const BUCKET = 'vault';
  const KDF_ITER = 600000;
  const VERIFIER_TEXT = 'pocket-vault-ok';
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  /* ---------------------------------------------------------------- icons -- */
  const ico = (p) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
  const I = {
    lock: ico('<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
    search: ico('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'),
    upload: ico('<path d="M12 16V4m0 0-4 4m4-4 4 4"/><path d="M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3"/>'),
    select: ico('<rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="m8 12 3 3 5-6"/>'),
    refresh: ico('<path d="M20 11a8 8 0 0 0-14-4L4 9"/><path d="M4 4v5h5"/><path d="M4 13a8 8 0 0 0 14 4l2-2"/><path d="M20 20v-5h-5"/>'),
    shield: ico('<path d="M12 3 5 6v5c0 4.5 3 8 7 10 4-2 7-5.5 7-10V6z"/><path d="m9 12 2 2 4-4"/>'),
    sliders: ico('<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>'),
    logout: ico('<path d="M9 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h4"/><path d="m16 8 4 4-4 4M20 12H9"/>'),
    close: ico('<path d="M6 6l12 12M18 6 6 18"/>'),
    left: ico('<path d="m15 5-7 7 7 7"/>'),
    right: ico('<path d="m9 5 7 7-7 7"/>'),
    download: ico('<path d="M12 4v12m0 0-4-4m4 4 4-4"/><path d="M4 18v1a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-1"/>'),
    edit: ico('<path d="M4 20h4L19 9l-4-4L4 16z"/>'),
    trash: ico('<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-12M9 7V4h6v3"/>'),
    check: ico('<path d="m5 12 5 5 9-10"/>'),
    image: ico('<rect x="3" y="4" width="18" height="16" rx="2.5"/><circle cx="9" cy="10" r="1.6"/><path d="m4 18 5-5 4 4 3-3 4 4"/>'),
    plus: ico('<path d="M12 5v14M5 12h14"/>'),
  };

  /* ---------------------------------------------------------------- state -- */
  const S = {
    open: false, sb: null, user: null, profile: null, meta: null, key: null,
    items: [], cat: 'All', q: '', sort: 'new', selecting: false, sel: new Set(),
    viewer: null, lastRefresh: 0,
  };
  const thumbCache = new Map();   // id -> objectURL
  const fullCache = new Map();    // id -> objectURL (LRU, small)
  let ac = null, idleTimer = 0, hideTimer = 0, lastEsc = 0;

  /* --------------------------------------------------------------- helpers -- */
  const b64e = (u8) => { let s = ''; const c = 0x8000; for (let i = 0; i < u8.length; i += c) s += String.fromCharCode.apply(null, u8.subarray(i, i + c)); return btoa(s); };
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const fmtBytes = (n) => { n = Number(n) || 0; const u = ['B', 'KB', 'MB', 'GB']; let i = 0; while (n >= 1024 && i < 3) { n /= 1024; i++; } return (i ? n.toFixed(n < 10 ? 1 : 0) : n) + ' ' + u[i]; };
  const fmtDate = (d) => { try { return new Date(d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); } catch { return ''; } };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const tick = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 20)));
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const u32 = (u8) => new DataView(u8.buffer, u8.byteOffset, 4).getUint32(0);
  const putU32 = (n) => { const u = new Uint8Array(4); new DataView(u.buffer).setUint32(0, n); return u; };

  function limiter(n) {
    let active = 0; const q = [];
    const next = () => {
      if (active >= n || !q.length) return;
      active++; const { fn, res, rej } = q.shift();
      fn().then(res, rej).finally(() => { active--; next(); });
    };
    return (fn) => new Promise((res, rej) => { q.push({ fn, res, rej }); next(); });
  }
  const thumbLimit = limiter(4);

  function friendly(e) {
    const m = String(e?.message || e || 'Something went wrong');
    if (/invalid login credentials/i.test(m)) return 'Email or password is incorrect.';
    if (/failed to fetch|networkerror|load failed/i.test(m)) return 'Can’t reach Supabase. Check your connection and config.js.';
    if (/does not exist|schema cache|Could not find the (table|function)/i.test(m)) return 'The database isn’t set up yet. Run supabase-schema.sql in the Supabase SQL editor.';
    if (/rate limit|too many/i.test(m)) return 'Too many attempts. Wait a minute and try again.';
    if (/row-level security|violates row/i.test(m)) return 'Permission denied by the server.';
    return m;
  }

  function toast(msg, type = '') {
    const t = document.createElement('div');
    t.className = 'toast ' + type; t.textContent = msg;
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), type === 'err' ? 6500 : 3500);
  }
  const view = (html) => { root.innerHTML = html; };
  const loadingView = (msg) => `<div class="center"><div class="loading"><span class="spin"></span><div>${esc(msg)}</div></div></div>`;
  function busy(btn, on, label) {
    if (!btn) return;
    if (on) { btn.dataset.l = btn.innerHTML; btn.disabled = true; btn.innerHTML = `<span class="spin"></span>${label ? ' ' + esc(label) : ''}`; }
    else { btn.disabled = false; if (btn.dataset.l) btn.innerHTML = btn.dataset.l; }
  }

  /* -------------------------------------------------------------- crypto --- */
  const C = {
    async deriveKey(pass, saltB64, iterations) {
      const base = await crypto.subtle.importKey('raw', enc.encode(pass.normalize('NFKC')), 'PBKDF2', false, ['deriveKey']);
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: b64d(saltB64), iterations, hash: 'SHA-256' },
        base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    },
    // output = IV(12) || ciphertext||tag ; `aad` binds the blob to its id + purpose
    async enc(key, data, aad) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, data));
      const out = new Uint8Array(12 + ct.length); out.set(iv); out.set(ct, 12); return out;
    },
    async dec(key, packed, aad) {
      if (!key) throw new Error('Vault is locked');
      const u = packed instanceof Uint8Array ? packed : new Uint8Array(packed);
      return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12), additionalData: enc.encode(aad) }, key, u.subarray(12)));
    },
  };
  const encMeta = async (id, meta, key = S.key) => b64e(await C.enc(key, enc.encode(JSON.stringify(meta)), id + '|meta'));
  const decMeta = async (id, b64, key = S.key) => JSON.parse(dec.decode(await C.dec(key, b64d(b64), id + '|meta')));

  async function createVault(pass) {
    const saltB64 = b64e(crypto.getRandomValues(new Uint8Array(16)));
    const key = await C.deriveKey(pass, saltB64, KDF_ITER);
    const verifier = b64e(await C.enc(key, enc.encode(VERIFIER_TEXT), 'verifier'));
    const row = { id: 1, salt: saltB64, iterations: KDF_ITER, verifier };
    const { error } = await S.sb.from('vault_meta').insert(row);
    if (error) throw error;
    S.meta = row; S.key = key;
  }
  async function unlockWith(pass, meta = S.meta) {
    const key = await C.deriveKey(pass, meta.salt, meta.iterations);
    try {
      const v = dec.decode(await C.dec(key, b64d(meta.verifier), 'verifier'));
      if (v !== VERIFIER_TEXT) throw 0;
    } catch { throw new Error('Wrong vault passphrase.'); }
    return key;
  }

  /* ------------------------------------------------------------- supabase -- */
  const remember = () => { try { return localStorage.getItem('pc.r') === '1'; } catch { return false; } };
  const setRemember = (v) => { try { localStorage.setItem('pc.r', v ? '1' : '0'); } catch {} };
  const authStorage = {
    getItem: (k) => { try { return sessionStorage.getItem(k) ?? localStorage.getItem(k); } catch { return null; } },
    setItem: (k, v) => { try { const keep = remember(); (keep ? localStorage : sessionStorage).setItem(k, v); (keep ? sessionStorage : localStorage).removeItem(k); } catch {} },
    removeItem: (k) => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch {} },
  };
  function client() {
    if (S.sb) return S.sb;
    if (!window.supabase) throw new Error('Couldn’t load the Supabase library. Check your connection.');
    if (!CFG.SUPABASE_URL || /YOUR-PROJECT/.test(CFG.SUPABASE_URL) || !CFG.SUPABASE_ANON_KEY || /YOUR-ANON/.test(CFG.SUPABASE_ANON_KEY))
      throw new Error('Backend not configured. Add your Supabase URL and anon key to config.js.');
    S.sb = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, {
      auth: { storage: authStorage, storageKey: 'pc.auth', persistSession: true, autoRefreshToken: true, detectSessionInUrl: false },
    });
    return S.sb;
  }

  /* ---------------------------------------------------------- open / lock --- */
  function isOpen() { return S.open; }
  function open() {
    if (S.open) return;
    S.open = true; root.hidden = false; calcEl.setAttribute('aria-hidden', 'true');
    ac = new AbortController();
    const o = { signal: ac.signal };
    window.addEventListener('keydown', onKey, o);
    window.addEventListener('paste', onPaste, o);
    document.addEventListener('visibilitychange', onVis, o);
    ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((ev) => root.addEventListener(ev, bump, { passive: true, signal: ac.signal }));
    route();
  }
  function lock() {
    if (!S.open) return;
    ac && ac.abort(); clearTimeout(idleTimer); clearTimeout(hideTimer);
    S.key = null; S.items = []; S.sel.clear(); S.selecting = false; S.viewer = null; S.cat = 'All'; S.q = '';
    thumbCache.forEach((u) => URL.revokeObjectURL(u)); thumbCache.clear();
    fullCache.forEach((u) => URL.revokeObjectURL(u)); fullCache.clear();
    root.innerHTML = ''; root.hidden = true; calcEl.removeAttribute('aria-hidden');
    S.open = false;
    window.PCCalc && window.PCCalc.reset();
  }
  async function logout() {
    try { if (S.sb) await S.sb.auth.signOut(); } catch {}
    S.user = null; S.profile = null; S.meta = null;
    lock();
  }
  function idleMs() { let m = 5; try { m = parseInt(localStorage.getItem('pc.al') ?? '5', 10); } catch {} return m > 0 ? m * 60000 : 0; }
  function bump() { clearTimeout(idleTimer); const ms = idleMs(); if (ms && S.key) idleTimer = setTimeout(lock, ms); }
  function onVis() {
    if (document.hidden) { clearTimeout(hideTimer); if (S.key) hideTimer = setTimeout(lock, 60000); }
    else {
      clearTimeout(hideTimer);
      if (S.key && $('#gw') && Date.now() - S.lastRefresh > 20000) softRefresh();
    }
  }
  function onKey(e) {
    if (e.key === 'Escape') {
      const scrims = root.querySelectorAll('.scrim');
      if (scrims.length) { const sc = scrims[scrims.length - 1]; sc._close && sc._close(); return; }
      if (S.viewer) { S.viewer.close(); return; }
      const now = Date.now();
      if (now - lastEsc < 600) { lock(); return; }   // double-Esc = panic
      lastEsc = now; return;
    }
    if (S.viewer && !root.querySelector('.scrim')) {
      if (e.key === 'ArrowRight') S.viewer.go(1);
      else if (e.key === 'ArrowLeft') S.viewer.go(-1);
      else if (e.key === '+' || e.key === '=') S.viewer.zoom(1.25);
      else if (e.key === '-') S.viewer.zoom(0.8);
    }
  }
  function onPaste(e) {
    if (!S.key || !$('#gw') || /input|textarea/i.test(e.target.tagName)) return;
    const files = [...(e.clipboardData?.files || [])].filter((f) => f.type.startsWith('image/'));
    if (files.length) { e.preventDefault(); startUpload(files); }
  }

  /* ---------------------------------------------------------------- route --- */
  async function route() {
    view(loadingView('Opening…'));
    try {
      const sb = client();
      const { data: { session } } = await sb.auth.getSession();
      if (session) {
        const { data: u, error } = await sb.auth.getUser();      // verifies with the server
        if (!error && u?.user) { S.user = u.user; return await afterAuth(); }
        await sb.auth.signOut();
      }
      const { data: init, error } = await sb.rpc('vault_initialized');
      if (error) throw error;
      init ? showLogin() : showSetup();
    } catch (e) { showFatal(friendly(e)); }
  }

  async function afterAuth() {
    const sb = client();
    const { data: prof, error } = await sb.from('profiles').select('*').eq('id', S.user.id).maybeSingle();
    if (error) throw error;
    if (!prof) { await sb.auth.signOut(); return showLogin('This account has no vault profile.'); }
    S.profile = prof;
    if (prof.role === 'pending') return showBlocked('Waiting for approval', 'Your account exists, but the admin hasn’t approved it yet.');
    if (prof.role === 'disabled') return showBlocked('Access removed', 'The admin has turned off this account.');
    const { data: meta, error: e2 } = await sb.from('vault_meta').select('*').eq('id', 1).maybeSingle();
    if (e2) throw e2;
    S.meta = meta;
    if (!meta) return prof.role === 'admin' ? showVaultSetup() : showBlocked('Vault not ready', 'The admin hasn’t finished creating the vault yet.');
    if (S.key) return showMain();
    showUnlock();
  }

  /* ----------------------------------------------------------- auth views --- */
  function strength(p) {
    let v = 0; if (/[a-z]/.test(p)) v++; if (/[A-Z]/.test(p)) v++; if (/\d/.test(p)) v++; if (/[^A-Za-z0-9]/.test(p)) v++; if (/\s/.test(p)) v++;
    const score = clamp(p.length * 4 + v * 6, 0, 100);
    return { score, label: p.length < 12 ? 'Too short — use 12 or more characters.' : score < 60 ? 'Okay. Add more words to make it stronger.' : score < 85 ? 'Good.' : 'Strong.' };
  }
  function bindMeter(inp, bar, txt) {
    inp.addEventListener('input', () => {
      const s = strength(inp.value);
      bar.style.width = s.score + '%';
      bar.style.background = s.score < 50 ? 'var(--rose)' : s.score < 80 ? 'var(--amber)' : 'var(--ok)';
      txt.textContent = inp.value ? s.label : 'Use 12+ characters — four random words works well.';
    });
  }
  const backBtn = () => root.querySelector('#back')?.addEventListener('click', () => lock());

  function showFatal(msg) {
    view(`<div class="center"><div class="card glass"><div class="mark">${I.lock}</div><h1>Can’t continue</h1><p class="sub">${esc(msg)}</p>
      <div class="row"><button class="btn" id="retry">Try again</button><button class="btn ghost" id="back">Back to calculator</button></div></div></div>`);
    $('#retry').onclick = route; backBtn();
  }
  function showBlocked(title, text) {
    view(`<div class="center"><div class="card glass"><div class="mark">${I.lock}</div><h1>${esc(title)}</h1><p class="sub">${esc(text)}</p>
      <div class="row"><button class="btn" id="out">Sign out</button><button class="btn ghost" id="back">Back to calculator</button></div></div></div>`);
    $('#out').onclick = logout; backBtn();
  }

  function showLogin(msg) {
    view(`<div class="center"><form class="card glass" id="f" autocomplete="on">
      <div class="mark">${I.lock}</div><h1>Sign in</h1><p class="sub">Use your vault account.</p>
      <label class="f"><span>Email</span><input class="in" type="email" id="em" autocomplete="username" required></label>
      <label class="f"><span>Password</span><input class="in" type="password" id="pw" autocomplete="current-password" required></label>
      <label class="check"><input type="checkbox" id="rm" ${remember() ? 'checked' : ''}> Keep me signed in on this device</label>
      <p class="err" id="err">${esc(msg || '')}</p>
      <button class="btn primary block" id="go">Sign in</button>
      <div class="row" style="margin-top:14px"><button type="button" class="link" id="back">Back to calculator</button></div>
    </form></div>`);
    backBtn(); $('#em').focus();
    $('#f').onsubmit = async (e) => {
      e.preventDefault(); $('#err').textContent = '';
      busy($('#go'), true, 'Signing in');
      try {
        setRemember($('#rm').checked);
        const { data, error } = await client().auth.signInWithPassword({ email: $('#em').value.trim(), password: $('#pw').value });
        if (error) throw error;
        S.user = data.user; await afterAuth();
      } catch (er) { const f = $('#err'); if (f) { f.textContent = friendly(er); busy($('#go'), false); } else showFatal(friendly(er)); }
    };
  }

  function showSetup() {
    view(`<div class="center"><form class="card glass" id="f" autocomplete="on">
      <div class="mark">${I.lock}</div><h1>Set up your vault</h1>
      <p class="sub">Create the Admin account and the passphrase that encrypts every photo in this browser.</p>
      <label class="f"><span>Admin email</span><input class="in" type="email" id="em" autocomplete="username" required></label>
      <label class="f"><span>Account password (10+ characters)</span><input class="in" type="password" id="pw" autocomplete="new-password" required></label>
      <label class="f"><span>Confirm account password</span><input class="in" type="password" id="pw2" autocomplete="new-password" required></label>
      <label class="f"><span>Vault passphrase (12+ characters)</span><input class="in" type="password" id="ps" autocomplete="off" required></label>
      <div class="meter"><i id="mt"></i></div><p class="hint" id="mh">Use 12+ characters — four random words works well.</p>
      <label class="f"><span>Confirm vault passphrase</span><input class="in" type="password" id="ps2" autocomplete="off" required></label>
      <p class="hint">The passphrase never leaves this device. If you lose it, the photos can’t be recovered — not even by you.</p>
      <p class="err" id="err"></p>
      <button class="btn primary block" id="go">Create vault</button>
      <div class="row" style="margin-top:14px"><button type="button" class="link" id="back">Back to calculator</button></div>
    </form></div>`);
    backBtn(); bindMeter($('#ps'), $('#mt'), $('#mh')); $('#em').focus();
    $('#f').onsubmit = async (e) => {
      e.preventDefault(); const err = $('#err'); err.textContent = '';
      const em = $('#em').value.trim(), pw = $('#pw').value, ps = $('#ps').value;
      if (pw.length < 10) return (err.textContent = 'Account password needs at least 10 characters.');
      if (pw !== $('#pw2').value) return (err.textContent = 'The account passwords don’t match.');
      if (ps.length < 12) return (err.textContent = 'Vault passphrase needs at least 12 characters.');
      if (ps !== $('#ps2').value) return (err.textContent = 'The vault passphrases don’t match.');
      if (ps === pw) return (err.textContent = 'Use a different vault passphrase than your account password.');
      busy($('#go'), true, 'Creating account');
      try {
        const sb = client();
        const { data, error } = await sb.auth.signUp({ email: em, password: pw });
        if (error) throw error;
        if (!data.session) throw new Error('Supabase is asking for email confirmation. Turn off “Confirm email” (Authentication → Providers → Email), delete the unconfirmed user, then try again.');
        S.user = data.user;
        const { data: prof, error: pe } = await sb.from('profiles').select('*').eq('id', S.user.id).maybeSingle();
        if (pe) throw pe;
        if (!prof || prof.role !== 'admin') { await sb.auth.signOut(); throw new Error('An admin already exists. Sign in instead.'); }
        S.profile = prof;
        $('#go').innerHTML = '<span class="spin"></span> Deriving key';
        await tick(); await createVault(ps);
        await showMain();
      } catch (er) { const f = $('#err'); if (f) { f.textContent = friendly(er); busy($('#go'), false); } else showFatal(friendly(er)); }
    };
  }

  function showVaultSetup() {
    view(`<div class="center"><form class="card glass" id="f" autocomplete="off">
      <div class="mark">${I.lock}</div><h1>Create the vault passphrase</h1>
      <p class="sub">You’re signed in as ${esc(S.user.email)}. Choose the passphrase that encrypts your photos.</p>
      <label class="f"><span>Vault passphrase (12+ characters)</span><input class="in" type="password" id="ps" autocomplete="off" required></label>
      <div class="meter"><i id="mt"></i></div><p class="hint" id="mh">Use 12+ characters — four random words works well.</p>
      <label class="f"><span>Confirm vault passphrase</span><input class="in" type="password" id="ps2" autocomplete="off" required></label>
      <p class="hint">It never leaves this device. If you lose it, the photos can’t be recovered.</p>
      <p class="err" id="err"></p>
      <button class="btn primary block" id="go">Create vault</button>
      <div class="row" style="margin-top:14px"><button type="button" class="link" id="out">Sign out</button></div>
    </form></div>`);
    $('#out').onclick = logout; bindMeter($('#ps'), $('#mt'), $('#mh')); $('#ps').focus();
    $('#f').onsubmit = async (e) => {
      e.preventDefault(); const err = $('#err'); err.textContent = '';
      const ps = $('#ps').value;
      if (ps.length < 12) return (err.textContent = 'Vault passphrase needs at least 12 characters.');
      if (ps !== $('#ps2').value) return (err.textContent = 'The passphrases don’t match.');
      busy($('#go'), true, 'Deriving key');
      try { await tick(); await createVault(ps); await showMain(); }
      catch (er) { const f = $('#err'); if (f) { f.textContent = friendly(er); busy($('#go'), false); } else showFatal(friendly(er)); }
    };
  }

  function showUnlock() {
    view(`<div class="center"><form class="card glass" id="f" autocomplete="off">
      <div class="mark">${I.lock}</div><h1>Unlock vault</h1>
      <p class="sub">Signed in as ${esc(S.user.email)}. Enter the vault passphrase.</p>
      <label class="f"><span>Vault passphrase</span><input class="in" type="password" id="ps" autocomplete="off" required></label>
      <p class="err" id="err"></p>
      <button class="btn primary block" id="go">Unlock</button>
      <div class="row sp" style="margin-top:14px"><button type="button" class="link" id="back">Back to calculator</button><button type="button" class="link" id="out">Sign out</button></div>
    </form></div>`);
    backBtn(); $('#out').onclick = logout; $('#ps').focus();
    $('#f').onsubmit = async (e) => {
      e.preventDefault(); $('#err').textContent = '';
      busy($('#go'), true, 'Unlocking');
      try { await tick(); S.key = await unlockWith($('#ps').value); await showMain(); }
      catch (er) { const f = $('#err'); if (f) { f.textContent = friendly(er); busy($('#go'), false); $('#ps').select(); } else showFatal(friendly(er)); }
    };
  }

  /* ---------------------------------------------------------------- items --- */
  async function fetchRows(cols = '*') {
    const out = [];
    for (let from = 0; ; from += 1000) {
      const { data, error } = await S.sb.from('vault_items').select(cols).order('created_at', { ascending: false }).range(from, from + 999);
      if (error) throw error;
      out.push(...data); if (data.length < 1000) break;
    }
    return out;
  }
  async function refreshItems() {
    const rows = await fetchRows();
    const items = [];
    for (const r of rows) {
      let meta, bad = false;
      try { meta = await decMeta(r.id, r.meta_enc); } catch { meta = { name: 'Unreadable item', category: 'Uncategorized' }; bad = true; }
      meta.name = meta.name || 'Untitled'; meta.category = meta.category || 'Uncategorized';
      items.push({ ...r, meta, bad });
    }
    S.items = items; S.lastRefresh = Date.now();
  }
  async function softRefresh() {
    try { await refreshItems(); if ($('#gw')) renderAll(); } catch {}
  }
  const byId = (id) => S.items.find((i) => i.id === id);

  function filtered() {
    const q = S.q.trim().toLowerCase();
    const a = S.items.filter((it) => (S.cat === 'All' || it.meta.category === S.cat) &&
      (!q || it.meta.name.toLowerCase().includes(q) || it.meta.category.toLowerCase().includes(q)));
    if (S.sort === 'old') a.sort((x, y) => new Date(x.created_at) - new Date(y.created_at));
    else if (S.sort === 'name') a.sort((x, y) => x.meta.name.localeCompare(y.meta.name, undefined, { numeric: true }));
    else a.sort((x, y) => new Date(y.created_at) - new Date(x.created_at));
    return a;
  }
  const categories = () => {
    const m = new Map(); S.items.forEach((i) => m.set(i.meta.category, (m.get(i.meta.category) || 0) + 1));
    return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  };

  /* ------------------------------------------------------------ main view --- */
  async function showMain() {
    const admin = S.profile.role === 'admin';
    view(`<div class="shell">
      <header class="top">
        <div class="brand"><div class="mark">${I.lock}</div><span class="nm">Vault</span></div>
        <div class="search">${I.search}<input class="in" id="q" type="search" placeholder="Search photos" autocomplete="off" aria-label="Search photos"></div>
        <div class="spacer"></div>
        <div class="tools">
          <button class="icon-btn" id="bUp" title="Upload photos" aria-label="Upload photos">${I.upload}</button>
          <button class="icon-btn" id="bSel" title="Select" aria-label="Select photos">${I.select}</button>
          ${admin ? `<button class="icon-btn" id="bAdmin" title="Admin" aria-label="Admin">${I.shield}</button>` : ''}
          <button class="icon-btn" id="bSet" title="Settings" aria-label="Settings">${I.sliders}</button>
          <button class="icon-btn" id="bLock" title="Lock now" aria-label="Lock now">${I.lock}</button>
        </div>
      </header>
      <div class="body">
        <aside class="side"><h3>Categories</h3><div class="cats" id="cats"></div></aside>
        <section class="main" id="main">
          <div class="bar"><h2 id="title">All photos</h2><span class="count" id="count"></span><div class="spacer"></div>
            <select class="in" id="sort" style="width:auto;padding:8px 12px" aria-label="Sort">
              <option value="new">Newest</option><option value="old">Oldest</option><option value="name">Name</option></select>
            <button class="icon-btn" id="bRef" title="Refresh" aria-label="Refresh">${I.refresh}</button>
          </div>
          <div id="selbar"></div>
          <div class="grid-wrap" id="gw"><div class="grid" id="grid"></div></div>
          <div class="drop" id="drop" hidden>Drop photos to encrypt &amp; upload</div>
        </section>
      </div>
    </div>
    <input type="file" id="file" accept="image/*,.heic,.heif" multiple hidden>`);
    $('#gw').innerHTML = `<div class="loading" style="padding:80px 0"><span class="spin"></span><div>Decrypting library…</div></div>`;
    bindMain();
    try { await refreshItems(); } catch (e) { toast(friendly(e), 'err'); }
    $('#gw').innerHTML = '<div class="grid" id="grid"></div>';
    renderAll(); bump();
  }

  function bindMain() {
    $('#bUp').onclick = () => $('#file').click();
    $('#file').onchange = (e) => { const f = [...e.target.files]; e.target.value = ''; if (f.length) startUpload(f); };
    $('#bSel').onclick = () => setSelecting(!S.selecting);
    $('#bLock').onclick = lock;
    $('#bSet').onclick = openSettings;
    if ($('#bAdmin')) $('#bAdmin').onclick = openAdmin;
    $('#bRef').onclick = async () => { try { await refreshItems(); renderAll(); toast('Library refreshed', 'ok'); } catch (e) { toast(friendly(e), 'err'); } };
    $('#q').oninput = (e) => { S.q = e.target.value; renderGrid(); };
    $('#sort').onchange = (e) => { S.sort = e.target.value; renderGrid(); };
    $('#cats').onclick = (e) => { const b = e.target.closest('[data-cat]'); if (b) { S.cat = b.dataset.cat; renderAll(); } };

    const main = $('#main'), drop = $('#drop'); let dc = 0;
    const hasFiles = (e) => [...(e.dataTransfer?.types || [])].includes('Files');
    main.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); dc++; drop.hidden = false; });
    main.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
    main.addEventListener('dragleave', () => { dc = Math.max(0, dc - 1); if (!dc) drop.hidden = true; });
    main.addEventListener('drop', (e) => { if (!hasFiles(e)) return; e.preventDefault(); dc = 0; drop.hidden = true; startUpload([...e.dataTransfer.files]); });
    window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); }, { signal: ac.signal });
    window.addEventListener('drop', (e) => { if (hasFiles(e)) e.preventDefault(); }, { signal: ac.signal });
  }

  function renderAll() { renderCats(); renderGrid(); renderSelBar(); }

  function renderCats() {
    const cats = categories();
    if (S.cat !== 'All' && !cats.find((c) => c[0] === S.cat)) S.cat = 'All';
    const el = $('#cats'); if (!el) return;
    el.innerHTML = `<button class="cat ${S.cat === 'All' ? 'on' : ''}" data-cat="All"><span class="t">All photos</span><span class="n">${S.items.length}</span></button>` +
      cats.map(([c, n]) => `<button class="cat ${S.cat === c ? 'on' : ''}" data-cat="${esc(c)}"><span class="t">${esc(c)}</span><span class="n">${n}</span></button>`).join('');
  }

  let io = null;
  function renderGrid() {
    const gw = $('#gw'); if (!gw) return;
    const list = filtered();
    $('#title').textContent = S.cat === 'All' ? 'All photos' : S.cat;
    $('#count').textContent = list.length + (list.length === 1 ? ' photo' : ' photos');
    gw.classList.toggle('selecting', S.selecting);
    if (io) io.disconnect();
    if (!list.length) {
      gw.innerHTML = S.items.length
        ? `<div class="empty"><div class="big">No matches</div>Try a different search or category.</div>`
        : `<div class="empty"><div class="big">Your vault is empty</div>Drag photos here, paste them, or tap upload. They’re encrypted before they leave this device.</div>`;
      return;
    }
    if (!$('#grid')) gw.innerHTML = '<div class="grid" id="grid"></div>';
    const g = $('#grid');
    g.innerHTML = list.map((it) => `<div class="tile ${S.sel.has(it.id) ? 'picked' : ''}" data-id="${it.id}">
      <div class="ph">${I.image}</div><img alt="${esc(it.meta.name)}" draggable="false">
      <div class="sel">${I.check}</div><div class="cap">${esc(it.meta.name)}</div></div>`).join('');
    bindGridHost();
    io = new IntersectionObserver((ents) => {
      ents.forEach((en) => { if (en.isIntersecting) { io.unobserve(en.target); loadThumb(en.target); } });
    }, { root: $('#gw'), rootMargin: '300px' });
    g.querySelectorAll('.tile').forEach((t) => io.observe(t));
  }

  function bindGridHost() {
    const g = $('#grid'); if (!g || g._bound) return; g._bound = true;
    let lp = null, lpFired = false;
    g.addEventListener('pointerdown', (e) => {
      const t = e.target.closest('.tile'); if (!t) return; lpFired = false;
      clearTimeout(lp); lp = setTimeout(() => { lpFired = true; if (!S.selecting) setSelecting(true); toggleSel(t.dataset.id); }, 520);
    });
    ['pointerup', 'pointerleave', 'pointercancel', 'pointermove'].forEach((ev) => g.addEventListener(ev, () => clearTimeout(lp)));
    g.addEventListener('contextmenu', (e) => { if (e.target.closest('.tile')) e.preventDefault(); });
    g.addEventListener('click', (e) => {
      const t = e.target.closest('.tile'); if (!t) return;
      if (lpFired) { lpFired = false; return; }
      if (S.selecting) toggleSel(t.dataset.id); else openViewer(t.dataset.id);
    });
  }

  async function loadThumb(tile) {
    const id = tile.dataset.id, it = byId(id); if (!it) return;
    const img = tile.querySelector('img'), ph = tile.querySelector('.ph');
    const show = (url) => { img.onload = () => { img.classList.add('ready'); ph.remove(); }; img.src = url; };
    if (thumbCache.has(id)) return show(thumbCache.get(id));
    if (!it.thumb_path) { ph.classList.add('dead'); return; }
    try {
      const blob = await thumbLimit(() => fetchDecrypt(it.thumb_path, id, 'thumb', 'image/jpeg'));
      if (!S.key) return;
      const url = URL.createObjectURL(blob); thumbCache.set(id, url);
      if (tile.isConnected) show(url);
    } catch { if (ph) ph.classList.add('dead'); }
  }

  async function fetchDecrypt(path, id, kind, mime) {
    const { data, error } = await S.sb.storage.from(BUCKET).download(path);
    if (error) throw error;
    const buf = new Uint8Array(await data.arrayBuffer());
    const plain = await C.dec(S.key, buf, `${id}|${kind}`);
    return new Blob([plain], { type: mime });
  }
  async function getFullUrl(it) {
    if (fullCache.has(it.id)) { const u = fullCache.get(it.id); fullCache.delete(it.id); fullCache.set(it.id, u); return u; }
    const blob = await fetchDecrypt(it.file_path, it.id, 'file', it.meta.mime || 'application/octet-stream');
    if (!S.key) throw new Error('Vault is locked');
    const url = URL.createObjectURL(blob); fullCache.set(it.id, url);
    while (fullCache.size > 8) { const k = fullCache.keys().next().value; URL.revokeObjectURL(fullCache.get(k)); fullCache.delete(k); }
    return url;
  }

  /* ------------------------------------------------------------ selection --- */
  function setSelecting(on) {
    S.selecting = on; if (!on) S.sel.clear();
    $('#bSel')?.classList.toggle('on', on); renderGrid(); renderSelBar();
  }
  function toggleSel(id) {
    S.sel.has(id) ? S.sel.delete(id) : S.sel.add(id);
    $(`.tile[data-id="${id}"]`)?.classList.toggle('picked', S.sel.has(id)); renderSelBar();
  }
  function renderSelBar() {
    const el = $('#selbar'); if (!el) return;
    if (!S.selecting) { el.innerHTML = ''; return; }
    const n = S.sel.size;
    el.innerHTML = `<div class="selbar glass"><b>${n} selected</b><div class="spacer"></div>
      <button class="btn sm" id="sAll">Select all</button>
      <button class="btn sm" id="sMove" ${n ? '' : 'disabled'}>Move</button>
      <button class="btn sm danger" id="sDel" ${n ? '' : 'disabled'}>Delete</button>
      <button class="btn sm ghost" id="sDone">Done</button></div>`;
    $('#sAll').onclick = () => { filtered().forEach((i) => S.sel.add(i.id)); renderGrid(); renderSelBar(); };
    $('#sDone').onclick = () => setSelecting(false);
    $('#sMove').onclick = async () => {
      const cat = await categoryPrompt('Move to category', `${S.sel.size} photo${S.sel.size === 1 ? '' : 's'}`, '');
      if (cat == null) return;
      await moveItems([...S.sel], cat); setSelecting(false);
    };
    $('#sDel').onclick = async () => {
      const ids = [...S.sel];
      if (!(await confirmBox(`Delete ${ids.length} photo${ids.length === 1 ? '' : 's'}?`, 'The encrypted files are removed from the server for good. This can’t be undone.', 'Delete', true))) return;
      await deleteItems(ids); setSelecting(false);
    };
  }

  /* --------------------------------------------------------------- modals --- */
  function modal(html, { wide = false, persistent = false } = {}) {
    const sc = document.createElement('div'); sc.className = 'scrim';
    sc.innerHTML = `<div class="modal glass ${wide ? 'wide' : ''}" role="dialog" aria-modal="true">${html}</div>`;
    root.appendChild(sc);
    const m = { el: sc.firstElementChild, scrim: sc, onclose: null, q: (s) => sc.querySelector(s) };
    m.close = (v) => { if (!sc.isConnected) return; sc.remove(); m.onclose && m.onclose(v); };
    sc._close = persistent ? null : () => m.close(undefined);
    if (!persistent) sc.addEventListener('mousedown', (e) => { if (e.target === sc) m.close(undefined); });
    const f = sc.querySelector('input,select,button.primary'); f && setTimeout(() => f.focus(), 30);
    return m;
  }
  function confirmBox(title, body, okText = 'OK', danger = false) {
    return new Promise((res) => {
      const m = modal(`<h3>${esc(title)}</h3><p>${esc(body)}</p><div class="acts"><button class="btn ghost" id="c">Cancel</button><button class="btn ${danger ? 'danger solid' : 'primary'}" id="o">${esc(okText)}</button></div>`);
      m.onclose = (v) => res(v === true);
      m.q('#c').onclick = () => m.close(false); m.q('#o').onclick = () => m.close(true);
    });
  }
  function textPrompt(title, body, { type = 'text', ph = '', ok = 'Continue', hint = '' } = {}) {
    return new Promise((res) => {
      const m = modal(`<form><h3>${esc(title)}</h3><p>${esc(body)}</p>
        <input class="in" id="v" type="${type}" placeholder="${esc(ph)}" autocomplete="off" required>${hint ? `<p class="hint" style="margin-top:8px">${esc(hint)}</p>` : ''}
        <div class="acts"><button type="button" class="btn ghost" id="c">Cancel</button><button class="btn primary">${esc(ok)}</button></div></form>`);
      m.onclose = (v) => res(typeof v === 'string' ? v : null);
      m.q('#c').onclick = () => m.close(null);
      m.q('form').onsubmit = (e) => { e.preventDefault(); m.close(m.q('#v').value); };
    });
  }
  function categoryPrompt(title, body, current) {
    return new Promise((res) => {
      const opts = categories().map(([c]) => `<option value="${esc(c)}"></option>`).join('');
      const m = modal(`<form><h3>${esc(title)}</h3><p>${esc(body)}</p>
        <label class="f"><span>Category</span><input class="in" id="v" list="cl" value="${esc(current)}" placeholder="Choose or type a new one" autocomplete="off" required></label>
        <datalist id="cl">${opts}</datalist>
        <div class="acts"><button type="button" class="btn ghost" id="c">Cancel</button><button class="btn primary">Save</button></div></form>`);
      m.onclose = (v) => res(typeof v === 'string' ? v : null);
      m.q('#c').onclick = () => m.close(null);
      m.q('form').onsubmit = (e) => { e.preventDefault(); const v = m.q('#v').value.trim(); if (v) m.close(v.slice(0, 40)); };
    });
  }
  function progressModal(title) {
    const m = modal(`<h3>${esc(title)}</h3><div class="prog"><i id="pb"></i></div><p id="pt" style="margin:6px 0 0">Starting…</p>`, { persistent: true });
    return { set: (pct, txt) => { m.q('#pb').style.width = clamp(pct, 0, 100) + '%'; if (txt) m.q('#pt').textContent = txt; }, close: () => m.close() };
  }

  /* --------------------------------------------------------------- upload --- */
  const IMG_RE = /\.(jpe?g|png|gif|webp|avif|heic|heif|bmp)$/i;
  async function makeThumb(file) {
    let src, w, h, url;
    try { src = await createImageBitmap(file); w = src.width; h = src.height; }
    catch {
      try {
        url = URL.createObjectURL(file);
        src = await new Promise((res, rej) => { const im = new Image(); im.onload = () => res(im); im.onerror = rej; im.src = url; });
        w = src.naturalWidth; h = src.naturalHeight;
      } catch { return null; } finally { url && URL.revokeObjectURL(url); }
    }
    const sc = Math.min(1, 480 / Math.max(w, h));
    const cv = document.createElement('canvas'); cv.width = Math.max(1, Math.round(w * sc)); cv.height = Math.max(1, Math.round(h * sc));
    const ctx = cv.getContext('2d'); ctx.fillStyle = '#0e1426'; ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.drawImage(src, 0, 0, cv.width, cv.height); src.close && src.close();
    const blob = await new Promise((r) => cv.toBlob(r, 'image/jpeg', 0.74));
    if (!blob) return null;
    return { bytes: new Uint8Array(await blob.arrayBuffer()), w, h };
  }

  async function putObject(path, bytes) {
    const { error } = await S.sb.storage.from(BUCKET).upload(path, new Blob([bytes], { type: 'application/octet-stream' }),
      { contentType: 'application/octet-stream', upsert: false, cacheControl: '3600' });
    if (error) throw error;
  }

  async function uploadOne(file, category, setState) {
    const id = crypto.randomUUID();
    setState('Encrypting…', 20);
    const buf = new Uint8Array(await file.arrayBuffer());
    const th = await makeThumb(file);
    const meta = { name: file.name || 'image', category, mime: file.type || 'application/octet-stream', size: file.size, w: th?.w, h: th?.h, added: Date.now() };
    const fileEnc = await C.enc(S.key, buf, `${id}|file`);
    const thumbEnc = th ? await C.enc(S.key, th.bytes, `${id}|thumb`) : null;
    const meta_enc = await encMeta(id, meta);
    const base = `${S.user.id}/${id}`;
    const fp = `${base}.bin`, tp = thumbEnc ? `${base}.t.bin` : null;
    setState('Uploading…', 55);
    try {
      await putObject(fp, fileEnc);
      if (tp) await putObject(tp, thumbEnc);
      const row = { id, owner: S.user.id, file_path: fp, thumb_path: tp, meta_enc, size_bytes: fileEnc.length + (thumbEnc?.length || 0) };
      const { data, error } = await S.sb.from('vault_items').insert(row).select().single();
      if (error) throw error;
      setState('Done', 100);
      return { ...data, meta, bad: false };
    } catch (e) {
      await S.sb.storage.from(BUCKET).remove([fp, tp].filter(Boolean)).catch(() => {});
      throw e;
    }
  }

  async function startUpload(files) {
    if (!S.key || !$('#gw')) return;
    const max = CFG.MAX_FILE_BYTES || 30 * 1024 * 1024;
    const ok = files.filter((f) => {
      if (!(f.type.startsWith('image/') || IMG_RE.test(f.name))) { toast(`${f.name || 'File'} isn’t an image.`, 'err'); return false; }
      if (f.size > max) { toast(`${f.name} is larger than ${fmtBytes(max)}.`, 'err'); return false; }
      return true;
    });
    if (!ok.length) return;
    const category = S.cat === 'All' ? 'Uncategorized' : S.cat;
    let q = $('#queue');
    if (!q) { q = document.createElement('div'); q.id = 'queue'; q.className = 'queue glass'; q.innerHTML = '<h4>Uploading</h4><div class="qlist"></div>'; root.appendChild(q); }
    const list = q.querySelector('.qlist');
    const jobs = ok.map((f) => {
      const row = document.createElement('div'); row.className = 'qi';
      row.innerHTML = `<span class="nm">${esc(f.name || 'image')}</span><span class="st">Waiting</span><div class="bar2"><i></i></div>`;
      list.appendChild(row);
      return { f, row, set: (t, p) => { row.querySelector('.st').textContent = t; row.querySelector('i').style.width = p + '%'; } };
    });
    let idx = 0, done = 0, failed = 0;
    const worker = async () => {
      while (idx < jobs.length) {
        const j = jobs[idx++];
        try { const it = await uploadOne(j.f, category, j.set); S.items.unshift(it); j.row.classList.add('done'); done++; if ($('#gw')) { renderCats(); renderGrid(); } }
        catch (e) { j.row.classList.add('fail'); j.set('Failed', 100); j.row.title = friendly(e); failed++; toast(`${j.f.name}: ${friendly(e)}`, 'err'); }
      }
    };
    await Promise.all([worker(), worker()]);
    if (done) toast(`${done} photo${done === 1 ? '' : 's'} encrypted and uploaded.`, 'ok');
    setTimeout(() => { if (q.isConnected && !q.querySelector('.qi:not(.done):not(.fail)')) q.remove(); }, failed ? 8000 : 2500);
  }

  /* ---------------------------------------------------- edit / move / delete -- */
  async function saveMeta(it, meta) {
    const meta_enc = await encMeta(it.id, meta);
    const { data, error } = await S.sb.from('vault_items').update({ meta_enc }).eq('id', it.id).select('id');
    if (error) throw error;
    if (!data?.length) throw new Error('Permission denied.');
    it.meta = meta; it.meta_enc = meta_enc;
  }
  async function moveItems(ids, cat) {
    const pool = limiter(4); let fail = 0;
    await Promise.all(ids.map((id) => pool(async () => { const it = byId(id); if (!it) return; try { await saveMeta(it, { ...it.meta, category: cat }); } catch { fail++; } })));
    renderAll(); fail ? toast(`${fail} couldn’t be moved.`, 'err') : toast('Moved.', 'ok');
  }
  async function deleteItems(ids) {
    try {
      const { data, error } = await S.sb.from('vault_items').delete().in('id', ids).select('id,file_path,thumb_path');
      if (error) throw error;
      const paths = (data || []).flatMap((r) => [r.file_path, r.thumb_path]).filter(Boolean);
      for (let i = 0; i < paths.length; i += 100) await S.sb.storage.from(BUCKET).remove(paths.slice(i, i + 100));
      const gone = new Set((data || []).map((r) => r.id));
      S.items = S.items.filter((i) => !gone.has(i.id));
      gone.forEach((id) => { const u = thumbCache.get(id); if (u) { URL.revokeObjectURL(u); thumbCache.delete(id); } const f = fullCache.get(id); if (f) { URL.revokeObjectURL(f); fullCache.delete(id); } });
      renderAll();
      const skipped = ids.length - gone.size;
      skipped ? toast(`${skipped} item${skipped === 1 ? '' : 's'} can only be deleted by who uploaded them or the admin.`, 'err') : toast('Deleted.', 'ok');
      return gone;
    } catch (e) { toast(friendly(e), 'err'); return new Set(); }
  }
  async function editItem(it) {
    return new Promise((res) => {
      const opts = categories().map(([c]) => `<option value="${esc(c)}"></option>`).join('');
      const m = modal(`<form><h3>Edit details</h3><p>Names and categories are encrypted too.</p>
        <label class="f"><span>Name</span><input class="in" id="n" value="${esc(it.meta.name)}" maxlength="120" required></label>
        <label class="f"><span>Category</span><input class="in" id="c" list="cl" value="${esc(it.meta.category)}" maxlength="40" required></label><datalist id="cl">${opts}</datalist>
        <div class="acts"><button type="button" class="btn ghost" id="x">Cancel</button><button class="btn primary">Save changes</button></div></form>`);
      m.onclose = (v) => res(v === true);
      m.q('#x').onclick = () => m.close(false);
      m.q('form').onsubmit = async (e) => {
        e.preventDefault(); const b = m.q('button.primary'); busy(b, true);
        try { await saveMeta(it, { ...it.meta, name: m.q('#n').value.trim() || it.meta.name, category: m.q('#c').value.trim() || 'Uncategorized' }); renderAll(); toast('Saved.', 'ok'); m.close(true); }
        catch (er) { busy(b, false); toast(friendly(er), 'err'); }
      };
    });
  }

  /* --------------------------------------------------------------- viewer --- */
  function openViewer(startId) {
    let list = filtered().map((i) => i.id), idx = list.indexOf(startId);
    if (idx < 0) return;
    const el = document.createElement('div'); el.className = 'viewer';
    el.innerHTML = `<div class="vbar">
        <div class="ttl"><b id="vT"></b><small id="vS"></small></div>
        <button class="icon-btn" id="vDl" title="Download decrypted copy" aria-label="Download decrypted copy">${I.download}</button>
        <button class="icon-btn" id="vEd" title="Edit details" aria-label="Edit details">${I.edit}</button>
        <button class="icon-btn" id="vDel" title="Delete" aria-label="Delete">${I.trash}</button>
        <button class="icon-btn" id="vX" title="Close" aria-label="Close">${I.close}</button>
      </div>
      <div class="stage" id="stage">
        <img id="vImg" alt="" draggable="false">
        <div class="noprev" id="vNo" hidden></div>
        <div class="loading" id="vLoad"><span class="spin"></span></div>
        <button class="icon-btn nav l" id="vP" aria-label="Previous">${I.left}</button>
        <button class="icon-btn nav r" id="vN" aria-label="Next">${I.right}</button>
      </div>
      <div class="vinfo" id="vI"></div>`;
    root.appendChild(el);
    const q = (s) => el.querySelector(s);
    const img = q('#vImg'), stage = q('#stage'), st = { s: 1, x: 0, y: 0 };
    let token = 0;
    const apply = () => { img.style.transform = `translate(${st.x}px,${st.y}px) scale(${st.s})`; stage.classList.toggle('zoomed', st.s > 1); };
    const reset = () => { st.s = 1; st.x = st.y = 0; apply(); };
    const zoom = (f) => { st.s = clamp(st.s * f, 1, 6); if (st.s === 1) { st.x = st.y = 0; } apply(); };

    async function show(i) {
      idx = i; reset(); const my = ++token; const it = byId(list[idx]); if (!it) return;
      q('#vT').textContent = it.meta.name;
      q('#vS').textContent = `${idx + 1} of ${list.length}`;
      const bits = [it.meta.category, fmtBytes(it.meta.size || it.size_bytes)];
      if (it.meta.w) bits.push(`${it.meta.w}×${it.meta.h}`);
      bits.push(`Added ${fmtDate(it.created_at)}`);
      q('#vI').textContent = bits.join('  ·  ');
      q('#vP').style.visibility = idx > 0 ? '' : 'hidden'; q('#vN').style.visibility = idx < list.length - 1 ? '' : 'hidden';
      q('#vNo').hidden = true; img.hidden = false; q('#vLoad').hidden = false;
      img.onerror = null;
      if (thumbCache.has(it.id)) { img.classList.add('soft'); img.src = thumbCache.get(it.id); } else { img.removeAttribute('src'); img.classList.remove('soft'); }
      try {
        const url = await getFullUrl(it); if (my !== token) return;
        img.onerror = () => { if (my !== token) return; img.hidden = true; q('#vLoad').hidden = true; const n = q('#vNo'); n.hidden = false; n.textContent = 'This browser can’t preview this format. Use Download to save the decrypted original.'; };
        img.onload = () => { if (my !== token) return; img.classList.remove('soft'); q('#vLoad').hidden = true; };
        img.src = url;
      } catch (e) {
        if (my !== token) return; img.hidden = true; q('#vLoad').hidden = true;
        const n = q('#vNo'); n.hidden = false; n.textContent = 'Couldn’t decrypt this photo. It may have been encrypted with a different passphrase.';
      }
    }
    const go = (d) => { const n = idx + d; if (n >= 0 && n < list.length) show(n); };
    const close = () => { el.remove(); S.viewer = null; };
    S.viewer = { close, go, zoom };

    q('#vX').onclick = close; q('#vP').onclick = () => go(-1); q('#vN').onclick = () => go(1);
    q('#vDl').onclick = async () => {
      const it = byId(list[idx]); try { const url = await getFullUrl(it); const a = document.createElement('a'); a.href = url; a.download = it.meta.name; document.body.appendChild(a); a.click(); a.remove(); }
      catch (e) { toast(friendly(e), 'err'); }
    };
    q('#vEd').onclick = async () => { const it = byId(list[idx]); if (await editItem(it)) show(idx); };
    q('#vDel').onclick = async () => {
      const it = byId(list[idx]);
      if (!(await confirmBox('Delete this photo?', 'The encrypted file is removed from the server for good. This can’t be undone.', 'Delete', true))) return;
      const gone = await deleteItems([it.id]);
      if (!gone.has(it.id)) return;
      list = list.filter((x) => x !== it.id);
      if (!list.length) close(); else show(Math.min(idx, list.length - 1));
    };

    // gestures: swipe, pinch, double-tap zoom, drag-pan, wheel
    const pts = new Map(); let d0 = 0, s0 = 1, sx = 0, sy = 0, ox = 0, oy = 0, moved = false, multi = false, t0 = 0, lastTap = 0;
    const dist = () => { const [a, b] = [...pts.values()]; return Math.hypot(a.x - b.x, a.y - b.y) || 1; };
    stage.addEventListener('pointerdown', (e) => {
      if (e.target.closest('.nav')) return;
      try { stage.setPointerCapture(e.pointerId); } catch {}
      pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size === 1) { sx = e.clientX; sy = e.clientY; ox = st.x; oy = st.y; moved = false; multi = false; t0 = Date.now(); }
      else if (pts.size === 2) { multi = true; d0 = dist(); s0 = st.s; }
    });
    stage.addEventListener('pointermove', (e) => {
      if (!pts.has(e.pointerId)) return; pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (pts.size === 2) { st.s = clamp(s0 * dist() / d0, 1, 6); if (st.s === 1) st.x = st.y = 0; moved = true; apply(); }
      else if (pts.size === 1) {
        const dx = e.clientX - sx, dy = e.clientY - sy; if (Math.hypot(dx, dy) > 8) moved = true;
        if (st.s > 1) { st.x = ox + dx; st.y = oy + dy; apply(); }
      }
    });
    const end = (e) => {
      if (!pts.has(e.pointerId)) return; pts.delete(e.pointerId);
      if (!pts.size && !multi) {
        const dx = e.clientX - sx, dy = e.clientY - sy, now = Date.now();
        if (!moved && now - t0 < 300) {
          if (now - lastTap < 320) {
            lastTap = 0;
            if (st.s > 1) reset();
            else { const r = stage.getBoundingClientRect(); st.s = 2.5; st.x = (e.clientX - (r.left + r.width / 2)) * (1 - 2.5); st.y = (e.clientY - (r.top + r.height / 2)) * (1 - 2.5); apply(); }
          } else lastTap = now;
        } else if (st.s === 1 && Math.abs(dx) > 60 && Math.abs(dy) < 80) go(dx < 0 ? 1 : -1);
        else if (st.s === 1 && dy > 110 && Math.abs(dx) < 80) close();
      }
      if (!pts.size) multi = false;
    };
    stage.addEventListener('pointerup', end); stage.addEventListener('pointercancel', end);
    stage.addEventListener('wheel', (e) => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.15 : 1 / 1.15); }, { passive: false });
    show(idx);
  }

  /* ------------------------------------------------------------- settings --- */
  function openSettings() {
    const admin = S.profile.role === 'admin';
    const al = (() => { try { return localStorage.getItem('pc.al') ?? '5'; } catch { return '5'; } })();
    const m = modal(`<h3>Settings</h3><p>${esc(S.user.email)} <span class="badge ${S.profile.role}">${S.profile.role}</span></p>
      <div class="sec"><h4>Auto-lock</h4>
        <select class="in" id="al"><option value="1">After 1 minute idle</option><option value="5">After 5 minutes idle</option><option value="15">After 15 minutes idle</option><option value="30">After 30 minutes idle</option><option value="0">Never (not recommended)</option></select>
        <p class="hint" style="margin-top:8px">The vault also locks 1 minute after you leave this tab. Press Esc twice to lock instantly.</p></div>
      <form class="sec" id="pf"><h4>Change account password</h4>
        <label class="f"><span>New password (10+ characters)</span><input class="in" type="password" id="np" autocomplete="new-password" minlength="10" required></label>
        <button class="btn sm">Update password</button></form>
      <div class="sec"><h4>Sessions</h4><div class="row wrap">
        <button class="btn sm" id="sRef">Refresh library</button>
        <button class="btn sm" id="sGlob">Sign out everywhere</button>
        <button class="btn sm danger" id="sOut">${I.logout} Sign out</button></div></div>
      <p class="hint">${admin ? 'You can’t reset another account’s password — remove and recreate it instead. ' : ''}Photos are encrypted with AES-256-GCM; the passphrase is never stored.</p>
      <div class="acts"><button class="btn primary" id="d">Done</button></div>`);
    m.q('#al').value = ['0', '1', '5', '15', '30'].includes(al) ? al : '5';
    m.q('#al').onchange = (e) => { try { localStorage.setItem('pc.al', e.target.value); } catch {} bump(); toast('Auto-lock updated.', 'ok'); };
    m.q('#d').onclick = () => m.close();
    m.q('#sOut').onclick = () => { m.close(); logout(); };
    m.q('#sGlob').onclick = async () => { try { await S.sb.auth.signOut({ scope: 'global' }); } catch {} m.close(); S.user = null; lock(); };
    m.q('#sRef').onclick = async () => { try { await refreshItems(); renderAll(); toast('Library refreshed.', 'ok'); } catch (e) { toast(friendly(e), 'err'); } };
    m.q('#pf').onsubmit = async (e) => {
      e.preventDefault(); const b = m.q('#pf button'); busy(b, true);
      try { const { error } = await S.sb.auth.updateUser({ password: m.q('#np').value }); if (error) throw error; toast('Password updated.', 'ok'); m.q('#np').value = ''; }
      catch (er) { toast(friendly(er), 'err'); } busy(b, false);
    };
  }

  /* ---------------------------------------------------------------- admin --- */
  function openAdmin() {
    const m = modal(`<div class="row sp"><h3>Admin</h3><button class="icon-btn" id="x" aria-label="Close">${I.close}</button></div>
      <div class="tabs"><button class="tab on" data-t="users">Users</button><button class="tab" data-t="vault">Vault</button></div><div id="pane"></div>`, { wide: true });
    m.q('#x').onclick = () => m.close();
    const tabs = m.el.querySelectorAll('.tab');
    const go = (t) => { tabs.forEach((b) => b.classList.toggle('on', b.dataset.t === t)); t === 'users' ? adminUsers(m.q('#pane')) : adminVault(m.q('#pane'), m); };
    tabs.forEach((b) => (b.onclick = () => go(b.dataset.t)));
    go('users');
  }

  async function adminUsers(pane) {
    pane.innerHTML = `<div class="loading" style="padding:30px"><span class="spin"></span></div>`;
    const { data, error } = await S.sb.from('profiles').select('*').order('created_at');
    if (error) { pane.innerHTML = `<p class="err">${esc(friendly(error))}</p>`; return; }
    const users = data.filter((u) => u.role === 'user').length;
    const max = CFG.MAX_USERS ?? 1, canAdd = users < max;
    pane.innerHTML = `<div class="sec"><table class="tbl"><thead><tr><th>Account</th><th>Role</th><th class="hide-xs">Created</th><th></th></tr></thead><tbody>
      ${data.map((u) => {
        const me = u.id === S.user.id;
        const acts = me ? '<span class="hint" style="margin:0">You</span>' : [
          u.role === 'pending' ? `<button class="btn sm" data-a="approve" data-id="${u.id}">Approve</button>` : '',
          u.role === 'user' ? `<button class="btn sm" data-a="disable" data-id="${u.id}">Disable</button>` : '',
          u.role === 'disabled' ? `<button class="btn sm" data-a="enable" data-id="${u.id}">Enable</button>` : '',
          `<button class="btn sm danger" data-a="delete" data-id="${u.id}" data-em="${esc(u.email)}">Delete</button>`].join(' ');
        return `<tr><td class="em">${esc(u.email)}</td><td><span class="badge ${u.role}">${u.role}</span></td><td class="hide-xs">${fmtDate(u.created_at)}</td><td><div class="row wrap" style="justify-content:flex-end">${acts}</div></td></tr>`;
      }).join('')}</tbody></table></div>
      <div class="sec"><h4>Add a User</h4>
        ${canAdd ? `<form id="au"><div class="row wrap" style="align-items:flex-end">
          <label class="f" style="flex:1;min-width:190px;margin:0"><span>Email</span><input class="in" type="email" id="ue" required autocomplete="off"></label>
          <label class="f" style="flex:1;min-width:190px;margin:0"><span>Temporary password (10+)</span><input class="in" type="password" id="up" minlength="10" required autocomplete="new-password"></label>
          <button class="btn primary">${I.plus} Create User</button></div>
          <p class="hint" style="margin-top:10px">Give them the vault passphrase through a separate, private channel — the server doesn’t have it. They can change their account password in Settings.</p></form>`
          : `<p class="hint" style="margin:0">User limit reached (${max}). Delete the existing User to add another, or raise MAX_USERS in config.js.</p>`}</div>`;

    pane.querySelectorAll('[data-a]').forEach((b) => (b.onclick = async () => {
      const id = b.dataset.id, a = b.dataset.a;
      try {
        if (a === 'delete') {
          if (!(await confirmBox('Delete account?', `${b.dataset.em} will be removed permanently. Photos they uploaded stay in the vault.`, 'Delete account', true))) return;
          const { error: e } = await S.sb.rpc('admin_delete_user', { target: id }); if (e) throw e;
        } else {
          const role = a === 'disable' ? 'disabled' : 'user';
          const { data: d, error: e } = await S.sb.from('profiles').update({ role }).eq('id', id).select('id'); if (e) throw e;
          if (!d?.length) throw new Error('Update was blocked.');
        }
        toast('Done.', 'ok'); adminUsers(pane);
      } catch (e) { toast(friendly(e), 'err'); }
    }));

    const f = pane.querySelector('#au');
    if (f) f.onsubmit = async (e) => {
      e.preventDefault(); const btn = f.querySelector('button'); busy(btn, true, 'Creating');
      try {
        const email = f.querySelector('#ue').value.trim(), password = f.querySelector('#up').value;
        // A throwaway client so the Admin's own session is untouched.
        const mem = {}; const tmp = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false, storageKey: 'pc.tmp',
            storage: { getItem: (k) => mem[k] ?? null, setItem: (k, v) => { mem[k] = v; }, removeItem: (k) => { delete mem[k]; } } } });
        const { data: sd, error: se } = await tmp.auth.signUp({ email, password });
        if (se) throw se;
        if (!sd.user || (sd.user.identities && sd.user.identities.length === 0)) throw new Error('That email is already registered.');
        const { data: ud, error: ue } = await S.sb.from('profiles').update({ role: 'user' }).eq('id', sd.user.id).select('id');
        if (ue) throw ue; if (!ud?.length) throw new Error('Account created but couldn’t be activated. Approve it from the list.');
        toast(sd.session ? 'User created.' : 'User created — they must confirm their email first (or turn off “Confirm email” in Supabase).', 'ok');
        adminUsers(pane);
      } catch (er) { toast(friendly(er), 'err'); busy(btn, false); }
    };
  }

  async function adminVault(pane, parentModal) {
    let rows = [];
    try { rows = await fetchRows('id,size_bytes,created_at'); } catch (e) { pane.innerHTML = `<p class="err">${esc(friendly(e))}</p>`; return; }
    const total = rows.reduce((a, r) => a + Number(r.size_bytes || 0), 0);
    pane.innerHTML = `<div class="sec"><div class="stats">
        <div class="stat"><b>${rows.length}</b><span>Encrypted photos</span></div>
        <div class="stat"><b>${fmtBytes(total)}</b><span>Ciphertext stored</span></div>
        <div class="stat"><b>${categories().length}</b><span>Categories</span></div></div></div>
      <div class="sec"><h4>Encrypted backup</h4>
        <p class="hint" style="margin:0 0 10px">One file with every photo, still encrypted with the vault passphrase. Restoring into a different vault asks for the old passphrase and re-encrypts.</p>
        <div class="row wrap"><button class="btn" id="bk">${I.download} Download backup</button><button class="btn" id="rs">${I.upload} Restore from backup</button></div></div>
      <div class="sec"><h4>Danger zone</h4>
        <p class="hint" style="margin:0 0 10px">Reset deletes every photo and the passphrase check, then lets you choose a new passphrase. To rotate the passphrase: download a backup, reset, create the new passphrase, restore.</p>
        <button class="btn danger" id="rst">Reset vault</button></div>`;
    pane.querySelector('#bk').onclick = () => makeBackup();
    pane.querySelector('#rs').onclick = () => { parentModal.close(); pickBackup(); };
    pane.querySelector('#rst').onclick = async () => {
      const t = await textPrompt('Reset the vault?', 'This permanently deletes all photos for everyone. Type RESET to confirm.', { ph: 'RESET', ok: 'Delete everything' });
      if (t !== 'RESET') { if (t != null) toast('Reset cancelled — you must type RESET.'); return; }
      parentModal.close(); await resetVault();
    };
  }

  async function resetVault() {
    const p = progressModal('Resetting vault');
    try {
      const rows = await fetchRows('id,file_path,thumb_path');
      p.set(10, 'Deleting photos…');
      const paths = rows.flatMap((r) => [r.file_path, r.thumb_path]).filter(Boolean);
      for (let i = 0; i < paths.length; i += 100) { await S.sb.storage.from(BUCKET).remove(paths.slice(i, i + 100)); p.set(10 + 70 * (i / Math.max(1, paths.length)), 'Deleting files…'); }
      const { error: e1 } = await S.sb.from('vault_items').delete().neq('id', '00000000-0000-0000-0000-000000000000'); if (e1) throw e1;
      const { error: e2 } = await S.sb.from('vault_meta').delete().eq('id', 1); if (e2) throw e2;
      p.close();
      S.key = null; S.meta = null; S.items = [];
      thumbCache.forEach((u) => URL.revokeObjectURL(u)); thumbCache.clear(); fullCache.forEach((u) => URL.revokeObjectURL(u)); fullCache.clear();
      await afterAuth();
    } catch (e) { p.close(); toast(friendly(e), 'err'); }
  }

  /* ------------------------------------------------------ backup / restore -- */
  const MAGIC = enc.encode('PCVAULT1');
  async function makeBackup() {
    const p = progressModal('Building encrypted backup');
    try {
      const rows = await fetchRows();
      const parts = [], items = [];
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i]; p.set((i / Math.max(1, rows.length)) * 95, `Downloading ${i + 1} of ${rows.length}…`);
        const f = await S.sb.storage.from(BUCKET).download(r.file_path); if (f.error) throw f.error;
        const fb = new Uint8Array(await f.data.arrayBuffer()); let tb = new Uint8Array(0);
        if (r.thumb_path) { const t = await S.sb.storage.from(BUCKET).download(r.thumb_path); if (t.error) throw t.error; tb = new Uint8Array(await t.data.arrayBuffer()); }
        items.push({ id: r.id, created_at: r.created_at, meta_enc: r.meta_enc, size_bytes: r.size_bytes, fileLen: fb.length, thumbLen: tb.length });
        parts.push(fb, tb);
      }
      p.set(97, 'Sealing manifest…');
      const clear = enc.encode(JSON.stringify({ v: 1, app: 'pocket-vault', created: new Date().toISOString(), kdf: { iterations: S.meta.iterations, salt: S.meta.salt }, verifier: S.meta.verifier }));
      const manifest = await C.enc(S.key, enc.encode(JSON.stringify({ items })), 'backup-manifest');
      const blob = new Blob([MAGIC, putU32(clear.length), clear, putU32(manifest.length), manifest, ...parts], { type: 'application/octet-stream' });
      const d = new Date(), z = (n) => String(n).padStart(2, '0');
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
      a.download = `vault-backup-${d.getFullYear()}${z(d.getMonth() + 1)}${z(d.getDate())}-${z(d.getHours())}${z(d.getMinutes())}.pcvault`;
      document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 60000);
      p.close(); toast(`Backup saved (${rows.length} photos).`, 'ok');
    } catch (e) { p.close(); toast('Backup failed: ' + friendly(e), 'err'); }
  }

  function pickBackup() {
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = '.pcvault,application/octet-stream';
    inp.onchange = () => { if (inp.files[0]) restoreBackup(inp.files[0]); };
    inp.click();
  }

  async function restoreBackup(file) {
    const slice = async (a, b) => new Uint8Array(await file.slice(a, b).arrayBuffer());
    let p;
    try {
      let off = 0;
      const magic = await slice(0, 8); off = 8;
      if (dec.decode(magic) !== 'PCVAULT1') throw new Error('That isn’t a vault backup file.');
      const cl = u32(await slice(off, off + 4)); off += 4; if (cl > 1e6) throw new Error('Backup header is corrupt.');
      const clear = JSON.parse(dec.decode(await slice(off, off + cl))); off += cl;
      const ml = u32(await slice(off, off + 4)); off += 4; if (ml > 5e8) throw new Error('Backup manifest is corrupt.');
      const encManifest = await slice(off, off + ml); off += ml;

      let bkey = S.key, same = clear.kdf.salt === S.meta.salt && clear.kdf.iterations === S.meta.iterations;
      if (!same) {
        const pass = await textPrompt('Passphrase for this backup', 'This backup was made with a different vault passphrase. Enter it and the photos will be re-encrypted with your current one.', { type: 'password', ok: 'Restore' });
        if (pass == null) return;
        const tp = progressModal('Checking passphrase'); await tick();
        try { bkey = await unlockWith(pass, { salt: clear.kdf.salt, iterations: clear.kdf.iterations, verifier: clear.verifier }); } finally { tp.close(); }
      }
      const manifest = JSON.parse(dec.decode(await C.dec(bkey, encManifest, 'backup-manifest')));
      p = progressModal('Restoring photos');
      const have = new Set((await fetchRows('id')).map((r) => r.id));
      let ok = 0, skipped = 0, failed = 0; const n = manifest.items.length;
      for (let i = 0; i < n; i++) {
        const it = manifest.items[i];
        const fOff = off; off += it.fileLen; const tOff = off; off += it.thumbLen;
        p.set((i / Math.max(1, n)) * 100, `Restoring ${i + 1} of ${n}…`);
        if (!UUID_RE.test(it.id) || have.has(it.id)) { skipped++; continue; }
        try {
          let fb = await slice(fOff, fOff + it.fileLen), tb = it.thumbLen ? await slice(tOff, tOff + it.thumbLen) : null, meta_enc = it.meta_enc;
          if (!same) {
            const meta = await decMeta(it.id, it.meta_enc, bkey);
            fb = await C.enc(S.key, await C.dec(bkey, fb, `${it.id}|file`), `${it.id}|file`);
            if (tb) tb = await C.enc(S.key, await C.dec(bkey, tb, `${it.id}|thumb`), `${it.id}|thumb`);
            meta_enc = await encMeta(it.id, meta);
          }
          const base = `${S.user.id}/${it.id}`, fp = `${base}.bin`, tp = tb ? `${base}.t.bin` : null;
          try {
            await putObject(fp, fb); if (tp) await putObject(tp, tb);
            const { error } = await S.sb.from('vault_items').insert({ id: it.id, owner: S.user.id, file_path: fp, thumb_path: tp, meta_enc, size_bytes: fb.length + (tb?.length || 0), created_at: it.created_at });
            if (error) throw error;
          } catch (e) { await S.sb.storage.from(BUCKET).remove([fp, tp].filter(Boolean)).catch(() => {}); throw e; }
          ok++;
        } catch { failed++; }
      }
      p.close(); p = null;
      await refreshItems(); renderAll();
      toast(`Restored ${ok}${skipped ? `, skipped ${skipped} already present` : ''}${failed ? `, ${failed} failed` : ''}.`, failed ? 'err' : 'ok');
    } catch (e) { p && p.close(); toast('Restore failed: ' + (/operation|decrypt/i.test(e?.message) ? 'wrong passphrase or damaged file.' : friendly(e)), 'err'); }
  }

  /* ------------------------------------------------------------------ API --- */
  window.PCVault = { open, lock, isOpen };
})();
