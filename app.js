/* osintnow. - application logic
   Everything runs client-side. Third-party data is only ever inserted with
   textContent / DOM nodes (never innerHTML), so API responses cannot inject markup. */
(() => {
  'use strict';

  /* =====================================================================
     Small utilities
     ===================================================================== */
  const $ = (sel, root = document) => root.querySelector(sel);
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function safeUrl(url) {
    try {
      const u = new URL(url);
      return /^https?:$/.test(u.protocol) ? u.href : null;
    } catch { return null; }
  }

  function append(el, kids) {
    for (const k of kids) {
      if (k == null || k === false) continue;
      if (Array.isArray(k)) append(el, k);
      else el.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
  }

  /** Tiny hyperscript helper. */
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
        else if (k === 'href') { const u = safeUrl(v); if (u) el.setAttribute('href', u); }
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    append(el, kids);
    return el;
  }

  const p = (...kids) => h('p', null, ...kids);
  const sleep = (ms, signal) => new Promise((resolve, reject) => {
    if (signal && signal.aborted) return reject(new DOMException('Aborted', 'AbortError'));
    const t = setTimeout(resolve, ms);
    if (signal) signal.addEventListener('abort', () => { clearTimeout(t); reject(new DOMException('Aborted', 'AbortError')); }, { once: true });
  });

  function svg(inner, size = 22) {
    const t = document.createElement('template');
    t.innerHTML = `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;
    return t.content.firstElementChild;
  }

  const dateFmt = new Intl.DateTimeFormat('en-US', { dateStyle: 'medium' });
  function fmtDate(value) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : dateFmt.format(d);
  }
  const num = (n) => (typeof n === 'number' ? n.toLocaleString('en-US') : String(n));

  let regionNames = null;
  try { regionNames = new Intl.DisplayNames(['en-US'], { type: 'region' }); } catch { /* unsupported */ }
  function countryName(code) {
    if (!code) return '';
    try { return (regionNames && regionNames.of(code.toUpperCase())) || code; } catch { return code; }
  }
  function flagEmoji(code) {
    if (!/^[A-Za-z]{2}$/.test(code || '')) return '';
    return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const ta = h('textarea', { 'aria-hidden': 'true', style: 'position:fixed;opacity:0;top:0;left:0' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch { ok = false; }
      ta.remove();
      return ok;
    }
  }

  /* =====================================================================
     Settings (optional API keys, kept in localStorage only)
     ===================================================================== */
  const Settings = {
    keys: { intelx: 'osintnow.intelx', intelxHost: 'osintnow.intelxHost', ipinfo: 'osintnow.ipinfo' },
    read(k) { try { return localStorage.getItem(k) || ''; } catch { return ''; } },
    write(k, v) { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k); } catch { /* storage blocked */ } },
    get() {
      return {
        intelx: this.read(this.keys.intelx).trim(),
        intelxHost: this.read(this.keys.intelxHost) || 'free.intelx.io',
        ipinfo: this.read(this.keys.ipinfo).trim(),
      };
    },
  };

  /* =====================================================================
     Networking
     ===================================================================== */
  async function fetchJSON(url, opts = {}) {
    const { timeout = 12000, signal, ...init } = opts;
    const ctrl = new AbortController();
    let timedOut = false;
    const onAbort = () => ctrl.abort();
    if (signal) {
      if (signal.aborted) ctrl.abort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    const timer = setTimeout(() => { timedOut = true; ctrl.abort(); }, timeout);
    try {
      const res = await fetch(url, { ...init, signal: ctrl.signal, credentials: 'omit', referrerPolicy: 'no-referrer' });
      const text = await res.text();
      let data = null;
      let parsed = false;
      try { data = text ? JSON.parse(text) : null; parsed = true; } catch { /* not JSON */ }
      if (!res.ok) {
        const err = new Error(`HTTP ${res.status}`);
        err.status = res.status;
        err.data = data;
        throw err;
      }
      if (!parsed) throw new Error('The service returned an unreadable response.');
      return data;
    } catch (err) {
      if (err.status) throw err;
      if (timedOut) { const e = new Error('timeout'); e.timeout = true; throw e; }
      if (signal && signal.aborted) throw err;
      if (err instanceof TypeError) { const e = new Error('network'); e.network = true; throw e; }
      throw err;
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
    }
  }

  function explain(err) {
    if (!err) return 'Unknown error.';
    if (err.timeout) return 'The service took too long to respond.';
    if (err.status === 429) return 'Rate limit reached. Wait a minute and try again.';
    if (err.status === 401 || err.status === 402) return 'The service rejected the request (invalid key or quota used up).';
    if (err.status === 403) return 'The service refused the request (access blocked or a key is required).';
    if (err.status === 404) return 'Nothing found.';
    if (err.status) return `The service answered with an error (HTTP ${err.status}).`;
    if (err.network) return 'The request was blocked: you may be offline, using a blocker, or the service does not allow browser access.';
    return err.message || 'Unknown error.';
  }

  /* DNS over HTTPS (Google first, Cloudflare as fallback) */
  const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
  async function doh(name, type, signal) {
    const code = DNS_TYPES[type];
    let data;
    try {
      data = await fetchJSON(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, { signal, timeout: 9000 });
    } catch (e) {
      if (signal && signal.aborted) throw e;
      data = await fetchJSON(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
        signal, timeout: 9000, headers: { accept: 'application/dns-json' },
      });
    }
    const answers = (data.Answer || []).filter((a) => a.type === code).map((a) => ({ ttl: a.TTL, data: cleanDns(type, a.data) }));
    return { status: data.Status, answers };
  }
  function cleanDns(type, value) {
    let v = String(value);
    if (type === 'TXT') return v.replace(/^"|"$/g, '').replace(/"\s+"/g, '');
    if (['NS', 'CNAME', 'PTR', 'MX'].includes(type)) v = v.replace(/\.$/, '');
    if (type === 'SOA') v = v.replace(/\.(?=\s)/g, '');
    return v;
  }

  /* =====================================================================
     IP helpers
     ===================================================================== */
  const isIPv4 = (s) => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(s);
  function isIPv6(s) {
    if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
    try { new URL(`http://[${s}]/`); return true; } catch { return false; }
  }
  function expandIPv6(ip) {
    let s = ip.toLowerCase();
    if (s.includes('.')) {
      const i = s.lastIndexOf(':');
      const v = s.slice(i + 1).split('.').map(Number);
      s = `${s.slice(0, i + 1)}${((v[0] << 8) | v[1]).toString(16)}:${((v[2] << 8) | v[3]).toString(16)}`;
    }
    const [head, tail] = s.split('::');
    const a = head ? head.split(':') : [];
    const b = tail ? tail.split(':') : [];
    const fill = s.includes('::') ? 8 - a.length - b.length : 0;
    return [...a, ...Array(Math.max(fill, 0)).fill('0'), ...b].map((x) => x.padStart(4, '0')).join('');
  }
  function reverseName(ip) {
    if (isIPv4(ip)) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
    return `${expandIPv6(ip).split('').reverse().join('.')}.ip6.arpa`;
  }
  function isPrivateIp(ip) {
    if (isIPv4(ip)) {
      const [a, b] = ip.split('.').map(Number);
      return a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
        (a === 192 && b === 0) || (a === 198 && (b === 18 || b === 19));
    }
    const x = expandIPv6(ip);
    return /^0{31}[01]$/.test(x) || /^f[cd]/.test(x) || /^fe[89ab]/.test(x) || x.startsWith('ff');
  }

  function normalizeDomain(raw) {
    let v = raw.trim().toLowerCase();
    if (!v) throw new Error('Enter a domain name, for example example.com.');
    if (!/^[a-z][a-z0-9+.-]*:\/\//.test(v)) v = `http://${v}`;
    let host;
    try { host = new URL(v).hostname.replace(/\.$/, ''); } catch { throw new Error('That does not look like a valid domain name.'); }
    if (isIPv4(host)) throw new Error('That is an IP address. Use the IP/DNS Analysis module instead.');
    if (!/^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(host)) {
      throw new Error('That does not look like a valid domain name.');
    }
    return host;
  }

  /* =====================================================================
     UI building blocks
     ===================================================================== */
  function kv(rows) {
    const items = rows.filter(([, v]) => v !== undefined && v !== null && v !== '' && v !== false);
    if (!items.length) return p(h('span', { class: 'muted' }, 'No details available.'));
    return h('dl', { class: 'kv' }, items.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
  }
  const chips = (list, mono = false) =>
    h('div', { class: 'chips' }, list.map((t) => h('span', { class: `chip${mono ? ' mono' : ''}` }, t)));
  const linkChips = (list) =>
    h('div', { class: 'chips' }, list.map(([label, url]) =>
      h('a', { class: 'link', href: url, target: '_blank', rel: 'noopener noreferrer' }, label)));
  const mutedP = (t) => h('p', { class: 'muted small' }, t);
  const extLink = (label, url) => h('a', { class: 'link', href: url, target: '_blank', rel: 'noopener noreferrer' }, label);

  function googleUrl(q) { return `https://www.google.com/search?q=${encodeURIComponent(q)}`; }

  function dorksList(queries) {
    return h('ul', { class: 'dorks' }, queries.map((q) => {
      const copy = h('button', { class: 'link', type: 'button' }, 'Copy');
      copy.addEventListener('click', async () => {
        const ok = await copyText(q);
        copy.textContent = ok ? 'Copied' : 'Copy failed';
        setTimeout(() => { copy.textContent = 'Copy'; }, 1500);
      });
      return h('li', null,
        h('code', null, q),
        h('div', { class: 'actions' }, extLink('Search', googleUrl(q)), copy));
    }));
  }

  function recordsView(map) {
    const rows = Object.entries(map).filter(([, list]) => list.length);
    if (!rows.length) return mutedP('No records found.');
    return h('div', { class: 'records' }, rows.map(([type, list]) =>
      h('div', { class: 'rec' },
        h('span', { class: 'tag' }, type),
        h('ul', null, list.map((r) => h('li', null, r.data, h('small', null, `TTL ${r.ttl}s`)))))));
  }

  /* =====================================================================
     Run context: cards, abort handling, memoised DNS
     ===================================================================== */
  let runSeq = 0;
  let currentRun = null;

  function makeCtx(run, host) {
    const keys = Settings.get();
    const dnsCache = new Map();
    let n = 0;
    const alive = () => currentRun === run && !run.ctrl.signal.aborted;
    const json = (url, opts = {}) => fetchJSON(url, { signal: run.ctrl.signal, ...opts });

    function makeCard(title) {
      const status = h('span', { class: 'status' }, 'Loading');
      let body = h('div', { class: 'card-body' }, h('div', { class: 'skeleton' }), h('div', { class: 'skeleton short' }));
      const el = h('article', { class: 'card is-loading', style: `--i:${n++}`, 'data-state': 'loading' },
        h('header', { class: 'card-head' }, h('h3', null, title), status), body);
      host.append(el);
      let settled = false;
      const done = (state, label, nodes) => {
        if (!alive()) return;
        settled = true;
        el.dataset.state = state;
        el.classList.remove('is-loading');
        status.textContent = label;
        const next = h('div', { class: 'card-body' }, nodes);
        body.replaceWith(next);
        body = next;
      };
      return {
        get settled() { return settled; },
        ok: (nodes, label = 'Found') => done('ok', label, nodes),
        note: (nodes, label = 'Info') => done('note', label, nodes),
        empty: (msg, label = 'No data') => done('empty', label, [mutedP(msg)]),
        fail: (err, label = 'Unavailable') => done('error', label, [
          p(explain(err)),
          err && (err.network || err.timeout) ? mutedP('Some free services limit browser access or rate-limit anonymous users. The result may work on a retry.') : null,
        ]),
      };
    }

    function task(title, fn) {
      const card = makeCard(title);
      return (async () => {
        try {
          await fn(card);
          if (!card.settled) card.empty('No data returned.');
        } catch (err) {
          if (alive()) card.fail(err);
        }
      })();
    }

    function dns(name, type) {
      const key = `${type}:${name}`;
      if (!dnsCache.has(key)) dnsCache.set(key, doh(name, type, run.ctrl.signal));
      return dnsCache.get(key);
    }

    return { keys, signal: run.ctrl.signal, alive, json, task, dns };
  }

  /* =====================================================================
     Shared module pieces
     ===================================================================== */
  function intelxTask(ctx, term) {
    const searchUrl = `https://intelx.io/?s=${encodeURIComponent(term)}`;
    return ctx.task('IntelX (leaks, pastes, darknet)', async (card) => {
      const { intelx, intelxHost } = ctx.keys;
      if (!intelx) {
        card.note([
          p('Add your free IntelX API key in Settings to search leaks, pastes and darknet records from here.'),
          h('div', { class: 'chips' },
            h('button', { class: 'link', type: 'button', onclick: () => openSettings() }, 'Open settings'),
            extLink('Search on intelx.io', searchUrl),
            extLink('Get a free key', 'https://intelx.io/signup')),
        ], 'Key needed');
        return;
      }
      const base = `https://${intelxHost}/`;
      const headers = { 'x-key': intelx, 'content-type': 'application/json' };
      try {
        const start = await ctx.json(`${base}intelligent/search`, {
          method: 'POST', headers, timeout: 15000,
          body: JSON.stringify({ term, buckets: [], lookuplevel: 0, maxresults: 50, timeout: 0, datefrom: '', dateto: '', sort: 4, media: 0, terminate: [] }),
        });
        if (!start || start.status !== 0 || !start.id) throw new Error('IntelX rejected this search term.');
        const records = new Map();
        for (let i = 0; i < 8; i++) {
          await sleep(i === 0 ? 700 : 1100, ctx.signal);
          const r = await ctx.json(`${base}intelligent/search/result?id=${encodeURIComponent(start.id)}&limit=50&statistics=0&previewlines=0`, { headers: { 'x-key': intelx }, timeout: 15000 });
          for (const rec of (r && r.records) || []) records.set(rec.systemid, rec);
          if (!r || r.status === 1 || r.status === 2 || records.size >= 50) break;
        }
        ctx.json(`${base}intelligent/search/terminate?id=${encodeURIComponent(start.id)}`, { headers: { 'x-key': intelx }, timeout: 5000 }).catch(() => {});
        if (!records.size) { card.empty('IntelX has no records for this term.', 'No results'); return; }
        const list = [...records.values()];
        card.ok([
          p(`${list.length}${list.length >= 50 ? '+' : ''} records found.`),
          h('ul', { class: 'dorks scroll-list' }, list.map((r) => h('li', null,
            h('div', null,
              h('code', null, r.name || `Record ${String(r.systemid).slice(0, 8)}`),
              h('small', { class: 'muted' }, ` ${[r.bucket, r.date && fmtDate(r.date)].filter(Boolean).join(' · ')}`)),
            extLink('Open', `https://intelx.io/?did=${encodeURIComponent(r.systemid)}`)))),
          h('div', { class: 'chips' }, extLink('All results on intelx.io', searchUrl)),
        ], `${list.length} records`);
      } catch (err) {
        if (ctx.signal.aborted) throw err;
        card.note([
          p(explain(err)),
          mutedP('IntelX may block direct browser requests (CORS) depending on your plan. The full search is one click away.'),
          h('div', { class: 'chips' }, extLink('Search on intelx.io', searchUrl)),
        ], 'Blocked');
      }
    });
  }

  /* =====================================================================
     MODULE: Username
     ===================================================================== */
  const enc = encodeURIComponent;

  const USER_API_CHECKS = [
    { name: 'GitHub', url: (u) => `https://github.com/${enc(u)}`, api: (u) => `https://api.github.com/users/${enc(u)}`,
      detail: (d) => d.login && [d.name, `${num(d.public_repos)} repos`, `${num(d.followers)} followers`, d.location].filter(Boolean).join(' · ') },
    { name: 'GitLab', url: (u) => `https://gitlab.com/${enc(u)}`, api: (u) => `https://gitlab.com/api/v4/users?username=${enc(u)}`,
      detail: (d) => Array.isArray(d) && d[0] && (d[0].name || d[0].username) },
    { name: 'Codeberg', url: (u) => `https://codeberg.org/${enc(u)}`, api: (u) => `https://codeberg.org/api/v1/users/${enc(u)}`,
      detail: (d) => d && d.login && [d.full_name, d.location].filter(Boolean).join(' · ') || d.login },
    { name: 'Reddit', url: (u) => `https://www.reddit.com/user/${enc(u)}`, api: (u) => `https://www.reddit.com/user/${enc(u)}/about.json`,
      detail: (d) => d && d.data && d.data.name && `${num(d.data.total_karma || 0)} karma` },
    { name: 'Hacker News', url: (u) => `https://news.ycombinator.com/user?id=${enc(u)}`, api: (u) => `https://hacker-news.firebaseio.com/v0/user/${enc(u)}.json`,
      detail: (d) => d && d.id && `${num(d.karma || 0)} karma` },
    { name: 'Keybase', url: (u) => `https://keybase.io/${enc(u)}`, api: (u) => `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${enc(u)}`,
      detail: (d) => d && d.them && d.them[0] && ((d.them[0].profile && d.them[0].profile.full_name) || 'Account exists') },
    { name: 'DEV Community', url: (u) => `https://dev.to/${enc(u)}`, api: (u) => `https://dev.to/api/users/by_username?url=${enc(u)}`,
      detail: (d) => d && d.username && [d.name, d.location].filter(Boolean).join(' · ') },
    { name: 'Lichess', url: (u) => `https://lichess.org/@/${enc(u)}`, api: (u) => `https://lichess.org/api/user/${enc(u)}`,
      detail: (d) => d && d.id && (d.count ? `${num(d.count.all)} games` : 'Account exists') },
    { name: 'Chess.com', url: (u) => `https://www.chess.com/member/${enc(u)}`, api: (u) => `https://api.chess.com/pub/player/${enc(u.toLowerCase())}`,
      detail: (d) => d && d.username && (d.name || 'Account exists') },
    { name: 'Mastodon (mastodon.social)', url: (u) => `https://mastodon.social/@${enc(u)}`, api: (u) => `https://mastodon.social/api/v1/accounts/lookup?acct=${enc(u)}`,
      detail: (d) => d && d.acct && `${num(d.followers_count || 0)} followers`, valid: (u) => /^\w+$/.test(u) },
    { name: 'Bluesky', url: (u) => `https://bsky.app/profile/${enc(u)}.bsky.social`, api: (u) => `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${enc(u)}.bsky.social`,
      detail: (d) => d && d.handle && `${num(d.followersCount || 0)} followers`, valid: (u) => /^[a-z0-9-]+$/i.test(u), missing: [400, 404] },
  ];

  const USER_LINK_ONLY = [
    ['Instagram', (u) => `https://www.instagram.com/${enc(u)}/`], ['X (Twitter)', (u) => `https://x.com/${enc(u)}`],
    ['TikTok', (u) => `https://www.tiktok.com/@${enc(u)}`], ['YouTube', (u) => `https://www.youtube.com/@${enc(u)}`],
    ['Twitch', (u) => `https://www.twitch.tv/${enc(u)}`], ['Telegram', (u) => `https://t.me/${enc(u)}`],
    ['Steam', (u) => `https://steamcommunity.com/id/${enc(u)}`], ['Pinterest', (u) => `https://www.pinterest.com/${enc(u)}/`],
    ['SoundCloud', (u) => `https://soundcloud.com/${enc(u)}`], ['Medium', (u) => `https://medium.com/@${enc(u)}`],
    ['Snapchat', (u) => `https://www.snapchat.com/add/${enc(u)}`], ['Facebook', (u) => `https://www.facebook.com/${enc(u)}`],
    ['Behance', (u) => `https://www.behance.net/${enc(u)}`], ['Dribbble', (u) => `https://dribbble.com/${enc(u)}`],
    ['Patreon', (u) => `https://www.patreon.com/${enc(u)}`], ['Linktree', (u) => `https://linktr.ee/${enc(u)}`],
    ['Flickr', (u) => `https://www.flickr.com/people/${enc(u)}`], ['Vimeo', (u) => `https://vimeo.com/${enc(u)}`],
    ['Spotify', (u) => `https://open.spotify.com/user/${enc(u)}`], ['Roblox (search)', (u) => `https://www.roblox.com/search/users?keyword=${enc(u)}`],
  ];

  async function checkPlatform(ctx, def, u) {
    if (def.valid && !def.valid(u)) return { state: 'unknown', detail: 'Username format not valid on this platform' };
    try {
      const data = await ctx.json(def.api(u), { timeout: 10000 });
      const detail = def.detail(data);
      return detail ? { state: 'found', detail: typeof detail === 'string' ? detail : 'Account exists' } : { state: 'missing', detail: 'No account' };
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      if ((def.missing || [404]).includes(err.status)) return { state: 'missing', detail: 'No account' };
      return { state: 'unknown', detail: err.status === 429 ? 'Rate limited, open to verify' : 'Could not verify, open to check' };
    }
  }

  function usernameDorks(u) {
    return [
      `"${u}"`,
      `intext:"${u}" -site:google.com`,
      `inurl:"${u}"`,
      `"${u}" site:github.com OR site:gitlab.com OR site:bitbucket.org`,
      `"${u}" site:reddit.com OR site:news.ycombinator.com`,
      `"${u}" site:pastebin.com OR site:ghostbin.com OR site:rentry.co`,
      `"${u}" site:linkedin.com/in OR site:facebook.com OR site:instagram.com`,
      `"${u}" site:twitter.com OR site:x.com OR site:t.me`,
      `"${u}" (email OR contact OR discord OR "@gmail.com")`,
      `"${u}" filetype:pdf OR filetype:doc OR filetype:xls`,
    ];
  }

  function runUsername(ctx, u) {
    const tasks = [];

    tasks.push(ctx.task('Profile check', async (card) => {
      const list = h('ul', { class: 'checks' });
      const marks = USER_API_CHECKS.map((def) => {
        const mark = h('span', { class: 'mark', 'data-state': 'pending' });
        const detail = h('span', { class: 'detail' }, 'Checking…');
        list.append(h('li', null, mark, extLink(def.name, def.url(u)), detail));
        return { mark, detail };
      });
      const counter = h('p', { class: 'muted small' }, 'Verifying public profile APIs…');
      const linkOnly = h('div', null,
        mutedP('These platforms block automated checks from the browser. Open each one to verify:'),
        linkChips(USER_LINK_ONLY.map(([name, fn]) => [name, fn(u)])));
      // Render the live list immediately so progress is visible, then settle the card.
      card.note([counter, list, linkOnly], 'Checking');
      let found = 0;
      await Promise.all(USER_API_CHECKS.map(async (def, i) => {
        const r = await checkPlatform(ctx, def, u);
        if (!ctx.alive()) return;
        if (r.state === 'found') found++;
        marks[i].mark.dataset.state = r.state;
        marks[i].detail.textContent = r.detail;
      }));
      if (!ctx.alive()) return;
      counter.textContent = `Found on ${found} of ${USER_API_CHECKS.length} verifiable platforms.`;
      // Update the status pill without rebuilding the (already rendered) list.
      const el = list.closest('.card');
      if (el) {
        el.dataset.state = found ? 'ok' : 'empty';
        $('.status', el).textContent = found ? `${found} found` : 'None found';
      }
    }));

    tasks.push(ctx.task('Google dorks', async (card) => {
      card.ok([
        mutedP('Ready-made search queries that surface where this username appears. Searches open in Google.'),
        dorksList(usernameDorks(u)),
      ], 'Ready');
    }));

    tasks.push(ctx.task('Search engines & username databases', async (card) => {
      card.ok([linkChips([
        ['WhatsMyName', `https://whatsmyname.app/?q=${enc(u)}`],
        ['Namechk', `https://namechk.com/`],
        ['DuckDuckGo', `https://duckduckgo.com/?q=${enc(`"${u}"`)}`],
        ['Bing', `https://www.bing.com/search?q=${enc(`"${u}"`)}`],
        ['Yandex', `https://yandex.com/search/?text=${enc(`"${u}"`)}`],
        ['Brave', `https://search.brave.com/search?q=${enc(`"${u}"`)}`],
        ['Wayback: profile URLs', `https://web.archive.org/web/*/${enc(u)}*`],
        ['GitHub code search', `https://github.com/search?q=${enc(u)}&type=code`],
      ])], 'Links');
    }));

    tasks.push(intelxTask(ctx, u));
    return Promise.all(tasks);
  }

  /* =====================================================================
     MODULE: IP / DNS
     ===================================================================== */
  async function geoLookup(ctx, ip) {
    const token = ctx.keys.ipinfo;
    try {
      const d = await ctx.json(`https://ipinfo.io/${enc(ip)}/json${token ? `?token=${enc(token)}` : ''}`, { timeout: 9000 });
      if (d.bogon) return { bogon: true };
      const m = /^(AS\d+)\s+(.*)$/.exec(d.org || '');
      return {
        source: 'ipinfo.io', ip: d.ip, hostname: d.hostname, city: d.city, region: d.region, countryCode: d.country,
        postal: d.postal, loc: d.loc, timezone: d.timezone, asn: m ? m[1] : '', org: m ? m[2] : d.org, anycast: d.anycast,
      };
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      const d = await ctx.json(`https://ipwho.is/${enc(ip)}`, { timeout: 9000 });
      if (!d.success) { const e = new Error(d.message || 'Lookup failed'); throw e; }
      return {
        source: 'ipwho.is (fallback)', ip: d.ip, city: d.city, region: d.region, countryCode: d.country_code,
        postal: d.postal, loc: d.latitude != null ? `${d.latitude},${d.longitude}` : '', timezone: d.timezone && d.timezone.id,
        asn: d.connection && d.connection.asn ? `AS${d.connection.asn}` : '', org: d.connection && (d.connection.org || d.connection.isp),
        type: d.type, continent: d.continent,
      };
    }
  }

  function renderGeo(g, origin) {
    const [lat, lon] = (g.loc || '').split(',');
    const place = [g.city, g.region].filter(Boolean).join(', ');
    return [
      kv([
        ['Resolved from', origin],
        ['IP address', g.ip],
        ['Location', place],
        ['Country', g.countryCode ? `${flagEmoji(g.countryCode)} ${countryName(g.countryCode)} (${g.countryCode})` : ''],
        ['Continent', g.continent],
        ['Postal code', g.postal],
        ['Coordinates', lat && lon ? `${lat}, ${lon}` : ''],
        ['Time zone', g.timezone],
        ['ASN', g.asn],
        ['Organization', g.org],
        ['Hostname', g.hostname],
        ['Anycast', g.anycast ? 'Yes' : ''],
        ['Address type', g.type],
        ['Source', g.source],
      ]),
      lat && lon ? h('div', { class: 'chips' }, extLink('View on OpenStreetMap', `https://www.openstreetmap.org/?mlat=${enc(lat)}&mlon=${enc(lon)}#map=10/${enc(lat)}/${enc(lon)}`)) : null,
      mutedP('IP geolocation is approximate and usually reflects the provider, not an exact address.'),
    ];
  }

  function ipLinks(ip) {
    return [
      ['Shodan', `https://www.shodan.io/host/${enc(ip)}`],
      ['Censys', `https://search.censys.io/hosts/${enc(ip)}`],
      ['GreyNoise', `https://viz.greynoise.io/ip/${enc(ip)}`],
      ['AbuseIPDB', `https://www.abuseipdb.com/check/${enc(ip)}`],
      ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${enc(ip)}`],
      ['URLScan', `https://urlscan.io/ip/${enc(ip)}`],
      ['BGP.he.net', `https://bgp.he.net/ip/${enc(ip)}`],
      ['Cisco Talos', `https://talosintelligence.com/reputation_center/lookup?search=${enc(ip)}`],
      ['IPinfo', `https://ipinfo.io/${enc(ip)}`],
      ['Google dork', googleUrl(`"${ip}"`)],
    ];
  }

  function runIp(ctx, q) {
    const tasks = [];
    const isHost = q.kind === 'host';
    let ipPromise;

    if (isHost) {
      ipPromise = (async () => {
        const a = await ctx.dns(q.value, 'A');
        if (a.answers.length) return a.answers[0].data;
        const aaaa = await ctx.dns(q.value, 'AAAA');
        return aaaa.answers.length ? aaaa.answers[0].data : null;
      })();
      ipPromise.catch(() => {});
      tasks.push(ctx.task(`DNS records for ${q.value}`, async (card) => {
        const types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'];
        const results = await Promise.all(types.map((t) => ctx.dns(q.value, t).catch(() => ({ answers: [] }))));
        const map = Object.fromEntries(types.map((t, i) => [t, results[i].answers]));
        if (results[0].status === 3) { card.empty('NXDOMAIN: this hostname does not exist.', 'Not found'); return; }
        const count = Object.values(map).reduce((s, l) => s + l.length, 0);
        if (!count) { card.empty('No DNS records returned.'); return; }
        card.ok([recordsView(map), mutedP('The first resolved IP address is analyzed below. Run other addresses separately.')], `${count} records`);
      }));
    } else {
      ipPromise = Promise.resolve(q.value);
    }

    tasks.push(ctx.task('Geolocation & network', async (card) => {
      const ip = await ipPromise;
      if (!ip) { card.empty('The hostname did not resolve to an IP address.'); return; }
      if (isPrivateIp(ip)) {
        card.note([p(`${ip} is a private or reserved address. It is not routable on the public internet, so no geolocation or ownership data exists.`)], 'Private');
        return;
      }
      const g = await geoLookup(ctx, ip);
      if (g.bogon) { card.note([p(`${ip} is a reserved (bogon) address with no public data.`)], 'Reserved'); return; }
      card.ok(renderGeo(g, isHost ? q.value : ''), 'Located');
    }));

    tasks.push(ctx.task('Reverse DNS (PTR)', async (card) => {
      const ip = await ipPromise;
      if (!ip) { card.empty('No IP address to look up.'); return; }
      const r = await ctx.dns(reverseName(ip), 'PTR');
      if (!r.answers.length) { card.empty(`No PTR record is published for ${ip}.`); return; }
      card.ok([chips(r.answers.map((a) => a.data), true)], `${r.answers.length} found`);
    }));

    tasks.push(ctx.task('Open ports & exposure (Shodan InternetDB)', async (card) => {
      const ip = await ipPromise;
      if (!ip) { card.empty('No IP address to look up.'); return; }
      if (isPrivateIp(ip)) { card.empty('Private addresses are not indexed.'); return; }
      let d;
      try {
        d = await ctx.json(`https://internetdb.shodan.io/${enc(ip)}`, { timeout: 10000 });
      } catch (err) {
        if (err.status === 404) { card.empty('Shodan InternetDB has no information about this address.'); return; }
        throw err;
      }
      const sections = [];
      if (d.ports && d.ports.length) sections.push(['Open ports', chips(d.ports.map(String), true)]);
      if (d.hostnames && d.hostnames.length) sections.push(['Hostnames', chips(d.hostnames, true)]);
      if (d.tags && d.tags.length) sections.push(['Tags', chips(d.tags)]);
      if (d.cpes && d.cpes.length) sections.push(['Software (CPE)', chips(d.cpes, true)]);
      if (d.vulns && d.vulns.length) {
        sections.push(['Known vulnerabilities', linkChips(d.vulns.slice(0, 60).map((v) => [v, `https://nvd.nist.gov/vuln/detail/${enc(v)}`]))]);
      }
      if (!sections.length) { card.empty('The address is indexed but exposes nothing notable.'); return; }
      card.ok([kv(sections)], d.vulns && d.vulns.length ? `${d.vulns.length} CVEs` : 'Indexed');
    }));

    tasks.push(ctx.task('Threat intel & lookup links', async (card) => {
      const ip = await ipPromise;
      if (!ip) { card.empty('No IP address to look up.'); return; }
      card.ok([linkChips(ipLinks(ip))], 'Links');
    }));

    tasks.push(intelxTask(ctx, q.value));
    return Promise.all(tasks);
  }

  /* =====================================================================
     MODULE: Domain
     ===================================================================== */
  function parseRdap(d) {
    const ev = (a) => ((d.events || []).find((e) => e.eventAction === a) || {}).eventDate;
    const registrarEnt = (d.entities || []).find((e) => (e.roles || []).includes('registrar'));
    let registrar = '';
    if (registrarEnt && registrarEnt.vcardArray && Array.isArray(registrarEnt.vcardArray[1])) {
      const fn = registrarEnt.vcardArray[1].find((x) => x[0] === 'fn');
      registrar = fn ? fn[3] : '';
    }
    return {
      registrar,
      created: ev('registration'),
      updated: ev('last changed'),
      expires: ev('expiration'),
      status: d.status || [],
      ns: (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean),
      dnssec: d.secureDNS ? (d.secureDNS.delegationSigned ? 'Signed' : 'Unsigned') : '',
    };
  }

  function ageOf(iso) {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return '';
    const days = Math.floor((Date.now() - t) / 86400000);
    if (days < 0) return '';
    const y = Math.floor(days / 365);
    return y >= 1 ? `${y} yr${y > 1 ? 's' : ''} ago` : `${days} day${days === 1 ? '' : 's'} ago`;
  }

  async function findSubdomains(ctx, domain) {
    let names;
    let source;
    try {
      const rows = await ctx.json(`https://crt.sh/?q=${enc(`%.${domain}`)}&output=json`, { timeout: 22000 });
      names = rows.flatMap((r) => String(r.name_value || '').split('\n'));
      source = 'crt.sh';
    } catch (err) {
      if (ctx.signal.aborted) throw err;
      const rows = await ctx.json(`https://api.certspotter.com/v1/issuances?domain=${enc(domain)}&include_subdomains=true&expand=dns_names`, { timeout: 22000 });
      names = rows.flatMap((r) => r.dns_names || []);
      source = 'Certificate Transparency (SSLMate)';
    }
    const set = new Set(names.map((n) => n.trim().toLowerCase().replace(/^\*\./, ''))
      .filter((n) => n === domain || n.endsWith(`.${domain}`)));
    return { list: [...set].sort(), source };
  }

  function domainLinks(d) {
    return [
      ['VirusTotal', `https://www.virustotal.com/gui/domain/${enc(d)}`],
      ['URLScan', `https://urlscan.io/search/#domain:${enc(d)}`],
      ['SecurityTrails', `https://securitytrails.com/domain/${enc(d)}/dns`],
      ['Shodan', `https://www.shodan.io/search?query=hostname:${enc(d)}`],
      ['crt.sh', `https://crt.sh/?q=${enc(d)}`],
      ['BuiltWith', `https://builtwith.com/${enc(d)}`],
      ['Wayback Machine', `https://web.archive.org/web/*/${enc(d)}`],
      ['DNSDumpster', 'https://dnsdumpster.com/'],
      ['MXToolbox', `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${enc(d)}`],
      ['Who.is', `https://who.is/whois/${enc(d)}`],
    ];
  }

  function domainDorks(d) {
    return [
      `site:${d}`,
      `site:${d} -www`,
      `site:*.${d} -www`,
      `site:${d} (inurl:admin OR inurl:login OR inurl:dashboard)`,
      `site:${d} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx)`,
      `site:${d} (ext:env OR ext:log OR ext:bak OR ext:sql)`,
      `site:${d} intitle:"index of"`,
      `"@${d}" -site:${d}`,
      `"${d}" site:pastebin.com OR site:github.com`,
      `link:${d} -site:${d}`,
    ];
  }

  function runDomain(ctx, domain) {
    const tasks = [];

    tasks.push(ctx.task('DNS records', async (card) => {
      const types = ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CAA', 'SOA'];
      const results = await Promise.all(types.map((t) => ctx.dns(domain, t).catch(() => null)));
      if (results.every((r) => !r)) throw Object.assign(new Error('network'), { network: true });
      if (results[0] && results[0].status === 3) { card.empty('NXDOMAIN: this domain does not exist in DNS.', 'Not found'); return; }
      const map = Object.fromEntries(types.map((t, i) => [t, results[i] ? results[i].answers : []]));
      const count = Object.values(map).reduce((s, l) => s + l.length, 0);
      if (!count) { card.empty('No DNS records returned.'); return; }
      card.ok([recordsView(map)], `${count} records`);
    }));

    tasks.push(ctx.task('Registration (RDAP / WHOIS)', async (card) => {
      let d;
      try {
        d = await ctx.json(`https://rdap.org/domain/${enc(domain)}`, { timeout: 15000, headers: { accept: 'application/rdap+json, application/json' } });
      } catch (err) {
        if (err.status === 404) {
          card.empty('No RDAP record found. If this is a subdomain, query the registrable domain (e.g. example.com). Some TLDs do not publish RDAP.');
          return;
        }
        throw err;
      }
      const r = parseRdap(d);
      card.ok([
        kv([
          ['Registrar', r.registrar],
          ['Created', r.created ? `${fmtDate(r.created)} (${ageOf(r.created)})` : ''],
          ['Last changed', r.updated ? fmtDate(r.updated) : ''],
          ['Expires', r.expires ? fmtDate(r.expires) : ''],
          ['Status', r.status.length ? chips(r.status) : ''],
          ['Name servers', r.ns.length ? chips(r.ns, true) : ''],
          ['DNSSEC', r.dnssec],
        ]),
        mutedP('Contact details are usually redacted for privacy (GDPR).'),
      ], 'Registered');
    }));

    tasks.push(ctx.task('Subdomains (certificate transparency)', async (card) => {
      const { list, source } = await findSubdomains(ctx, domain);
      if (!list.length) { card.empty('No certificates were found for this domain.'); return; }
      const copy = h('button', { class: 'link', type: 'button' }, 'Copy all');
      copy.addEventListener('click', async () => {
        const ok = await copyText(list.join('\n'));
        copy.textContent = ok ? 'Copied' : 'Copy failed';
        setTimeout(() => { copy.textContent = 'Copy all'; }, 1500);
      });
      card.ok([
        p(`${num(list.length)} unique hostnames seen in public certificates (${source}).`),
        h('div', { class: 'chips scroll-list' }, list.slice(0, 400).map((s) => h('span', { class: 'chip mono' }, s))),
        list.length > 400 ? mutedP(`Showing the first 400 of ${num(list.length)}. Use "Copy all" for the full list.`) : null,
        h('div', { class: 'chips' }, copy),
      ], `${num(list.length)} found`);
    }));

    tasks.push(ctx.task('Email security (SPF & DMARC)', async (card) => {
      const [txt, dmarc] = await Promise.all([ctx.dns(domain, 'TXT'), ctx.dns(`_dmarc.${domain}`, 'TXT')]);
      const spf = txt.answers.find((a) => /^v=spf1/i.test(a.data));
      const dm = dmarc.answers.find((a) => /^v=DMARC1/i.test(a.data));
      const policy = dm && /(?:^|;)\s*p=(\w+)/i.exec(dm.data);
      card.ok([kv([
        ['SPF', spf ? h('code', null, spf.data) : 'Not published'],
        ['DMARC', dm ? h('code', null, dm.data) : 'Not published'],
        ['DMARC policy', policy ? policy[1].toLowerCase() : ''],
      ]), mutedP('A missing or "none" policy can mean the domain is easier to spoof in email.')], 'Checked');
    }));

    tasks.push(ctx.task('Web archive history', async (card) => {
      const d = await ctx.json(`https://archive.org/wayback/available?url=${enc(domain)}`, { timeout: 12000 });
      const snap = d && d.archived_snapshots && d.archived_snapshots.closest;
      if (!snap || !snap.available) { card.empty('The Wayback Machine has no snapshots of this domain.'); return; }
      const ts = snap.timestamp || '';
      const iso = /^\d{14}$/.test(ts) ? `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}Z` : '';
      card.ok([
        kv([['Closest snapshot', iso ? fmtDate(iso) : ts]]),
        h('div', { class: 'chips' },
          extLink('Open snapshot', String(snap.url).replace(/^http:/, 'https:')),
          extLink('Full timeline', `https://web.archive.org/web/*/${enc(domain)}`)),
      ], 'Archived');
    }));

    tasks.push(ctx.task('Google dorks', async (card) => {
      card.ok([mutedP('Queries to map exposed pages, documents and mentions of this domain.'), dorksList(domainDorks(domain))], 'Ready');
    }));

    tasks.push(ctx.task('Investigation links', async (card) => { card.ok([linkChips(domainLinks(domain))], 'Links'); }));
    tasks.push(intelxTask(ctx, domain));
    return Promise.all(tasks);
  }

  /* =====================================================================
     MODULE: Phone
     ===================================================================== */
  let phoneLibPromise = null;
  function loadPhoneLib() {
    if (window.libphonenumber) return Promise.resolve(window.libphonenumber);
    if (!phoneLibPromise) {
      phoneLibPromise = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/libphonenumber-js@1.11.4/bundle/libphonenumber-max.js';
        s.async = true;
        s.onload = () => (window.libphonenumber ? resolve(window.libphonenumber) : reject(new Error('Parser loaded without exports.')));
        s.onerror = () => { phoneLibPromise = null; s.remove(); reject(new Error('The phone-number parser could not be loaded.')); };
        document.head.append(s);
      });
    }
    return phoneLibPromise;
  }

  const PHONE_TYPES = {
    MOBILE: 'Mobile', FIXED_LINE: 'Landline', FIXED_LINE_OR_MOBILE: 'Landline or mobile', TOLL_FREE: 'Toll-free',
    PREMIUM_RATE: 'Premium rate', SHARED_COST: 'Shared cost', VOIP: 'VoIP', PERSONAL_NUMBER: 'Personal number',
    PAGER: 'Pager', UAN: 'Universal access number', VOICEMAIL: 'Voicemail',
  };

  function phoneVariants(info) {
    const out = [info.international, info.e164, info.national, info.nationalDigits].filter(Boolean);
    return [...new Set(out)];
  }

  function runPhone(ctx, e164) {
    const tasks = [];
    const infoPromise = (async () => {
      const digits = e164.slice(1);
      try {
        const lib = await loadPhoneLib();
        const pn = lib.parsePhoneNumberFromString(e164);
        if (!pn) return { e164, digits, partial: true, reason: 'The number could not be parsed.' };
        let type = '';
        try { type = pn.getType() || ''; } catch { type = ''; }
        return {
          e164: pn.number, digits: pn.number.slice(1), international: pn.formatInternational(), national: pn.formatNational(),
          nationalDigits: String(pn.nationalNumber), country: pn.country, callingCode: pn.countryCallingCode,
          valid: pn.isValid(), possible: pn.isPossible(), type,
        };
      } catch (err) {
        return { e164, digits, partial: true, reason: err.message };
      }
    })();

    tasks.push(ctx.task('Number details', async (card) => {
      const i = await infoPromise;
      if (i.partial) {
        card.note([
          p(i.reason),
          kv([['E.164', i.e164], ['Digits', i.digits]]),
          mutedP('Country, validity and line type need the parser library. Check your connection and run the analysis again.'),
        ], 'Limited');
        return;
      }
      card.ok([
        kv([
          ['E.164 format', h('code', null, i.e164)],
          ['International', i.international],
          ['National', i.national],
          ['Country / region', i.country ? `${flagEmoji(i.country)} ${countryName(i.country)} (${i.country})` : 'Shared or unassigned region'],
          ['Calling code', `+${i.callingCode}`],
          ['Valid number', i.valid ? 'Yes' : 'No, this number does not match any known numbering plan'],
          ['Possible length', i.possible ? 'Yes' : 'No'],
          ['Line type', PHONE_TYPES[i.type] || (i.valid ? 'Unknown' : '')],
        ]),
        mutedP('Carrier and subscriber names are not available from free public APIs, and country data shows where the number range was issued, not where the phone is.'),
      ], i.valid ? 'Valid' : 'Invalid');
    }));

    tasks.push(ctx.task('Google dorks', async (card) => {
      const i = await infoPromise;
      const vs = phoneVariants(i);
      const any = vs.map((v) => `"${v}"`).join(' OR ');
      const main = vs[0] ? `"${vs[0]}"` : `"${e164}"`;
      card.ok([
        mutedP('Phone numbers appear in different formats, so these queries cover the common variants.'),
        dorksList([
          any,
          `(${any}) (contact OR whatsapp OR telegram OR viber)`,
          `(${any}) site:facebook.com OR site:linkedin.com OR site:instagram.com`,
          `(${any}) site:pastebin.com OR site:github.com`,
          `(${any}) (filetype:pdf OR filetype:doc OR filetype:xls)`,
          `${main} (scam OR spam OR fraud OR "who called")`,
        ]),
      ], 'Ready');
    }));

    tasks.push(ctx.task('Lookup & messaging links', async (card) => {
      const i = await infoPromise;
      const links = [
        ['WhatsApp', `https://wa.me/${i.digits}`],
        ['Telegram', `https://t.me/+${i.digits}`],
        ['Signal', `https://signal.me/#p/+${i.digits}`],
        ['Sync.me', `https://sync.me/search/?number=${i.digits}`],
      ];
      if (i.country && i.nationalDigits) links.unshift(['Truecaller', `https://www.truecaller.com/search/${i.country.toLowerCase()}/${i.nationalDigits}`]);
      card.ok([
        linkChips(links),
        mutedP('Messaging links show whether an account exists and may reveal a public profile name or photo. They do not notify the owner until you send a message.'),
      ], 'Links');
    }));

    tasks.push(intelxTask(ctx, e164));
    return Promise.all(tasks);
  }

  /* =====================================================================
     MODULE: Minecraft
     ===================================================================== */
  function runMinecraft(ctx, q) {
    const tasks = [];
    let profilePromise = (async () => {
      try {
        const res = await ctx.json(`https://playerdb.co/api/player/minecraft/${enc(q.value)}`, { timeout: 12000 });
        return res && res.success && res.data && res.data.player ? res.data.player : null;
      } catch (err) {
        if (err.data && err.data.success === false) return null;
        if (err.status === 400 || err.status === 404) return null;
        throw err;
      }
    })();
    profilePromise.catch(() => {});

    tasks.push(ctx.task('Profile (Mojang)', async (card) => {
      const pl = await profilePromise;
      if (!pl) {
        card.empty(q.kind === 'uuid'
          ? 'No Java Edition account uses this UUID.'
          : `No Java Edition account uses the name "${q.value}". It may be available, or the account may have been deleted.`, 'Not found');
        return;
      }
      const raw = pl.raw_id || String(pl.id || '').replace(/-/g, '');
      const img = (src, w, label) => h('img', { src, alt: label, width: w, height: w, loading: 'lazy', referrerpolicy: 'no-referrer', onerror: (e) => e.target.remove() });
      card.ok([
        h('div', { class: 'avatars' },
          img(`https://mc-heads.net/avatar/${enc(raw)}/96`, 96, `${pl.username} head`),
          h('img', { src: `https://mc-heads.net/body/${enc(raw)}/140`, alt: `${pl.username} full skin`, height: 140, loading: 'lazy', referrerpolicy: 'no-referrer', onerror: (e) => e.target.remove() })),
        kv([
          ['Username', pl.username],
          ['UUID', h('code', null, pl.id)],
          ['UUID (no dashes)', h('code', null, raw)],
        ]),
        h('div', { class: 'chips' },
          extLink('Download skin', `https://mc-heads.net/download/${enc(raw)}`),
          extLink('Session profile (JSON)', `https://sessionserver.mojang.com/session/minecraft/profile/${enc(raw)}`)),
      ], 'Premium account');
    }));

    tasks.push(ctx.task('Name history & cosmetics', async (card) => {
      const pl = await profilePromise;
      if (!pl) { card.empty('Nothing to show because no matching account was found.'); return; }
      let a;
      try {
        a = await ctx.json(`https://api.ashcon.app/mojang/v2/user/${enc(pl.username)}`, { timeout: 12000 });
      } catch (err) {
        if (err.status === 404) { card.empty('No extended profile data is cached for this account.'); return; }
        throw err;
      }
      const hist = Array.isArray(a.username_history) ? a.username_history : [];
      const tex = a.textures || {};
      card.ok([
        kv([
          ['Account created', a.created_at ? fmtDate(a.created_at) : ''],
          ['Skin model', tex.slim === true ? 'Slim (Alex)' : tex.slim === false ? 'Classic (Steve)' : ''],
          ['Cape', tex.cape ? 'Has a cape' : 'No cape'],
        ]),
        hist.length > 1
          ? h('div', { class: 'records' }, hist.map((e, i) => h('div', { class: 'rec' },
            h('span', { class: 'tag' }, i === 0 ? 'first' : `#${i + 1}`),
            h('ul', null, h('li', null, e.username, h('small', null, e.changed_at ? fmtDate(e.changed_at) : 'original name'))))))
          : mutedP('No previous names on record.'),
        mutedP('Mojang removed its public name-history endpoint in 2022, so only names cached by third parties appear. NameMC is the most complete source.'),
      ], hist.length > 1 ? `${hist.length} names` : 'Loaded');
    }));

    tasks.push(ctx.task('NameMC & community profiles', async (card) => {
      const pl = await profilePromise;
      const name = pl ? pl.username : q.value;
      const links = [
        ['NameMC profile', `https://namemc.com/profile/${enc(name)}`],
        ['NameMC search', `https://namemc.com/search?q=${enc(name)}`],
        ['Laby.net', `https://laby.net/@${enc(name)}`],
        ['Crafty.gg', `https://crafty.gg/@${enc(name)}`],
        ['Hypixel stats', `https://plancke.io/hypixel/player/stats/${enc(name)}`],
        ['MCSR Ranked', `https://mcsrranked.com/stats/${enc(name)}`],
      ];
      card.ok([
        linkChips(links),
        q.kind === 'name' || pl ? h('div', { class: 'chips' },
          h('button', { class: 'link', type: 'button', onclick: () => openTool('username', name, true) }, `Run Username Analysis for "${name}"`)) : null,
        mutedP('NameMC has no free public API, so these open its pages directly (it also shows servers, friends and skin history).'),
      ], 'Links');
    }));

    tasks.push(ctx.task('Google dorks', async (card) => {
      const pl = await profilePromise;
      const n = pl ? pl.username : q.value;
      card.ok([
        mutedP('Find where this player appears across forums, servers, videos and social media.'),
        dorksList([
          `"${n}" minecraft`,
          `"${n}" site:namemc.com OR site:laby.net`,
          `"${n}" (minecraft OR hypixel) site:reddit.com`,
          `"${n}" minecraft site:youtube.com OR site:twitch.tv`,
          `"${n}" (minecraft OR mc) discord`,
          `"${n}" minecraft (ban OR banned OR appeal OR griefer) -site:namemc.com`,
          `"${n}" site:twitter.com OR site:x.com OR site:github.com`,
          `inurl:"${n}" minecraft`,
        ]),
      ], 'Ready');
    }));

    tasks.push(intelxTask(ctx, q.kind === 'uuid' ? q.value : q.value));
    return Promise.all(tasks);
  }

  /* =====================================================================
     Tool registry
     ===================================================================== */
  const TOOLS = [
    {
      id: 'username', title: 'Username Analysis',
      blurb: 'Find where a handle exists across developer, social and gaming platforms, with ready-made Google dorks.',
      desc: 'Checks public profile APIs, builds Google dorks and links to username databases and IntelX.',
      icon: '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-7 8-7s8 3 8 7"/>',
      placeholder: 'Enter a username', hint: '2 to 40 characters: letters, numbers, . _ -', example: 'torvalds',
      normalize(v) {
        const s = v.trim().replace(/^@/, '');
        if (!/^[A-Za-z0-9._-]{2,40}$/.test(s)) throw new Error('Enter a username of 2 to 40 characters using letters, numbers, dots, underscores or hyphens.');
        return s;
      },
      run: runUsername,
    },
    {
      id: 'ip', title: 'IP/DNS Analysis',
      blurb: 'Geolocation, ASN, reverse DNS, open ports and CVEs for an IP address, or full DNS for a hostname.',
      desc: 'Uses ipinfo.io, Shodan InternetDB, DNS over HTTPS and IntelX. Hostnames are resolved first.',
      icon: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.5 3 14.5 0 18M12 3c-3 3.5-3 14.5 0 18"/>',
      placeholder: 'IPv4, IPv6 or hostname', hint: 'For example an IP address or www.example.com', example: '1.1.1.1',
      normalize(v) {
        let s = v.trim();
        if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
        if (isIPv4(s) || isIPv6(s)) return { kind: 'ip', value: s.toLowerCase() };
        return { kind: 'host', value: normalizeDomain(s) };
      },
      run: runIp,
    },
    {
      id: 'domain', title: 'Domain Analysis',
      blurb: 'DNS records, RDAP registration data, subdomains from certificates, email security and archive history.',
      desc: 'Combines DNS over HTTPS, RDAP, Certificate Transparency, Wayback Machine, Google dorks and IntelX.',
      icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
      placeholder: 'example.com', hint: 'A domain or URL; the protocol and path are ignored', example: 'wikipedia.org',
      normalize: normalizeDomain,
      run: runDomain,
    },
    {
      id: 'phone', title: 'Phone Number Analysis',
      blurb: 'Validate and parse a number offline-style, then pivot to dorks, messaging apps and caller databases.',
      desc: 'Parses the number with libphonenumber, then builds Google dorks and lookup links. Use international format.',
      icon: '<rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18h2"/>',
      placeholder: '+44 7700 900123', hint: 'International format with the country code, starting with +', example: '+44 7700 900123',
      normalize(v) {
        let s = v.trim().replace(/[\s().-]/g, '');
        if (s.startsWith('00')) s = `+${s.slice(2)}`;
        if (!/^\+[1-9]\d{5,14}$/.test(s)) throw new Error('Use international format with the country code, for example +39 312 345 6789.');
        return s;
      },
      run: runPhone,
    },
    {
      id: 'minecraft', title: 'Minecraft Account Analysis',
      blurb: 'Resolve a Java Edition username or UUID, view skins and history, and pivot to NameMC and dorks.',
      desc: 'Uses PlayerDB (Mojang data) and Ashcon for history, plus NameMC links and Google dorks.',
      icon: '<path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M12 12l9-5M12 12L3 7M12 12v10"/>',
      placeholder: 'Java username or UUID', hint: '3 to 16 characters (letters, numbers, _) or a UUID', example: 'jeb_',
      normalize(v) {
        const s = v.trim();
        const compact = s.replace(/-/g, '');
        if (/^[0-9a-f]{32}$/i.test(compact) && /^[0-9a-f-]{32,36}$/i.test(s)) return { kind: 'uuid', value: compact.toLowerCase() };
        if (!/^[A-Za-z0-9_]{3,16}$/.test(s)) throw new Error('Enter a Java username (3 to 16 letters, numbers or underscores) or a 32-character UUID.');
        return { kind: 'name', value: s };
      },
      run: runMinecraft,
    },
  ];

  /* =====================================================================
     App shell: views, navigation, tool form
     ===================================================================== */
  const views = { splash: $('#view-splash'), menu: $('#view-menu'), tool: $('#view-tool') };
  const els = {
    form: $('#tool-form'), input: $('#tool-input'), run: $('#tool-run'), error: $('#tool-error'), results: $('#results-host'),
    title: $('#tool-title'), desc: $('#tool-desc'), hint: $('#tool-hint'), example: $('#tool-example'),
    grid: $('#menu-grid'), dialog: $('#settings'),
  };
  let current = 'splash';
  let navToken = 0;
  let activeTool = null;

  function show(name) {
    if (name === current) return Promise.resolve();
    const token = ++navToken;
    const from = views[current];
    const to = views[name];
    from.classList.remove('active');
    from.classList.add('leaving');
    return sleep(reduceMotion ? 0 : 260).then(() => {
      if (token !== navToken) return;
      for (const [key, v] of Object.entries(views)) {
        v.classList.remove('active', 'leaving');
        v.hidden = key !== name;
      }
      to.classList.add('active');
      current = name;
      document.body.dataset.view = name;
      window.scrollTo(0, 0);
      to.focus({ preventScroll: true });
    });
  }

  function cancelRun() {
    if (currentRun) { currentRun.ctrl.abort(); currentRun = null; }
    els.run.classList.remove('busy');
  }

  function configureTool(tool) {
    cancelRun();
    activeTool = tool;
    els.title.textContent = tool.title;
    els.desc.textContent = tool.desc;
    els.input.value = '';
    els.input.placeholder = tool.placeholder;
    els.hint.textContent = tool.hint;
    els.example.textContent = `Try: ${tool.example}`;
    els.error.hidden = true;
    els.results.replaceChildren();
    if (current === 'tool') {
      const v = views.tool;
      v.classList.remove('active');
      void v.offsetWidth;
      v.classList.add('active');
    }
  }

  function render(state) {
    if (state.view === 'tool') {
      const tool = TOOLS.find((t) => t.id === state.tool);
      if (!tool) return render({ view: 'menu' });
      configureTool(tool);
      return show('tool').then(() => { if (current === 'tool') els.input.focus({ preventScroll: true }); });
    }
    cancelRun();
    return show(state.view);
  }

  function navigate(view, tool) {
    const state = { view, tool: tool || null };
    try { history.pushState(state, ''); } catch { /* history unavailable */ }
    return render(state);
  }

  function openTool(id, value, autorun) {
    navigate('tool', id);
    if (value) {
      els.input.value = value;
      if (autorun) runAnalysis();
    }
  }

  window.addEventListener('popstate', (e) => { render(e.state || { view: 'splash' }); });

  function showError(msg) {
    els.error.textContent = msg;
    els.error.hidden = false;
    els.error.style.animation = 'none';
    void els.error.offsetWidth;
    els.error.style.animation = '';
    els.input.focus();
  }

  async function runAnalysis() {
    if (!activeTool) return;
    let q;
    try { q = activeTool.normalize(els.input.value); } catch (err) { showError(err.message); return; }
    els.error.hidden = true;
    cancelRun();
    const run = { id: ++runSeq, ctrl: new AbortController() };
    currentRun = run;
    els.run.classList.add('busy');
    els.results.replaceChildren();
    const host = h('div', { class: 'results', 'aria-live': 'polite' });
    els.results.append(host);
    const ctx = makeCtx(run, host);
    try {
      await activeTool.run(ctx, q);
    } catch (err) {
      if (ctx.alive()) host.append(h('p', { class: 'form-error' }, explain(err)));
    } finally {
      if (currentRun === run) els.run.classList.remove('busy');
    }
    if (currentRun === run) {
      const first = host.firstElementChild;
      if (first && !reduceMotion) first.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  /* ---------- Settings dialog ---------- */
  function openSettings() {
    const s = Settings.get();
    $('#set-intelx').value = s.intelx;
    $('#set-intelx-host').value = s.intelxHost;
    $('#set-ipinfo').value = s.ipinfo;
    if (typeof els.dialog.showModal === 'function') els.dialog.showModal();
    else els.dialog.setAttribute('open', '');
  }

  $('#settings-btn').addEventListener('click', openSettings);
  $('#settings-cancel').addEventListener('click', () => els.dialog.close());
  $('#settings-clear').addEventListener('click', () => {
    for (const k of Object.values(Settings.keys)) Settings.write(k, '');
    $('#set-intelx').value = '';
    $('#set-ipinfo').value = '';
    $('#set-intelx-host').value = 'free.intelx.io';
  });
  $('#settings-form').addEventListener('submit', () => {
    Settings.write(Settings.keys.intelx, $('#set-intelx').value.trim());
    Settings.write(Settings.keys.intelxHost, $('#set-intelx-host').value);
    Settings.write(Settings.keys.ipinfo, $('#set-ipinfo').value.trim());
  });
  els.dialog.addEventListener('click', (e) => { if (e.target === els.dialog) els.dialog.close(); });

  /* ---------- Menu ---------- */
  TOOLS.forEach((tool, i) => {
    const card = h('button', { class: 'menu-card', type: 'button', style: `--i:${i}` },
      h('span', { class: 'menu-icon' }, svg(tool.icon)),
      h('h3', null, tool.title),
      p(tool.blurb),
      h('span', { class: 'go' }, 'Open module', svg('<path d="M5 12h14M13 6l6 6-6 6"/>', 16)));
    card.addEventListener('click', () => navigate('tool', tool.id));
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${e.clientX - r.left}px`);
      card.style.setProperty('--my', `${e.clientY - r.top}px`);
    });
    els.grid.append(card);
  });

  /* ---------- Splash ---------- */
  [...'osintnow.'].forEach((c, i) => {
    $('.letters').append(h('span', { class: `letter${c === '.' ? ' dot' : ''}`, style: `--i:${i}` }, c));
  });
  $('#start-btn').addEventListener('click', () => navigate('menu'));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && current === 'splash' && !e.target.closest('button')) navigate('menu');
  });

  /* ---------- Tool view wiring ---------- */
  $('#home-btn').addEventListener('click', () => { if (current !== 'menu') navigate('menu'); });
  $('#back-btn').addEventListener('click', () => navigate('menu'));
  els.form.addEventListener('submit', (e) => { e.preventDefault(); runAnalysis(); });
  els.example.addEventListener('click', () => {
    if (!activeTool) return;
    els.input.value = activeTool.example;
    runAnalysis();
  });
  els.input.addEventListener('input', () => { els.error.hidden = true; });

  try { history.replaceState({ view: 'splash' }, ''); } catch { /* history unavailable */ }
})();