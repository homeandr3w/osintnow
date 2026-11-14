/* osintnow. — client-side OSINT toolkit. Only free, public, no-key sources. */
(() => {
  'use strict';

  /* =====================================================================
     Utilities
     ===================================================================== */
  const $ = (s, r = document) => r.querySelector(s);
  const enc = encodeURIComponent;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'style') el.style.cssText = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  const ext = (url, text, cls = 'inline') => h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', class: cls, text: text || url });

  const store = {
    get(k) { try { return localStorage.getItem(k) || ''; } catch { return ''; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignore */ } }
  };

  async function fetchStatus(url, { timeout = 10000, headers } = {}) {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeout);
    try {
      const r = await fetch(url, { signal: ctl.signal, cache: 'no-store', headers });
      let data = null;
      try { data = await r.json(); } catch { /* not JSON */ }
      return { status: r.status, data };
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error('Request timed out.');
      throw new Error('Could not reach the service (network error, blocked by CORS, or the service is down).');
    } finally {
      clearTimeout(t);
    }
  }

  async function fetchJSON(url, opts) {
    const r = await fetchStatus(url, opts);
    if (r.status === 429) throw new Error('Rate limit reached for this free service. Try again in a minute.');
    if (r.status < 200 || r.status >= 300) throw new Error(`The service answered with HTTP ${r.status}.`);
    if (r.data == null) throw new Error('The service returned an unexpected response.');
    return r.data;
  }

  const fmtDate = s => { const d = new Date(s); return isNaN(d) ? String(s) : d.toISOString().slice(0, 10); };
  const daysSince = s => { const d = new Date(s); return isNaN(d) ? null : Math.floor((Date.now() - d.getTime()) / 864e5); };
  const regionName = cc => { try { return new Intl.DisplayNames(['en-US'], { type: 'region' }).of(cc.toUpperCase()) || cc; } catch { return cc; } };
  const flag = cc => /^[A-Za-z]{2}$/.test(cc || '') ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0))) : '';
  const hostOf = u => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch { return ''; } };
  const gsearch = q => `https://www.google.com/search?q=${enc(q)}`;

  /* ----- validators ----- */
  const isIPv4 = v => /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v);
  const isIPv6 = v => { if (!v.includes(':') || /[\s/\\?#@]/.test(v)) return false; try { new URL(`http://[${v}]`); return true; } catch { return false; } };
  const isDomain = v => /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(v) && !/^[\d.]+$/.test(v);
  const isEmail = v => /^[^\s@<>()[\]\\,;:"]{1,64}@([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i.test(v) && v.length <= 254;
  function normDomain(v) {
    let s = v.trim().toLowerCase();
    if (!s) return null;
    try { s = new URL(s.includes('://') ? s : `http://${s}`).hostname; } catch { return null; }
    s = s.replace(/\.$/, '');
    return isDomain(s) ? s : null;
  }

  function reverseName(ip) {
    if (isIPv4(ip)) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
    const clean = ip.split('%')[0];
    const [l, r] = clean.split('::');
    const L = l ? l.split(':') : [];
    const R = r ? r.split(':') : [];
    const fill = clean.includes('::') ? 8 - L.length - R.length : 0;
    const parts = [...L, ...Array(Math.max(fill, 0)).fill('0'), ...R].map(p => p.padStart(4, '0'));
    if (parts.length !== 8 || parts.some(p => !/^[0-9a-f]{4}$/i.test(p))) throw new Error('Unsupported IPv6 notation for reverse lookup.');
    return `${parts.join('').split('').reverse().join('.')}.ip6.arpa`;
  }

  /* ----- DNS over HTTPS (Cloudflare, falling back to Google) ----- */
  const RTYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 257: 'CAA' };
  const cleanTxt = s => String(s).replace(/^"|"$/g, '').replace(/"\s+"/g, '');
  async function doh(name, type) {
    const q = `name=${enc(name)}&type=${type}`;
    let last;
    for (const u of [`https://cloudflare-dns.com/dns-query?${q}`, `https://dns.google/resolve?${q}`]) {
      try {
        const data = await fetchJSON(u, { headers: { accept: 'application/dns-json' }, timeout: 8000 });
        return {
          status: data.Status,
          answers: (data.Answer || []).map(a => {
            const t = RTYPES[a.type] || String(a.type);
            return { name: a.name, type: t, ttl: a.TTL, data: t === 'TXT' ? cleanTxt(a.data) : String(a.data).replace(/\.$/, '') };
          })
        };
      } catch (e) { last = e; }
    }
    throw last || new Error('DNS lookup failed.');
  }

  /* =====================================================================
     UI building blocks
     ===================================================================== */
  function kv(rows) {
    const dl = h('dl', { class: 'kv' });
    for (const [k, v, mono] of rows) {
      if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue;
      dl.append(h('dt', { text: k }), h('dd', { class: mono ? 'mono' : '' }, Array.isArray(v) ? v.map(x => h('div', {}, x)) : v));
    }
    return dl.children.length ? dl : h('p', { class: 'note', text: 'No data returned.' });
  }

  function table(head, rows) {
    return h('div', { class: 'table-wrap' },
      h('table', {},
        h('thead', {}, h('tr', {}, head.map(x => h('th', { text: x })))),
        h('tbody', {}, rows.map(r => h('tr', {}, r.map(c => (c && c.nodeType) ? h('td', {}, c) : h('td', { class: 'mono', text: c })))))));
  }

  const chips = (list, mono) => h('div', { class: 'chips' }, list.map(x => h('span', { class: `chip${mono ? ' mono' : ''}`, text: x })));
  const note = text => h('p', { class: 'note', text });
  const src = text => h('p', { class: 'src', text });
  const badge = (kind, text) => h('span', { class: `badge ${kind}`, text });

  function linkGrid(items) {
    return h('ul', { class: 'links' }, items.map(i => h('li', {}, h('a', { href: i.u, target: '_blank', rel: 'noopener noreferrer' }, h('strong', { text: i.t }), h('small', { text: i.d || hostOf(i.u) })))));
  }

  function panel(out, title, fn, tag, wide) {
    const body = h('div', { class: 'body' }, h('div', { class: 'loader', 'aria-label': 'Loading' }, h('span'), h('span'), h('span')));
    const card = h('article', { class: `card${wide ? ' wide' : ''}`, style: `--i:${Math.min(out.children.length, 10)}` },
      h('header', { class: 'card-h' }, h('h3', { text: title }), tag ? h('span', { class: 'tag', text: tag }) : null), body);
    out.append(card);
    const p = Promise.resolve().then(fn)
      .then(res => body.replaceChildren(...[].concat(typeof res === 'string' ? note(res) : res).filter(Boolean)))
      .catch(err => body.replaceChildren(h('p', { class: 'err', text: `⚠ ${(err && err.message) || 'Lookup failed.'}` })));
    (out._p = out._p || []).push(p);
    return p;
  }

  async function dnsTable(host, types) {
    const res = await Promise.allSettled(types.map(t => doh(host, t)));
    const rows = [];
    let ok = 0;
    res.forEach(r => {
      if (r.status === 'fulfilled') { ok++; r.value.answers.forEach(a => rows.push([a.type, a.data, String(a.ttl)])); }
    });
    if (!ok) throw new Error('DNS-over-HTTPS resolvers could not be reached.');
    if (!rows.length) return note('No records found. The name may not exist or has no public records of these types.');
    return [table(['Type', 'Value', 'TTL'], rows), src('Source: Cloudflare / Google DNS-over-HTTPS')];
  }

  /* =====================================================================
     Tool: Username Analysis
     ===================================================================== */
  const J = (o, ...k) => k.reduce((a, x) => (a == null ? a : a[x]), o);
  const USER_CHECKS = [
    { n: 'GitHub', api: u => `https://api.github.com/users/${u}`, page: u => `https://github.com/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: [d.name, d.public_repos != null && `${d.public_repos} public repos`, d.created_at && `joined ${fmtDate(d.created_at)}`].filter(Boolean).join(' · ') } : s === 404 ? { f: false } : null },
    { n: 'GitLab', api: u => `https://gitlab.com/api/v4/users?username=${u}`, page: u => `https://gitlab.com/${u}`,
      ok: (s, d) => s === 200 && Array.isArray(d) ? (d.length ? { f: true, i: d[0].name || '' } : { f: false }) : null },
    { n: 'Codeberg', api: u => `https://codeberg.org/api/v1/users/${u}`, page: u => `https://codeberg.org/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: [d.full_name, d.created && `joined ${fmtDate(d.created)}`].filter(Boolean).join(' · ') } : s === 404 ? { f: false } : null },
    { n: 'Keybase', api: u => `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${u}&fields=basics`, page: u => `https://keybase.io/${u}`,
      ok: (s, d) => s === 200 && d ? (J(d, 'them', 0) ? { f: true, i: '' } : { f: false }) : null },
    { n: 'Hacker News', api: u => `https://hacker-news.firebaseio.com/v0/user/${u}.json`, page: u => `https://news.ycombinator.com/user?id=${u}`,
      ok: (s, d) => s === 200 ? (d ? { f: true, i: `${d.karma} karma · joined ${fmtDate(d.created * 1000)}` } : { f: false }) : null },
    { n: 'DEV Community', api: u => `https://dev.to/api/users/by_username?url=${u}`, page: u => `https://dev.to/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: [d.name, d.joined_at].filter(Boolean).join(' · ') } : s === 404 ? { f: false } : null },
    { n: 'Docker Hub', api: u => `https://hub.docker.com/v2/users/${u}/`, page: u => `https://hub.docker.com/u/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: d.date_joined ? `joined ${fmtDate(d.date_joined)}` : '' } : s === 404 ? { f: false } : null },
    { n: 'Chess.com', api: u => `https://api.chess.com/pub/player/${u}`, page: u => `https://www.chess.com/member/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: d.joined ? `joined ${fmtDate(d.joined * 1000)}` : '' } : s === 404 ? { f: false } : null },
    { n: 'Lichess', api: u => `https://lichess.org/api/user/${u}`, page: u => `https://lichess.org/@/${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: d.createdAt ? `joined ${fmtDate(d.createdAt)}` : '' } : s === 404 ? { f: false } : null },
    { n: 'Mastodon.social', api: u => `https://mastodon.social/api/v1/accounts/lookup?acct=${u}`, page: u => `https://mastodon.social/@${u}`,
      ok: (s, d) => s === 200 && d ? { f: true, i: [d.display_name, d.followers_count != null && `${d.followers_count} followers`].filter(Boolean).join(' · ') } : s === 404 ? { f: false } : null },
    { n: 'Bluesky', valid: u => /^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?$/i.test(u), api: u => `https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${u}.bsky.social`, page: u => `https://bsky.app/profile/${u}.bsky.social`,
      ok: (s, d) => s === 200 && d ? { f: true, i: [d.displayName, d.followersCount != null && `${d.followersCount} followers`].filter(Boolean).join(' · ') } : (s === 400 || s === 404) ? { f: false } : null },
    { n: 'Reddit', api: u => `https://www.reddit.com/user/${u}/about.json`, page: u => `https://www.reddit.com/user/${u}`,
      ok: (s, d) => s === 200 && J(d, 'data', 'name') ? { f: true, i: `${J(d, 'data', 'total_karma') ?? '?'} karma · joined ${fmtDate(d.data.created_utc * 1000)}` } : s === 404 ? { f: false } : null },
    { n: 'Wikipedia (EN)', api: u => `https://en.wikipedia.org/w/api.php?action=query&list=users&ususers=${u}&usprop=registration%7Ceditcount&format=json&origin=*`, page: u => `https://en.wikipedia.org/wiki/User:${u}`,
      ok: (s, d) => { const x = J(d, 'query', 'users', 0); if (s !== 200 || !x) return null; return ('missing' in x || 'invalid' in x) ? { f: false } : { f: true, i: `${x.editcount ?? 0} edits` }; } }
  ];

  const MANUAL_PROFILES = [
    ['Instagram', u => `https://www.instagram.com/${u}/`], ['X / Twitter', u => `https://x.com/${u}`], ['TikTok', u => `https://www.tiktok.com/@${u}`],
    ['YouTube', u => `https://www.youtube.com/@${u}`], ['Twitch', u => `https://www.twitch.tv/${u}`], ['Pinterest', u => `https://www.pinterest.com/${u}/`],
    ['Telegram', u => `https://t.me/${u}`], ['Snapchat', u => `https://www.snapchat.com/add/${u}`], ['LinkedIn', u => `https://www.linkedin.com/in/${u}`],
    ['Medium', u => `https://medium.com/@${u}`], ['Steam', u => `https://steamcommunity.com/id/${u}`], ['Spotify', u => `https://open.spotify.com/user/${u}`],
    ['SoundCloud', u => `https://soundcloud.com/${u}`], ['Patreon', u => `https://www.patreon.com/${u}`], ['Flickr', u => `https://www.flickr.com/people/${u}`],
    ['Vimeo', u => `https://vimeo.com/${u}`], ['Tumblr', u => `https://${u}.tumblr.com`], ['Linktree', u => `https://linktr.ee/${u}`],
    ['About.me', u => `https://about.me/${u}`], ['Behance', u => `https://www.behance.net/${u}`], ['Dribbble', u => `https://dribbble.com/${u}`],
    ['Replit', u => `https://replit.com/@${u}`], ['Product Hunt', u => `https://www.producthunt.com/@${u}`], ['Pastebin', u => `https://pastebin.com/u/${u}`],
    ['Imgur', u => `https://imgur.com/user/${u}`], ['Kick', u => `https://kick.com/${u}`], ['Last.fm', u => `https://www.last.fm/user/${u}`],
    ['Letterboxd', u => `https://letterboxd.com/${u}/`], ['Gravatar', u => `https://gravatar.com/${u}`], ['npm', u => `https://www.npmjs.com/~${u}`],
    ['PyPI', u => `https://pypi.org/user/${u}/`], ['Hugging Face', u => `https://huggingface.co/${u}`]
  ];

  async function runUsername(input, out, ctx) {
    const u = input.trim().replace(/^@/, '');
    if (!/^[\w.\-]{1,40}$/.test(u)) throw new Error('Usernames can contain letters, numbers, dots, dashes and underscores (max 40 characters).');
    const name = enc(u);

    const summary = h('p', { class: 'note', text: 'Checking platforms…' });
    const rows = USER_CHECKS.map(c => {
      const st = h('td', {}, badge('wait', 'Checking'));
      const info = h('td', { text: '' });
      return { c, st, info, tr: h('tr', {}, h('td', { text: c.n }), st, info, h('td', {}, ext(c.page(name), 'Open', 'inline'))) };
    });

    const done = panel(out, 'Live account check', async () => {
      const wrap = h('div', {}, summary, table(['Platform', 'Status', 'Details', 'Link'], []));
      const tbody = wrap.querySelector('tbody');
      rows.forEach(r => tbody.append(r.tr));
      let found = 0, checked = 0;
      await Promise.all(rows.map(async r => {
        const { c } = r;
        if (c.valid && !c.valid(u)) { r.st.replaceChildren(badge('unk', 'Invalid name')); r.info.textContent = 'Username format not allowed here'; return; }
        try {
          const { status, data } = await fetchStatus(c.api(name), { timeout: 9000 });
          const res = c.ok(status, data);
          checked++;
          if (!res) r.st.replaceChildren(badge('unk', status === 429 || status === 403 ? 'Rate limited' : 'Unknown'));
          else if (res.f) { found++; r.st.replaceChildren(badge('found', 'Found')); r.info.textContent = res.i || ''; }
          else r.st.replaceChildren(badge('miss', 'Not found'));
        } catch (e) {
          r.st.replaceChildren(badge('unk', 'Unreachable'));
          r.info.textContent = 'Blocked or offline';
        }
        summary.textContent = `${found} profile${found === 1 ? '' : 's'} found · ${checked}/${rows.length} checked`;
      }));
      summary.textContent = `${found} profile${found === 1 ? '' : 's'} found across ${checked} platforms that allow browser lookups.`;
      return wrap;
    }, 'Public APIs', true);

    panel(out, 'Manual verification links', () => [
      note('Most large networks block automated checks from browsers, so open these to confirm by eye. Treat identical usernames as leads, not proof of identity.'),
      linkGrid(MANUAL_PROFILES.map(([t, f]) => ({ t, u: f(name), d: hostOf(f(name)) })))
    ], `${MANUAL_PROFILES.length} sites`, true);

    panel(out, 'Search engine & leak-index pivots', () => linkGrid([
      { t: 'Google — exact', u: gsearch(`"${u}"`), d: 'Exact username mentions' },
      { t: 'Google — profiles', u: gsearch(`"${u}" (inurl:user OR inurl:profile OR inurl:u OR inurl:@${u})`), d: 'Profile-style URLs' },
      { t: 'Google — code & pastes', u: gsearch(`"${u}" (site:github.com OR site:gist.github.com OR site:pastebin.com OR site:gitlab.com)`), d: 'Public code and paste sites' },
      { t: 'Bing', u: `https://www.bing.com/search?q=${enc(`"${u}"`)}`, d: 'Second index' },
      { t: 'DuckDuckGo', u: `https://duckduckgo.com/?q=${enc(`"${u}"`)}`, d: 'Privacy-friendly index' },
      { t: 'Yandex', u: `https://yandex.com/search/?text=${enc(`"${u}"`)}`, d: 'Strong on Eastern-European sites' },
      { t: 'Intelligence X', u: `https://intelx.io/?s=${name}`, d: 'Free tier searches leaks & pastes' },
      { t: 'Wayback Machine', u: `https://web.archive.org/web/*/${name}*`, d: 'Archived pages mentioning it' },
      { t: 'Reverse username (WhatsMyName)', u: 'https://whatsmyname.app/', d: 'Open-source username checker' }
    ]), 'Pivots', true);
    await done;
  }

  /* =====================================================================
     Tool: IP / DNS Analysis
     ===================================================================== */
  async function ipInfoPanel(ip) {
    const tok = store.get('osintnow.ipinfo');
    let data, srcName = 'ipinfo.io';
    try {
      data = await fetchJSON(`https://ipinfo.io/${enc(ip)}/json${tok ? `?token=${enc(tok)}` : ''}`, { timeout: 9000 });
      if (data.bogon) return note('This is a bogon / reserved address (private, loopback or otherwise non-routable), so no public geolocation exists.');
      const [asn, ...orgParts] = (data.org || '').split(' ');
      const loc = (data.loc || '').split(',');
      return [kv([
        ['IP address', data.ip, true], ['Hostname', data.hostname, true],
        ['Country', data.country ? `${flag(data.country)} ${regionName(data.country)} (${data.country})` : ''],
        ['Region / city', [data.city, data.region, data.postal].filter(Boolean).join(', ')],
        ['Coordinates', data.loc ? ext(`https://www.openstreetmap.org/?mlat=${loc[0]}&mlon=${loc[1]}#map=10/${loc[0]}/${loc[1]}`, `${data.loc} (open map)`) : ''],
        ['ASN', /^AS\d+/i.test(asn || '') ? asn : '', true], ['Organization', /^AS\d+/i.test(asn || '') ? orgParts.join(' ') : data.org],
        ['Timezone', data.timezone]
      ]), src(`Source: ${srcName}. IP geolocation is approximate — often city-level at best, and VPN/proxy exits show the provider's location.`)];
    } catch (e1) {
      try {
        srcName = 'ipwho.is';
        data = await fetchJSON(`https://ipwho.is/${enc(ip)}`, { timeout: 9000 });
        if (data.success === false) throw new Error(data.message || 'Lookup failed.');
        return [kv([
          ['IP address', data.ip, true], ['Type', data.type],
          ['Country', data.country_code ? `${flag(data.country_code)} ${data.country} (${data.country_code})` : data.country],
          ['Region / city', [data.city, data.region, data.postal].filter(Boolean).join(', ')],
          ['Coordinates', data.latitude != null ? ext(`https://www.openstreetmap.org/?mlat=${data.latitude}&mlon=${data.longitude}#map=10/${data.latitude}/${data.longitude}`, `${data.latitude}, ${data.longitude} (open map)`) : ''],
          ['ASN', J(data, 'connection', 'asn') ? `AS${data.connection.asn}` : '', true], ['Organization', J(data, 'connection', 'org')], ['ISP', J(data, 'connection', 'isp')],
          ['Domain', J(data, 'connection', 'domain'), true], ['Timezone', J(data, 'timezone', 'id')]
        ]), src('Source: ipwho.is (fallback — ipinfo.io was unavailable). Geolocation is approximate.')];
      } catch (e2) { throw e1; }
    }
  }

  async function runIPDNS(input, out) {
    const raw = input.trim();
    let host = null, ip = null;
    if (isIPv4(raw) || isIPv6(raw)) ip = raw;
    else { host = normDomain(raw); if (!host) throw new Error('Enter a valid IPv4, IPv6 address, hostname or domain.'); }

    if (host) {
      const ipsP = (async () => {
        const r = await Promise.allSettled([doh(host, 'A'), doh(host, 'AAAA')]);
        return r.flatMap(x => x.status === 'fulfilled' ? x.value.answers.filter(a => a.type === 'A' || a.type === 'AAAA').map(a => a.data) : []);
      })();
      panel(out, `DNS records · ${host}`, () => dnsTable(host, ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']), 'DoH', true);
      const ips = [...new Set(await ipsP)];
      if (!ips.length) { panel(out, 'Resolution', () => 'This hostname has no A/AAAA records, so there is no IP address to analyze.'); return; }
      ip = ips[0];
      if (ips.length > 1) panel(out, 'Resolved addresses', () => [chips(ips, true), note(`Showing network details for the first address (${ip}). Paste another to inspect it.`)], `${ips.length} IPs`);
    }

    panel(out, 'Geolocation & network', () => ipInfoPanel(ip), ip);
    panel(out, 'Reverse DNS (PTR)', async () => {
      const r = await doh(reverseName(ip), 'PTR');
      const ptr = r.answers.filter(a => a.type === 'PTR').map(a => a.data);
      return ptr.length ? [chips(ptr, true), src('PTR records often reveal hosting providers, ISPs or mail servers.')] : 'No PTR record is published for this address.';
    });
    panel(out, 'Pivot to other sources', () => linkGrid([
      { t: 'Shodan', u: `https://www.shodan.io/host/${enc(ip)}`, d: 'Open ports & banners' },
      { t: 'Censys', u: `https://search.censys.io/hosts/${enc(ip)}`, d: 'Services & certificates' },
      { t: 'AbuseIPDB', u: `https://www.abuseipdb.com/check/${enc(ip)}`, d: 'Abuse reports' },
      { t: 'GreyNoise', u: `https://viz.greynoise.io/ip/${enc(ip)}`, d: 'Internet scanner noise' },
      { t: 'VirusTotal', u: `https://www.virustotal.com/gui/ip-address/${enc(ip)}`, d: 'Reputation & relations' },
      { t: 'Hurricane Electric BGP', u: `https://bgp.he.net/ip/${enc(ip)}`, d: 'Routing & prefixes' },
      { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(ip)}`, d: 'Leaks & pastes' },
      { t: 'urlscan.io', u: `https://urlscan.io/search/#${enc(`ip:"${ip}"`)}`, d: 'Scans hosted on this IP' }
    ]), 'Pivots', true);
  }

  /* =====================================================================
     Tool: Domain Analysis
     ===================================================================== */
  const TXT_SERVICES = [
    [/^google-site-verification=/i, 'Google Search Console / Workspace'], [/^MS=/i, 'Microsoft 365'], [/^facebook-domain-verification=/i, 'Meta / Facebook'],
    [/^atlassian-domain-verification=/i, 'Atlassian'], [/^docusign=/i, 'DocuSign'], [/^stripe-verification=/i, 'Stripe'], [/^apple-domain-verification=/i, 'Apple'],
    [/^zoom-domain-verification/i, 'Zoom'], [/^adobe-idp-site-verification=/i, 'Adobe'], [/^github-challenge-/i, 'GitHub'], [/^openai-domain-verification=/i, 'OpenAI'],
    [/^slack-domain-verification=/i, 'Slack'], [/^h1-domain-verification=/i, 'HackerOne'], [/^_?globalsign-domain-verification=/i, 'GlobalSign'],
    [/^amazonses:/i, 'Amazon SES'], [/^dropbox-domain-verification=/i, 'Dropbox'], [/^miro-verification=/i, 'Miro'], [/^onetrust-domain-verification=/i, 'OneTrust'],
    [/^mailchimp/i, 'Mailchimp'], [/^shopify-verification/i, 'Shopify']
  ];

  function rdapPanel(d) {
    const ev = {};
    (d.events || []).forEach(e => { ev[e.eventAction] = e.eventDate; });
    const reg = (d.entities || []).find(e => (e.roles || []).includes('registrar'));
    const fn = e => { const a = J(e, 'vcardArray', 1) && e.vcardArray[1].find(x => x[0] === 'fn'); return a ? a[3] : ''; };
    const age = ev.registration ? daysSince(ev.registration) : null;
    const expIn = ev.expiration ? Math.ceil((new Date(ev.expiration) - Date.now()) / 864e5) : null;
    return [kv([
      ['Domain', d.ldhName, true],
      ['Status', d.status && d.status.length ? d.status : ''],
      ['Registered', ev.registration ? `${fmtDate(ev.registration)}${age != null ? ` (${(age / 365.25).toFixed(1)} years ago)` : ''}` : ''],
      ['Last changed', ev['last changed'] ? fmtDate(ev['last changed']) : ''],
      ['Expires', ev.expiration ? `${fmtDate(ev.expiration)}${expIn != null ? ` (${expIn >= 0 ? `in ${expIn} days` : `${-expIn} days ago`})` : ''}` : ''],
      ['Registrar', fn(reg) || J(reg, 'publicIds', 0, 'identifier')],
      ['Name servers', (d.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).filter(Boolean), true],
      ['DNSSEC', d.secureDNS ? (d.secureDNS.delegationSigned ? 'Signed' : 'Unsigned') : '']
    ]), src('Source: RDAP via rdap.org. Contact details are usually redacted for privacy (GDPR).')];
  }

  async function mailSecurity(d) {
    const [txt, dm, mx] = await Promise.allSettled([doh(d, 'TXT'), doh(`_dmarc.${d}`, 'TXT'), doh(d, 'MX')]);
    if (txt.status === 'rejected' && mx.status === 'rejected') throw new Error('DNS-over-HTTPS resolvers could not be reached.');
    const txts = x => x.status === 'fulfilled' ? x.value.answers.filter(a => a.type === 'TXT').map(a => a.data) : [];
    const all = txts(txt);
    const spf = all.filter(x => /^v=spf1/i.test(x));
    const dmarc = txts(dm).filter(x => /^v=DMARC1/i.test(x));
    const mxs = mx.status === 'fulfilled' ? mx.value.answers.filter(a => a.type === 'MX').map(a => a.data) : [];
    const services = [...new Set(all.flatMap(t => TXT_SERVICES.filter(([re]) => re.test(t)).map(([, n]) => n)))];
    return [kv([
      ['Mail servers (MX)', mxs, true],
      ['SPF', spf.length ? spf : 'Not published', true],
      ['DMARC', dmarc.length ? dmarc : 'Not published', true],
      ['Third-party services', services.length ? services.join(', ') : '']
    ]), src('Verification TXT records reveal which SaaS platforms the organization has registered with.')];
  }

  async function subdomainPanel(d) {
    const data = await fetchJSON(`https://api.certspotter.com/v1/issuances?domain=${enc(d)}&include_subdomains=true&expand=dns_names`, { timeout: 15000 });
    const set = new Set();
    (Array.isArray(data) ? data : []).forEach(c => (c.dns_names || []).forEach(n => {
      const x = n.replace(/^\*\./, '').toLowerCase();
      if (x === d || x.endsWith(`.${d}`)) set.add(x);
    }));
    const list = [...set].sort();
    if (!list.length) return 'No subdomains were found in public Certificate Transparency logs.';
    return [h('div', { class: 'stat' }, h('b', { text: String(list.length) }), h('span', { text: 'unique names in certificates' })),
      chips(list.slice(0, 120), true),
      list.length > 120 ? note(`Showing 120 of ${list.length}.`) : null,
      src('Source: Certificate Transparency via SSLMate Cert Spotter (free tier). Names may include historical or internal hosts.')];
  }

  async function urlscanPanel(d) {
    const data = await fetchJSON(`https://urlscan.io/api/v1/search/?q=${enc(`domain:${d}`)}&size=10`, { timeout: 12000 });
    const res = data.results || [];
    if (!res.length) return 'No public urlscan.io scans found for this domain.';
    return [table(['Date', 'Page', 'IP', 'Result'], res.map(r => [fmtDate(J(r, 'task', 'time')), String(J(r, 'page', 'url') || '').slice(0, 70), J(r, 'page', 'ip') || '', ext(`https://urlscan.io/result/${enc(r._id)}/`, 'View')])),
      src(`Source: urlscan.io (${data.total ?? res.length} public scans total)`)];
  }

  async function waybackPanel(d) {
    const data = await fetchJSON(`https://archive.org/wayback/available?url=${enc(d)}`, { timeout: 10000 });
    const c = J(data, 'archived_snapshots', 'closest');
    if (!c) return [note('No snapshots found in the Wayback Machine.'), linkGrid([{ t: 'Wayback calendar', u: `https://web.archive.org/web/*/${enc(d)}`, d: 'archive.org' }])];
    const ts = c.timestamp || '';
    return [kv([['Closest snapshot', ext(c.url.replace(/^http:/, 'https:'), `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`)], ['Status', c.status]]),
      linkGrid([{ t: 'Full snapshot calendar', u: `https://web.archive.org/web/*/${enc(d)}`, d: 'archive.org' }])];
  }

  async function runDomain(input, out) {
    const d = normDomain(input);
    if (!d) throw new Error('Enter a valid domain such as example.com (URLs are fine — the host is extracted).');
    panel(out, 'Registration (RDAP / WHOIS)', async () => {
      const r = await fetchStatus(`https://rdap.org/domain/${enc(d)}`, { timeout: 15000 });
      if (r.status === 404) return 'No RDAP record found. The domain may be unregistered, or its TLD does not publish RDAP.';
      if (r.status !== 200 || !r.data) throw new Error(`The RDAP service answered with HTTP ${r.status}.`);
      return rdapPanel(r.data);
    }, d);
    panel(out, 'DNS records', () => dnsTable(d, ['A', 'AAAA', 'NS', 'MX', 'TXT', 'CAA', 'SOA']), 'DoH', true);
    panel(out, 'Email security & service footprint', () => mailSecurity(d));
    panel(out, 'Subdomains (Certificate Transparency)', () => subdomainPanel(d));
    panel(out, 'Recent public scans', () => urlscanPanel(d));
    panel(out, 'Web archive', () => waybackPanel(d));
    panel(out, 'Pivot to other sources', () => linkGrid([
      { t: 'crt.sh', u: `https://crt.sh/?q=${enc(d)}`, d: 'Certificate search' },
      { t: 'VirusTotal', u: `https://www.virustotal.com/gui/domain/${enc(d)}`, d: 'Reputation & relations' },
      { t: 'SecurityTrails', u: `https://securitytrails.com/domain/${enc(d)}/dns`, d: 'DNS history' },
      { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(d)}`, d: 'Leaks, pastes, documents' },
      { t: 'urlscan.io', u: `https://urlscan.io/search/#${enc(`domain:${d}`)}`, d: 'Scan history' },
      { t: 'Shodan', u: `https://www.shodan.io/search?query=hostname%3A${enc(d)}`, d: 'Exposed services' },
      { t: 'Google — site index', u: gsearch(`site:${d}`), d: 'Indexed pages' },
      { t: 'Google — exposed files', u: gsearch(`site:${d} (ext:pdf OR ext:docx OR ext:xlsx OR ext:txt)`), d: 'Public documents' },
      { t: 'BuiltWith', u: `https://builtwith.com/${enc(d)}`, d: 'Technology stack' }
    ]), 'Pivots', true);
  }

  /* =====================================================================
     Tool: Phone Number Analysis
     ===================================================================== */
  const PHONE_TYPES = {
    MOBILE: 'Mobile', FIXED_LINE: 'Fixed line', FIXED_LINE_OR_MOBILE: 'Fixed line or mobile', TOLL_FREE: 'Toll-free', PREMIUM_RATE: 'Premium rate',
    SHARED_COST: 'Shared cost', VOIP: 'VoIP', PERSONAL_NUMBER: 'Personal number', PAGER: 'Pager', UAN: 'Universal access number', VOICEMAIL: 'Voicemail'
  };

  async function runPhone(input, out, ctx) {
    const lib = window.libphonenumber;
    if (!lib) throw new Error('The phone parsing library could not be loaded. Check your connection and reload the page.');
    let p;
    try { p = lib.parsePhoneNumberFromString(input.trim(), ctx.extra || undefined); } catch { /* handled below */ }
    if (!p) throw new Error('That does not look like a phone number. Use international format (e.g. +1 415 555 2671) or choose a default country.');

    const digits = p.number.replace(/\D/g, '');
    const type = p.getType && p.getType();
    const possible = p.getPossibleCountries ? p.getPossibleCountries() : [];

    panel(out, 'Number intelligence', () => [kv([
      ['Valid number', p.isValid() ? '✓ Matches a known numbering plan' : '✗ Not valid for any known numbering plan'],
      ['Possible length', p.isPossible() ? '✓ Plausible length' : '✗ Length is not plausible'],
      ['E.164', p.number, true], ['International', p.formatInternational(), true], ['National', p.formatNational(), true], ['RFC 3966', p.getURI(), true],
      ['Country / region', p.country ? `${flag(p.country)} ${regionName(p.country)} (${p.country})` : ''],
      ['Also possible', possible.length > 1 ? possible.map(c => `${flag(c)} ${regionName(c)}`).join(', ') : ''],
      ['Calling code', `+${p.countryCallingCode}`, true], ['Line type', type ? (PHONE_TYPES[type] || type) : 'Not determinable from the number alone'],
      ['National number', p.nationalNumber, true]
    ]), src('Source: libphonenumber-js (Google numbering-plan metadata), computed offline in your browser. No number is sent to any server.'),
    note('Carrier, owner and live status cannot be derived from the digits: numbers are ported between carriers and recycled.')], p.isValid() ? 'Valid' : 'Check format');

    const variants = [...new Set([p.number, p.formatInternational(), p.formatNational(), digits, p.formatNational().replace(/[^\d]+/g, '-').replace(/^-|-$/g, ''), p.formatNational().replace(/[^\d]+/g, '.').replace(/^\.|\.$/g, '')])];
    panel(out, 'Search variations', () => [
      note('The same number is published in many formats. Searching all of them surfaces listings, ads, forum posts and scam reports.'),
      chips(variants, true),
      linkGrid([
        { t: 'Google — all formats', u: gsearch(variants.map(v => `"${v}"`).join(' OR ')), d: 'Combined exact-match query' },
        { t: 'Google — scam reports', u: gsearch(`(${variants.map(v => `"${v}"`).join(' OR ')}) (scam OR spam OR fraud OR "who called")`), d: 'Reputation' },
        { t: 'Google — social & classifieds', u: gsearch(`(${variants.slice(0, 3).map(v => `"${v}"`).join(' OR ')}) (site:facebook.com OR site:linkedin.com OR site:olx.com OR site:craigslist.org OR site:x.com)`), d: 'Where numbers get posted' },
        { t: 'Bing', u: `https://www.bing.com/search?q=${enc(variants.slice(0, 3).map(v => `"${v}"`).join(' OR '))}`, d: 'Second index' },
        { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(p.number)}`, d: 'Leaks & pastes' }
      ])
    ], `${variants.length} formats`, true);

    panel(out, 'Pivot to caller-ID & messaging', () => [
      note('These open third-party pages; nothing is sent until you click. Messaging apps may show a name or photo that the owner chose themselves.'),
      linkGrid([
        { t: 'WhatsApp', u: `https://wa.me/${digits}`, d: 'Check for an account' },
        { t: 'Telegram', u: `https://t.me/+${digits}`, d: 'Check for an account' },
        { t: 'Truecaller', u: `https://www.truecaller.com/search/${enc((p.country || 'us').toLowerCase())}/${p.nationalNumber}`, d: 'Crowd-sourced caller ID' },
        { t: 'Sync.me', u: `https://sync.me/search/?number=${digits}`, d: 'Caller ID lookup' },
        { t: 'Who Called Me (reports)', u: gsearch(`"${p.formatNational()}" who called`), d: 'Community reports' }
      ])
    ], 'Pivots', true);
  }

  const PHONE_LEARN = () => h('details', { class: 'learn-more', id: 'phone-learn' },
    h('summary', { text: 'Learn more about phone number analysis' }),
    h('div', { class: 'learn-body' },
      h('div', {}, h('h4', { text: 'What a number reveals' }), h('ul', {},
        h('li', { text: 'Country or region from the calling code (+1, +44, +39…).' }),
        h('li', { text: 'Numbering-plan range: valid, plausible, or malformed.' }),
        h('li', { text: 'Line type: mobile, fixed, VoIP, toll-free or premium.' }),
        h('li', { text: 'Every standard notation (E.164, national, RFC 3966) for searching.' }))),
      h('div', {}, h('h4', { text: 'What it does not reveal' }), h('ul', {},
        h('li', { text: 'The owner’s identity or exact location.' }),
        h('li', { text: 'The current carrier — number portability breaks old lookups.' }),
        h('li', { text: 'Whether it is active: numbers are recycled and caller IDs are spoofed.' }))),
      h('div', {}, h('h4', { text: 'Typical investigation workflow' }), h('ul', {},
        h('li', { text: 'Normalize to E.164, then search every format variation.' }),
        h('li', { text: 'Check community scam/spam reports and caller-ID reputation.' }),
        h('li', { text: 'See whether messaging apps expose a self-chosen name or photo.' }),
        h('li', { text: 'Look in public registries, classifieds, WHOIS/RDAP contacts and archives.' }),
        h('li', { text: 'Corroborate with at least two independent sources before concluding.' }))),
      h('div', {}, h('h4', { text: 'Good practice' }), h('ul', {},
        h('li', { text: 'Only investigate numbers you are authorized to research (your own, your organization’s, or reported abuse).' }),
        h('li', { text: 'Do not contact, harass or publish personal details of private individuals.' }),
        h('li', { text: 'Respect privacy law (GDPR, CCPA) and each service’s terms.' })))));

  /* =====================================================================
     Tool: Minecraft Account Analysis
     ===================================================================== */
  const dashUUID = r => r.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');

  async function runMinecraft(input, out, ctx) {
    const v = input.trim();
    const isUUID = /^[0-9a-f]{8}-?([0-9a-f]{4}-?){3}[0-9a-f]{12}$/i.test(v);
    if (!isUUID && !/^[A-Za-z0-9_]{3,16}$/.test(v)) throw new Error('Java usernames are 3–16 characters (letters, numbers, underscore). You can also paste a UUID.');

    const { status, data } = await fetchStatus(`https://playerdb.co/api/player/minecraft/${enc(v)}`, { timeout: 12000 });
    const player = status === 200 && data && data.success ? J(data, 'data', 'player') : null;

    if (!player) {
      panel(out, 'Mojang profile', () => status === 429 ? 'Rate limited by the lookup service. Try again shortly.' : [
        note(`No Java Edition account found for “${v}”. It may be available, misspelled, or belong to a Bedrock-only account.`),
        src('Source: Mojang session servers via PlayerDB')]);
      panel(out, 'Check availability & history', () => linkGrid([
        { t: 'NameMC', u: `https://namemc.com/search?q=${enc(v)}`, d: 'Availability & drop times' },
        { t: 'LABY.net', u: `https://laby.net/@${enc(v)}`, d: 'Name history' }
      ]), 'Pivots', true);
      return;
    }

    const uuid = player.id || dashUUID(player.raw_id || '');
    const raw = (player.raw_id || uuid.replace(/-/g, ''));
    const history = player.name_history || J(player, 'meta', 'name_history') || [];
    const skin = player.skin_texture ? String(player.skin_texture).replace(/^http:/, 'https:') : '';

    panel(out, 'Mojang profile', () => [
      h('div', { class: 'mc' },
        h('img', { class: 'avatar', src: `https://crafatar.com/avatars/${enc(raw)}?size=96&overlay`, alt: `${player.username} avatar`, loading: 'lazy', width: 96, height: 96, onerror: e => e.target.remove() }),
        h('img', { class: 'body-render', src: `https://crafatar.com/renders/body/${enc(raw)}?scale=4&overlay`, alt: `${player.username} skin render`, loading: 'lazy', onerror: e => e.target.remove() })),
      kv([
        ['Username', player.username, true], ['UUID', uuid, true], ['UUID (no dashes)', raw, true],
        ['Skin texture', skin ? ext(skin, 'View texture file') : ''],
        ['Name history', history.length ? history.map(x => `${x.name}${x.changedToAt ? ` — ${fmtDate(x.changedToAt)}` : ' — original'}`) : '']
      ]),
      src('Source: Mojang via PlayerDB, skins via Crafatar. Mojang removed the public name-history API in 2022; use NameMC for history.')
    ], 'Java Edition');

    panel(out, 'Skin & community pivots', () => [
      linkGrid([
        { t: 'NameMC profile', u: `https://namemc.com/profile/${enc(player.username)}`, d: 'History, skins, capes, servers' },
        { t: 'LABY.net', u: `https://laby.net/@${enc(player.username)}`, d: 'Name history & cosmetics' },
        { t: 'Download skin (PNG)', u: `https://crafatar.com/skins/${enc(raw)}`, d: 'Crafatar' },
        { t: 'Hypixel stats', u: `https://plancke.io/hypixel/player/stats/${enc(player.username)}`, d: 'Server statistics' },
        { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(player.username)}`, d: 'Leaks & pastes' }
      ]),
      h('div', { class: 'actions' }, h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => ctx.pivot('username', player.username) }, 'Run username analysis on this name →'))
    ], 'Pivots', true);

    panel(out, 'Public mention search', () => [
      note('Search operators for finding where this username is publicly used (profiles, servers, forums, videos).'),
      linkGrid([
        { t: 'Google — Minecraft mentions', u: gsearch(`"${player.username}" minecraft`), d: 'Exact username + game' },
        { t: 'Google — social platforms', u: gsearch(`"${player.username}" (site:reddit.com OR site:youtube.com OR site:x.com OR site:twitch.tv OR site:github.com)`), d: 'Cross-platform usage' },
        { t: 'Google — servers & forums', u: gsearch(`"${player.username}" (hypixel OR mineplex OR "minecraft server" OR "minecraft forum")`), d: 'Community footprint' },
        { t: 'Google — NameMC', u: gsearch(`site:namemc.com "${player.username}"`), d: 'Related NameMC pages' }
      ]),
      src('Only public mentions are searched. Credential or password lookups are deliberately not part of this tool.')
    ], 'Dorks', true);
  }

  /* =====================================================================
     Tool: Email Analysis + Breaches
     ===================================================================== */
  const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'aol.com', 'gmx.com', 'gmx.net', 'mail.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'fastmail.com', 'tuta.com', 'tutanota.com', 'libero.it', 'virgilio.it']);
  const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com', 'throwawaymail.com', 'sharklasers.com', 'getnada.com', 'dispostable.com', 'maildrop.cc', 'mailnesia.com', 'fakeinbox.com', 'moakt.com', 'tmpmail.org']);

  async function sha256hex(s) {
    if (!(window.crypto && crypto.subtle)) throw new Error('Hashing is unavailable in this context (a secure origin such as https:// or localhost is required).');
    const b = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
    return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
  }
  const imgExists = src => new Promise(res => { const i = new Image(); const t = setTimeout(() => res(false), 8000); i.onload = () => { clearTimeout(t); res(true); }; i.onerror = () => { clearTimeout(t); res(false); }; i.src = src; });

  async function breachPanel(email) {
    const r = await fetchStatus(`https://api.xposedornot.com/v1/check-email/${enc(email)}`, { timeout: 15000 });
    if (r.status === 429) throw new Error('Rate limit reached for XposedOrNot. Try again in a minute.');
    if (r.status === 404) return [h('div', { class: 'stat' }, h('b', { text: '0' }), h('span', { text: 'known breaches' })), note('This address was not found in the breach corpus indexed by XposedOrNot. That is encouraging, but not a guarantee.'), src('Source: XposedOrNot. The address is sent to xposedornot.com to perform this check.')];
    if (r.status !== 200 || !r.data) throw new Error(`The breach service answered with HTTP ${r.status}.`);
    const list = [...new Set((r.data.breaches || []).flat(Infinity).filter(x => typeof x === 'string'))];
    if (!list.length) return [h('div', { class: 'stat' }, h('b', { text: '0' }), h('span', { text: 'known breaches' })), src('Source: XposedOrNot')];
    return [h('div', { class: 'stat' }, h('b', { text: String(list.length) }), h('span', { text: `breach${list.length === 1 ? '' : 'es'} include this address` })),
      chips(list),
      note('If you own this address: change the password on those services, make every password unique, and enable multi-factor authentication.'),
      src('Source: XposedOrNot. The address is sent to xposedornot.com to perform this check.')];
  }

  async function runEmail(input, out, ctx) {
    const em = input.trim().toLowerCase();
    if (!isEmail(em)) throw new Error('Enter a valid email address such as name@example.com.');
    const at = em.lastIndexOf('@');
    const local = em.slice(0, at), domain = em.slice(at + 1);
    const gm = domain === 'gmail.com' || domain === 'googlemail.com';
    const plus = local.includes('+');

    panel(out, 'Address analysis', () => [kv([
      ['Local part', local, true], ['Domain', domain, true],
      ['Provider type', DISPOSABLE.has(domain) ? 'Disposable / temporary mailbox' : FREE_MAIL.has(domain) ? 'Free public mailbox provider' : 'Custom or corporate domain'],
      ['Sub-address tag', plus ? `+${local.split('+')[1]} (alias of ${local.split('+')[0]}@${domain})` : ''],
      ['Canonical Gmail form', gm ? `${local.split('+')[0].replace(/\./g, '')}@gmail.com` : '']
    ]), h('div', { class: 'actions' },
      h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => ctx.pivot('username', local.split('+')[0]) }, `Run username analysis on “${local.split('+')[0]}” →`),
      FREE_MAIL.has(domain) || DISPOSABLE.has(domain) ? null : h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => ctx.pivot('domain', domain) }, `Analyze domain ${domain} →`)),
    src('Disposable and free-provider lists are a small built-in sample, not exhaustive.')], domain);

    panel(out, 'Mail infrastructure', async () => {
      const [mx, txt, dm] = await Promise.allSettled([doh(domain, 'MX'), doh(domain, 'TXT'), doh(`_dmarc.${domain}`, 'TXT')]);
      if (mx.status === 'rejected') throw new Error('DNS-over-HTTPS resolvers could not be reached.');
      const mxs = mx.value.answers.filter(a => a.type === 'MX').map(a => a.data);
      const t = x => x.status === 'fulfilled' ? x.value.answers.filter(a => a.type === 'TXT').map(a => a.data) : [];
      return [kv([
        ['Receives email', mxs.length ? '✓ MX records published' : '✗ No MX records — the domain may not accept mail'],
        ['Mail servers', mxs, true],
        ['SPF', t(txt).filter(x => /^v=spf1/i.test(x)).join(' ') || 'Not published', true],
        ['DMARC', t(dm).filter(x => /^v=DMARC1/i.test(x)).join(' ') || 'Not published', true]
      ]), src('Source: Cloudflare / Google DNS-over-HTTPS')];
    });

    panel(out, 'Gravatar', async () => {
      const hash = await sha256hex(em);
      const url = `https://gravatar.com/avatar/${hash}?s=160&d=404`;
      return (await imgExists(url))
        ? [h('div', { class: 'mc' }, h('img', { class: 'avatar', src: url, alt: 'Gravatar avatar', width: 96, height: 96 })), note('A Gravatar is registered for this address. The picture is public and was chosen by the owner.'), linkGrid([{ t: 'Gravatar profile', u: `https://gravatar.com/${hash}`, d: 'May list linked accounts' }])]
        : 'No public Gravatar is registered for this address.';
    });

    panel(out, 'Data breach exposure', () => breachPanel(em), 'XposedOrNot');

    panel(out, 'Pivot to other sources', () => linkGrid([
      { t: 'Have I Been Pwned', u: `https://haveibeenpwned.com/account/${enc(em)}`, d: 'Breach lookup' },
      { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(em)}`, d: 'Leaks & pastes' },
      { t: 'Epieos', u: `https://epieos.com/?q=${enc(em)}&t=email`, d: 'Linked-account lookup' },
      { t: 'Google — exact', u: gsearch(`"${em}"`), d: 'Public mentions' },
      { t: 'Google — code & pastes', u: gsearch(`"${em}" (site:github.com OR site:pastebin.com OR site:gitlab.com)`), d: 'Commits and pastes' },
      { t: 'DeHashed', u: `https://dehashed.com/search?query=${enc(em)}`, d: 'Leak search (account may be required)' }
    ]), 'Pivots', true);
  }

  async function runBreaches(input, out, ctx) {
    const v = input.trim();
    if (!v) throw new Error('Enter a username or an email address.');
    if (v.includes('@')) {
      const em = v.toLowerCase();
      if (!isEmail(em)) throw new Error('That looks like an email address but is not valid.');
      panel(out, `Breach exposure · ${em}`, () => breachPanel(em), 'XposedOrNot', true);
    } else {
      if (!/^[\w.\-]{1,40}$/.test(v)) throw new Error('Usernames can contain letters, numbers, dots, dashes and underscores (max 40 characters).');
      panel(out, 'How username breach checks work', () => [
        note('Free, keyless APIs index breaches by email address; usernames are only searchable in commercial or account-gated leak indexes. So the honest approach is to search public leak indexes and open-web pastes yourself using the links below.'),
        note('Tip: if you know an email address associated with this username, paste it here instead for a direct breach lookup.')
      ], 'Info', true);
      panel(out, 'Leak indexes', () => linkGrid([
        { t: 'Intelligence X', u: `https://intelx.io/?s=${enc(v)}`, d: 'Free tier: pastes, leaks, documents' },
        { t: 'Have I Been Pwned', u: 'https://haveibeenpwned.com/', d: 'Breach list & email search' },
        { t: 'DeHashed', u: `https://dehashed.com/search?query=${enc(v)}`, d: 'Account may be required' },
        { t: 'LeakCheck', u: 'https://leakcheck.io/', d: 'Leak search' },
        { t: 'BreachDirectory', u: 'https://breachdirectory.org/', d: 'Public breach search' },
        { t: 'XposedOrNot', u: 'https://xposedornot.com/', d: 'Free breach database' }
      ]), 'Pivots', true);
      panel(out, 'Public paste & code search', () => linkGrid([
        { t: 'Pastebin mentions', u: gsearch(`site:pastebin.com "${v}"`), d: 'Google dork' },
        { t: 'GitHub code & gists', u: gsearch(`"${v}" (site:github.com OR site:gist.github.com)`), d: 'Google dork' },
        { t: 'Paste sites (broad)', u: gsearch(`"${v}" (site:pastebin.com OR site:paste.ee OR site:justpaste.it OR site:rentry.co OR site:controlc.com)`), d: 'Google dork' },
        { t: 'Hacker forums & dumps (mentions)', u: gsearch(`"${v}" ("data breach" OR "leaked database" OR "combo list")`), d: 'Context search' },
        { t: 'GitHub code search', u: `https://github.com/search?q=${enc(`"${v}"`)}&type=code`, d: 'Requires GitHub sign-in' }
      ]), 'Dorks', true);
    }
    panel(out, 'What to do if exposed', () => h('ul', { class: 'note', style: 'margin:0;padding-left:18px' },
      ['Change the password on the affected service and anywhere it was reused.', 'Use a password manager to give every account a unique password.', 'Enable multi-factor authentication (an authenticator app or a security key).', 'Watch for phishing that references the breached service.'].map(t => h('li', { text: t }))), 'Defensive', true);
  }

  /* =====================================================================
     Tool registry
     ===================================================================== */
  const ICONS = {
    user: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-8 8-8s8 3.6 8 8"/></svg>',
    globe: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.2 3 14.8 0 18M12 3c-3 3.2-3 14.8 0 18"/></svg>',
    domain: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/></svg>',
    phone: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="2" width="10" height="20" rx="2.5"/><path d="M11 18h2"/></svg>',
    cube: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2l9 5v10l-9 5-9-5V7z"/><path d="M12 12l9-5M12 12L3 7M12 12v10"/></svg>',
    mail: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg>',
    shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.4 8.2-8 9-4.6-.8-8-4-8-9V6z"/><path d="M12 8v5M12 16h.01"/></svg>'
  };

  const TOOLS = [
    { id: 'username', title: 'Username Analysis', icon: 'user', blurb: 'Find where a handle is registered across developer, social and gaming platforms.',
      desc: 'Checks live public APIs for matching accounts, then gives you verification links and search pivots for everything else.',
      placeholder: 'e.g. torvalds', hint: 'Letters, numbers, dots, dashes and underscores.', examples: ['torvalds', 'gvanrossum'], run: runUsername },
    { id: 'ip', title: 'IP/DNS Analysis', icon: 'globe', blurb: 'Geolocation, ASN, reverse DNS and full DNS records for an IP or hostname.',
      desc: 'Enter an IPv4/IPv6 address or a hostname. Hostnames are resolved first, then the first address is analyzed.',
      placeholder: 'e.g. 1.1.1.1 or example.com', hint: 'IPv4, IPv6, hostname or domain.', examples: ['1.1.1.1', '8.8.8.8', 'github.com'], run: runIPDNS },
    { id: 'domain', title: 'Domain Analysis', icon: 'domain', blurb: 'WHOIS/RDAP, DNS, email security, subdomains, scans and web archive.',
      desc: 'Profiles a domain from registration data, certificate transparency logs, DNS and public scan history.',
      placeholder: 'e.g. example.com', hint: 'You can paste a full URL — the host is extracted.', examples: ['example.com', 'wikipedia.org'], run: runDomain },
    { id: 'phone', title: 'Phone Number Analysis', icon: 'phone', learn: true, blurb: 'Validate, normalize and pivot on a phone number.',
      desc: 'Parses any phone number offline, identifies region and line type, and builds search variations and caller-ID pivots.',
      placeholder: 'e.g. +1 415 555 2671', hint: 'Use international format (+ and country code) or pick a default country.', examples: ['+14155552671', '+442071838750'], extra: 'region', run: runPhone, after: PHONE_LEARN },
    { id: 'minecraft', title: 'Minecraft Account Analysis', icon: 'cube', blurb: 'Resolve a Java username or UUID to its profile, skin and public footprint.',
      desc: 'Looks up the Mojang profile, shows skin renders and links to NameMC, LABY.net and public mention searches.',
      placeholder: 'e.g. Notch or a UUID', hint: 'Java Edition usernames: 3–16 characters. UUIDs also accepted.', examples: ['Notch', 'jeb_'], run: runMinecraft },
    { id: 'email', title: 'Email Analysis', icon: 'mail', blurb: 'Inspect address type, mail setup, Gravatar and known breach exposure.',
      desc: 'Analyzes an email address using DNS, Gravatar and the free XposedOrNot breach database.',
      placeholder: 'e.g. name@example.com', hint: 'The address is only sent to the services named in each result card.', examples: [], run: runEmail },
    { id: 'breach', title: 'Username Analysis in Public Data Breaches', icon: 'shield', blurb: 'Check whether an identity shows up in public leaks and pastes.',
      desc: 'Email addresses get a direct breach lookup. Usernames get leak-index and paste-site search pivots.',
      placeholder: 'e.g. username or name@example.com', hint: 'Emails use XposedOrNot; usernames use public leak indexes and dorks.', examples: [], run: runBreaches }
  ];
  const toolById = id => TOOLS.find(t => t.id === id);

  /* =====================================================================
     Navigation & views
     ===================================================================== */
  const screens = { intro: $('#intro'), menu: $('#menu'), tool: $('#tool') };
  let current = 'intro';

  function show(name) {
    current = name;
    Object.entries(screens).forEach(([k, el]) => {
      const on = k === name;
      el.classList.toggle('active', on);
      if (on) el.removeAttribute('inert'); else el.setAttribute('inert', '');
      el.setAttribute('aria-hidden', on ? 'false' : 'true');
    });
  }

  let routed = '';
  function route(hash) {
    hash = hash || '';
    if (hash === routed) return;
    routed = hash;
    const p = new URLSearchParams(hash.replace(/^#/, ''));
    if (hash === '#menu') { show('menu'); }
    else if (p.get('tool') && toolById(p.get('tool'))) { renderTool(toolById(p.get('tool')), p.get('v') || ''); show('tool'); }
    else show('intro');
  }

  function go(hash) {
    hash = hash || '';
    if (location.hash !== hash) {
      // The History API can throw on file:// pages; fall back to the hash, then to plain in-memory routing.
      try { history.pushState(null, '', hash || (location.pathname + location.search)); }
      catch { try { location.hash = hash; } catch { /* ignore */ } }
    }
    route(hash);
    const sc = $('.screen.active .screen-scroll'); if (sc) sc.scrollTo({ top: 0, behavior: 'auto' });
  }
  window.addEventListener('popstate', () => route(location.hash));
  window.addEventListener('hashchange', () => route(location.hash));

  function pivot(id, value) { go(`#tool=${id}&v=${enc(value)}`); }

  /* ----- Intro ----- */
  (function buildLogo() {
    const box = $('.letters');
    [...'osintnow'].forEach((c, i) => box.append(h('span', { class: 'ch', style: `animation-delay:${.25 + i * .07}s`, text: c })));
    box.append(h('span', { class: 'ch dot', style: `animation-delay:${.25 + 8 * .07}s`, text: '.' }));
  })();

  $('#launch').addEventListener('click', () => go('#menu'));
  $('#brand-home').addEventListener('click', () => go(''));

  /* ----- Menu ----- */
  const grid = $('#menu-grid');
  TOOLS.forEach((t, i) => {
    const b = h('button', { class: 'card-btn', type: 'button', role: 'listitem', style: `--i:${i}`, 'aria-label': t.title, onclick: () => go(`#tool=${t.id}`) },
      h('span', { class: 'card-ico', 'aria-hidden': 'true' }),
      h('h3', { text: t.title }), h('p', { text: t.blurb }),
      h('span', { class: 'card-foot' }, h('span', { class: t.learn ? 'learn' : '', text: t.learn ? 'Learn more inside' : 'Open module' }), h('span', { class: 'arrow', 'aria-hidden': 'true', text: '→' })));
    b.querySelector('.card-ico').innerHTML = ICONS[t.icon]; // static, trusted markup
    b.addEventListener('pointermove', e => { const r = b.getBoundingClientRect(); b.style.setProperty('--mx', `${e.clientX - r.left}px`); b.style.setProperty('--my', `${e.clientY - r.top}px`); });
    grid.append(b);
  });

  /* ----- Tool view ----- */
  const toolRoot = $('#tool-root');
  let runId = 0;

  function renderTool(tool, preset) {
    runId++;
    const ico = h('div', { class: 'tool-ico', 'aria-hidden': 'true' });
    ico.innerHTML = ICONS[tool.icon]; // static, trusted markup

    const input = h('input', { type: 'text', id: 'q', name: 'q', placeholder: tool.placeholder, autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', 'aria-label': tool.title + ' input', required: true });
    input.value = preset || '';
    let select = null;
    if (tool.extra === 'region') {
      select = h('select', { 'aria-label': 'Default country', title: 'Default country (used when the number has no + prefix)' }, h('option', { value: '', text: 'Default country: auto' }));
      const lib = window.libphonenumber;
      if (lib && lib.getCountries) {
        lib.getCountries().map(c => ({ c, n: regionName(c) })).sort((a, b) => a.n.localeCompare(b.n)).forEach(({ c, n }) => select.append(h('option', { value: c, text: `${flag(c)} ${n} (+${lib.getCountryCallingCode(c)})` })));
      }
    }
    const btn = h('button', { class: 'btn btn-primary', type: 'submit' }, 'Analyze');
    const results = h('div', { class: 'results', 'aria-live': 'polite' });
    const resWrap = h('div', {});

    const form = h('form', { class: 'form', novalidate: true }, input, select, btn);
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const value = input.value.trim();
      if (!value) { input.focus(); return; }
      const my = ++runId;
      const out = h('div', { class: 'results', 'aria-live': 'polite' });
      const copy = h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: async () => {
        try { await navigator.clipboard.writeText(`${tool.title}: ${value}\n\n${out.innerText}`); copy.textContent = 'Copied ✓'; } catch { copy.textContent = 'Copy failed'; }
        setTimeout(() => { copy.textContent = 'Copy results'; }, 1800);
      } }, 'Copy results');
      resWrap.replaceChildren(h('div', { class: 'results-bar' }, h('span', { text: `Results · ${value.slice(0, 60)}` }), copy), out);
      btn.disabled = true; btn.replaceChildren(h('span', { class: 'spin' }), 'Analyzing');
      resWrap.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
      try {
        await tool.run(value, out, { extra: select ? select.value : '', pivot });
        await Promise.allSettled(out._p || []);
      } catch (err) {
        out.append(h('article', { class: 'card wide' }, h('header', { class: 'card-h' }, h('h3', { text: 'Input problem' })), h('div', { class: 'body' }, h('p', { class: 'err', text: `⚠ ${err.message || 'Something went wrong.'}` }))));
      } finally {
        if (my === runId) { btn.disabled = false; btn.textContent = 'Analyze'; }
      }
    });

    const examples = tool.examples && tool.examples.length
      ? h('div', { class: 'examples' }, 'Try:', tool.examples.map(x => h('button', { type: 'button', text: x, onclick: () => { input.value = x; form.requestSubmit(); } })))
      : null;

    toolRoot.replaceChildren(...[
      h('div', { class: 'tool-top' }, h('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: () => go('#menu') }, '← All modules')),
      h('div', { class: 'tool-head' }, ico, h('div', {}, h('h2', { text: tool.title }), h('p', { text: tool.desc }))),
      form, h('p', { class: 'hint', text: tool.hint }), examples,
      tool.after ? tool.after() : null,
      resWrap].filter(Boolean));
    setTimeout(() => input.focus({ preventScroll: true }), 250);
    if (preset) setTimeout(() => form.requestSubmit(), 350);
  }

  /* ----- Settings ----- */
  const dlg = $('#settings');
  $('#open-settings').addEventListener('click', () => { $('#ipinfo-token').value = store.get('osintnow.ipinfo'); if (dlg.showModal) dlg.showModal(); });
  $('#settings-form').addEventListener('submit', e => {
    if (e.submitter && e.submitter.value === 'save') store.set('osintnow.ipinfo', $('#ipinfo-token').value.trim());
  });
  dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !dlg.open) {
      if (current === 'tool') go('#menu');
    }
  });

  /* =====================================================================
     Animated background (network of drifting nodes)
     ===================================================================== */
  (function background() {
    const cv = $('#bg'); const ctx = cv.getContext('2d');
    let w, h2, dpr, pts = [], raf = 0, mouse = { x: -999, y: -999 };
    const N = () => Math.min(80, Math.floor((w * h2) / 18000));
    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth; h2 = window.innerHeight;
      cv.width = w * dpr; cv.height = h2 * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = N();
      while (pts.length < n) pts.push({ x: Math.random() * w, y: Math.random() * h2, vx: (Math.random() - .5) * .28, vy: (Math.random() - .5) * .28, r: Math.random() * 1.4 + .6 });
      pts.length = n;
      if (reduceMotion) draw();
    }
    function draw() {
      ctx.clearRect(0, 0, w, h2);
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i];
        if (!reduceMotion) {
          a.x += a.vx; a.y += a.vy;
          if (a.x < -20) a.x = w + 20; else if (a.x > w + 20) a.x = -20;
          if (a.y < -20) a.y = h2 + 20; else if (a.y > h2 + 20) a.y = -20;
        }
        ctx.fillStyle = 'rgba(255,255,255,.55)';
        ctx.beginPath(); ctx.arc(a.x, a.y, a.r, 0, 6.2832); ctx.fill();
        for (let j = i + 1; j < pts.length; j++) {
          const b = pts[j]; const dx = a.x - b.x, dy = a.y - b.y; const d = dx * dx + dy * dy;
          if (d < 19600) { ctx.strokeStyle = `rgba(255,255,255,${(1 - d / 19600) * .16})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
        }
        const mx = a.x - mouse.x, my = a.y - mouse.y, md = mx * mx + my * my;
        if (md < 22500) { ctx.strokeStyle = `rgba(255,255,255,${(1 - md / 22500) * .35})`; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(mouse.x, mouse.y); ctx.stroke(); }
      }
    }
    function loop() { draw(); raf = requestAnimationFrame(loop); }
    window.addEventListener('resize', resize);
    window.addEventListener('pointermove', e => { mouse.x = e.clientX; mouse.y = e.clientY; }, { passive: true });
    window.addEventListener('pointerleave', () => { mouse.x = mouse.y = -999; });
    document.addEventListener('visibilitychange', () => { if (reduceMotion) return; if (document.hidden) cancelAnimationFrame(raf); else raf = requestAnimationFrame(loop); });
    resize();
    if (!reduceMotion) raf = requestAnimationFrame(loop);
  })();

  /* ----- Boot: always start on the intro screen ----- */
  show('intro');
})();
