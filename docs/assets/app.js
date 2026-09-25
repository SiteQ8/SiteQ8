/* 3li.info · Ali AlEnezi — portfolio app. Vanilla JS, no build step, works from file:// too. */
(function () {
  'use strict';
  const D = window.SITE_DATA;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isFile = location.protocol === 'file:';

  const state = {
    lang: document.documentElement.lang === 'ar' ? 'ar' : 'en',
    theme: document.documentElement.getAttribute('data-theme') || 'dark',
    q: '', cat: 'all', tag: null, sort: 'featured', view: 'grid', mode: 'curated', langFilter: 'all',
    gh: null, ghStatus: 'loading', ghPromise: null
  };

  /* ---------- helpers ---------- */
  const t = (k, vars) => {
    let s = (D.i18n[state.lang] || {})[k];
    if (s == null) s = D.i18n.en[k] != null ? D.i18n.en[k] : k;
    if (vars) Object.keys(vars).forEach(v => { s = s.split('{' + v + '}').join(vars[v]); });
    return s;
  };
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmt = n => (n == null ? '—' : Number(n).toLocaleString('en-US'));
  const store = (k, v) => { try { localStorage.setItem('3li.' + k, JSON.stringify(v)); } catch (e) { } };
  const load = k => { try { const v = localStorage.getItem('3li.' + k); return v ? JSON.parse(v) : null; } catch (e) { return null; } };
  const domainOf = id => D.domains.find(d => d.id === id);
  const dLabel = (id, short) => { const d = domainOf(id); if (!d) return id; return short ? d.short[state.lang] : d[state.lang]; };
  const pbCat = id => D.playbookCats.find(c => c.id === id);
  const published = D.playbooks.filter(p => p.status === 'published');
  const repoName = p => p.repo ? p.repo.split('/')[1] : null;
  const projectUrl = p => p.live || (p.repo ? 'https://github.com/' + p.repo : D.profile.github);

  function timeAgo(iso) {
    const d = new Date(iso); const s = Math.max(1, Math.round((Date.now() - d.getTime()) / 1000));
    const ar = state.lang === 'ar';
    const units = [[31536000, 'year', 'سنة'], [2592000, 'month', 'شهر'], [604800, 'week', 'أسبوع'], [86400, 'day', 'يوم'], [3600, 'hour', 'ساعة'], [60, 'minute', 'دقيقة']];
    for (const [sec, en, arU] of units) {
      if (s >= sec) { const n = Math.floor(s / sec); return ar ? ('قبل ' + n + ' ' + arU) : (n + ' ' + en + (n > 1 ? 's' : '') + ' ago'); }
    }
    return ar ? 'الآن' : 'just now';
  }

  let toastTimer;
  function toast(msg) {
    const el = $('#toast'); el.textContent = msg; el.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove('show'), 1800);
  }
  function copy(text, msg) {
    const done = () => toast(msg || t('toast.copied'));
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.top = '-1000px';
    document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) { } ta.remove(); done();
  }
  function openExternal(url) { window.open(url, '_blank', 'noopener'); }

  /* ---------- theme ---------- */
  function applyTheme(theme, announce) {
    state.theme = theme; document.documentElement.setAttribute('data-theme', theme); store('theme', theme);
    try { localStorage.setItem('theme', theme); } catch (e) { }
    $('#meta-theme').setAttribute('content', theme === 'dark' ? '#0a0e17' : '#f5f7fb');
    $('#btn-theme').innerHTML = theme === 'dark'
      ? '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>'
      : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
    if (announce) toast(t('toast.theme.' + theme));
    bg.recolor(); renderCharts();
  }

  /* ---------- language ---------- */
  function applyLang(lang, announce) {
    state.lang = lang === 'ar' ? 'ar' : 'en';
    document.documentElement.lang = state.lang; document.documentElement.dir = state.lang === 'ar' ? 'rtl' : 'ltr';
    try { localStorage.setItem('lang', state.lang); } catch (e) { }
    $$('[data-i18n]').forEach(el => { el.textContent = t(el.getAttribute('data-i18n')); });
    $$('[data-i18n-html]').forEach(el => { el.innerHTML = t(el.getAttribute('data-i18n-html')); });
    $$('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.getAttribute('data-i18n-placeholder')); });
    $$('[data-i18n-title]').forEach(el => { el.title = t(el.getAttribute('data-i18n-title')); });
    document.title = state.lang === 'ar' ? 'علي العنزي · 3li.info · خبير أمن سيبراني، الكويت' : 'Ali AlEnezi · 3li.info · Cybersecurity Expert, Kuwait';
    renderSortOptions(); renderStats(); renderFilters(); renderQuickTags(); renderGrid(); renderCharts(); renderPlaybooks(); renderFocus(); renderSkills(); updateLiveLine();
    typer.restart();
    if (announce) toast(t('toast.lang'));
  }

  /* ---------- typewriter ---------- */
  const typer = (() => {
    let token = 0;
    function run() {
      const el = $('#typer'); const phrases = D.typer[state.lang]; const my = ++token;
      if (reduced) { el.textContent = phrases[0]; return; }
      let i = 0;
      const sleep = ms => new Promise(r => setTimeout(r, ms));
      (async () => {
        while (my === token) {
          const p = phrases[i % phrases.length];
          for (let c = 1; c <= p.length && my === token; c++) { el.textContent = p.slice(0, c); await sleep(28); }
          await sleep(2000);
          for (let c = p.length; c >= 0 && my === token; c--) { el.textContent = p.slice(0, c); await sleep(12); }
          await sleep(300); i++;
        }
      })();
    }
    return { restart: run };
  })();

  /* ---------- background network ---------- */
  const bg = (() => {
    const canvas = $('#bgnet'); const ctx = canvas.getContext('2d');
    let w, h, nodes = [], raf, color = '74,158,255', mouse = { x: -1e4, y: -1e4 }, running = false;
    function recolor() {
      const c = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
      const m = /^#([0-9a-f]{6})$/i.exec(c);
      if (m) { const n = parseInt(m[1], 16); color = [(n >> 16) & 255, (n >> 8) & 255, n & 255].join(','); }
    }
    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = window.innerWidth; h = Math.min(window.innerHeight, 900);
      canvas.width = w * dpr; canvas.height = h * dpr; canvas.style.height = h + 'px'; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = w < 640 ? 28 : w < 1100 ? 48 : 70;
      nodes = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - .5) * .25, vy: (Math.random() - .5) * .25, r: 1 + Math.random() * 1.6 }));
      if (reduced) draw();
    }
    function draw() {
      ctx.clearRect(0, 0, w, h);
      const fade = y => Math.max(0, 1 - y / h);
      for (let i = 0; i < nodes.length; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < nodes.length; j++) {
          const b = nodes[j]; const dx = a.x - b.x, dy = a.y - b.y; const d2 = dx * dx + dy * dy;
          if (d2 < 130 * 130) { const al = (1 - Math.sqrt(d2) / 130) * .35 * fade((a.y + b.y) / 2); ctx.strokeStyle = 'rgba(' + color + ',' + al.toFixed(3) + ')'; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); }
        }
      }
      for (const n of nodes) {
        const dx = n.x - mouse.x, dy = n.y - mouse.y; const d2 = dx * dx + dy * dy;
        const glow = d2 < 160 * 160 ? 1 - Math.sqrt(d2) / 160 : 0;
        ctx.fillStyle = 'rgba(' + color + ',' + (0.35 + glow * .6) * fade(n.y) + ')';
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r + glow * 1.5, 0, Math.PI * 2); ctx.fill();
      }
    }
    function step() {
      if (!running) return;
      for (const n of nodes) {
        n.x += n.vx; n.y += n.vy;
        const dx = mouse.x - n.x, dy = mouse.y - n.y; const d2 = dx * dx + dy * dy;
        if (d2 < 200 * 200 && d2 > 1) { n.vx += dx / d2 * .6; n.vy += dy / d2 * .6; }
        n.vx *= .995; n.vy *= .995;
        if (n.x < -20) n.x = w + 20; if (n.x > w + 20) n.x = -20; if (n.y < -20) n.y = h + 20; if (n.y > h + 20) n.y = -20;
      }
      draw(); raf = requestAnimationFrame(step);
    }
    function start() { if (reduced || running) return; running = true; raf = requestAnimationFrame(step); }
    function stop() { running = false; cancelAnimationFrame(raf); }
    window.addEventListener('resize', resize, { passive: true });
    window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; }, { passive: true });
    window.addEventListener('mouseleave', () => { mouse.x = -1e4; mouse.y = -1e4; });
    document.addEventListener('visibilitychange', () => { document.hidden ? stop() : start(); });
    recolor(); resize(); start();
    return { recolor };
  })();

  /* ---------- scroll chrome ---------- */
  (function scrollChrome() {
    const bar = $('#progress'), totop = $('#totop'), links = $$('#navlinks a');
    function onScroll() {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.width = (max > 0 ? (window.scrollY / max) * 100 : 0) + '%';
      totop.classList.toggle('show', window.scrollY > 600);
    }
    window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
    totop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: reduced ? 'auto' : 'smooth' }));
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(entries => entries.forEach(en => { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } }), { rootMargin: '0px 0px -8% 0px' });
      $$('.reveal').forEach(el => io.observe(el));
      const secs = ['work', 'numbers', 'playbooks', 'expertise', 'about'].map(id => document.getElementById(id));
      const nav = new IntersectionObserver(entries => {
        entries.forEach(en => { if (en.isIntersecting) links.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + en.target.id)); });
      }, { rootMargin: '-40% 0px -55% 0px' });
      secs.forEach(s => s && nav.observe(s));
    } else { $$('.reveal').forEach(el => el.classList.add('in')); }
    const menu = $('#mobile-menu'), burger = $('#btn-menu');
    burger.addEventListener('click', () => { const open = !menu.classList.contains('open'); menu.classList.toggle('open', open); burger.setAttribute('aria-expanded', String(open)); });
    menu.addEventListener('click', e => { if (e.target.tagName === 'A') { menu.classList.remove('open'); burger.setAttribute('aria-expanded', 'false'); } });
  })();

  /* ---------- stats ---------- */
  let statsAnimated = false;
  function statValues() {
    const gh = state.gh; const u = gh && gh.user;
    const langsLive = gh ? new Set(gh.repos.filter(r => !r.fork && r.language).map(r => r.language)).size : null;
    const langsStatic = new Set(D.projects.map(p => p.tags[0]).filter(x => /^(Python|Bash|JavaScript|TypeScript|HTML|Node\.js|PowerShell)$/.test(x))).size;
    return [
      { k: 'repos', v: u ? u.public_repos : D.profile.fallback.public_repos, live: !!u },
      { k: 'tools', v: D.projects.length },
      { k: 'domains', v: D.domains.length },
      { k: 'playbooks', v: published.length },
      { k: 'followers', v: u ? u.followers : D.profile.fallback.followers, live: !!u },
      { k: 'langs', v: langsLive != null ? langsLive : langsStatic, live: langsLive != null },
      { k: 'frameworks', v: D.skills[3].items.length, suffix: '+' },
      { k: 'bilingual', text: 'AR · EN', label: state.lang === 'ar' ? 'ثنائي اللغة، بتركيز خليجي' : 'bilingual, Gulf focused' }
    ];
  }
  function renderStats() {
    const host = $('#stats');
    host.innerHTML = statValues().map(s => '<div class="stat' + (s.live ? ' live' : '') + '"><div class="snum" data-n="' + (s.text ? '' : s.v) + '" data-suffix="' + (s.suffix || '') + '">' + (s.text ? esc(s.text) : (statsAnimated || reduced ? fmt(s.v) + (s.suffix || '') : '0')) + '</div><div class="slbl">' + esc(s.label || t('stat.' + s.k)) + '</div></div>').join('');
    if (statsAnimated || reduced) return;
    const io = new IntersectionObserver(en => { if (en[0].isIntersecting) { io.disconnect(); animateStats(); } }, { threshold: .3 });
    io.observe(host);
  }
  function animateStats() {
    statsAnimated = true;
    $$('#stats .snum').forEach(el => {
      const target = Number(el.getAttribute('data-n')); if (!el.getAttribute('data-n')) return;
      const suffix = el.getAttribute('data-suffix') || ''; const t0 = performance.now(); const dur = 900;
      (function tick(now) { const p = Math.min(1, (now - t0) / dur); const e = 1 - Math.pow(1 - p, 3); el.textContent = fmt(Math.round(target * e)) + suffix; if (p < 1) requestAnimationFrame(tick); })(t0);
    });
  }

  /* ---------- GitHub live data ---------- */
  const GH_API = 'https://api.github.com';
  async function ghFetch(path) {
    const r = await fetch(GH_API + path, { headers: { Accept: 'application/vnd.github+json' } });
    if (!r.ok) throw new Error('GitHub ' + r.status);
    return r.json();
  }
  const minRepo = r => ({ name: r.name, description: r.description, url: r.html_url, homepage: r.homepage, stars: r.stargazers_count, forks: r.forks_count, language: r.language, pushed: r.pushed_at, topics: (r.topics || []).slice(0, 6), fork: !!r.fork, archived: !!r.archived });
  function loadGitHub(force) {
    if (state.ghPromise && !force) return state.ghPromise;
    state.ghPromise = (async () => {
      const cached = load('gh.v1');
      if (cached && !force && Date.now() - cached.at < 30 * 60 * 1000) { state.gh = cached; state.gh.fromCache = true; state.ghStatus = 'ok'; onGitHub(); return state.gh; }
      try {
        const user = await ghFetch('/users/' + D.profile.handle);
        let repos = [];
        for (let page = 1; page <= 5; page++) {
          const chunk = await ghFetch('/users/' + D.profile.handle + '/repos?per_page=100&sort=pushed&page=' + page);
          repos = repos.concat(chunk.map(minRepo)); if (chunk.length < 100) break;
        }
        let events = [];
        try { events = (await ghFetch('/users/' + D.profile.handle + '/events/public?per_page=100')).filter(e => e.type === 'PushEvent').map(e => ({ repo: e.repo.name, at: e.created_at, n: (e.payload && e.payload.size) || 1 })); } catch (e) { }
        state.gh = { at: Date.now(), user: { public_repos: user.public_repos, followers: user.followers, following: user.following, avatar: user.avatar_url, name: user.name, bio: user.bio }, repos, events };
        store('gh.v1', state.gh); state.ghStatus = 'ok'; onGitHub(); return state.gh;
      } catch (e) {
        if (cached) { state.gh = cached; state.gh.fromCache = true; state.ghStatus = 'ok'; onGitHub(); return state.gh; }
        state.ghStatus = 'static'; updateLiveLine(); return null;
      }
    })();
    return state.ghPromise;
  }
  function repoByName(name) { if (!state.gh || !name) return null; const n = name.toLowerCase(); return state.gh.repos.find(r => r.name.toLowerCase() === n) || null; }
  function onGitHub() { updateLiveLine(); renderStats(); renderSortOptions(); renderGrid(); renderCharts(); }
  function updateLiveLine() {
    const el = $('#hero-live'), txt = $('#hero-live-text'); el.classList.remove('ok', 'static');
    if (state.ghStatus === 'ok' && state.gh) {
      el.classList.add('ok');
      const stars = state.gh.repos.filter(r => !r.fork).reduce((a, r) => a + (r.stars || 0), 0);
      txt.textContent = t(state.gh.fromCache ? 'live.cached' : 'live.ok', { t: timeAgo(new Date(state.gh.at).toISOString()) }) + ' · ' + fmt(stars) + ' ★';
    } else if (state.ghStatus === 'static') { el.classList.add('static'); txt.textContent = t('live.static'); }
    else txt.textContent = t('live.loading');
  }

  /* ---------- work explorer ---------- */
  function renderSortOptions() {
    const sel = $('#sort'); const live = !!state.gh;
    sel.innerHTML = [['featured', 'work.sort.featured'], ['name', 'work.sort.name'], ['updated', 'work.sort.updated'], ['stars', 'work.sort.stars']]
      .map(([v, k]) => '<option value="' + v + '"' + (v === state.sort ? ' selected' : '') + ((v === 'updated' || v === 'stars') && !live ? ' disabled' : '') + '>' + esc(t(k)) + '</option>').join('');
  }
  function renderFilters() {
    const host = $('#filters');
    if (state.mode === 'all' && state.gh) {
      const counts = {}; allRepos().forEach(r => { const l = r.language || 'Other'; counts[l] = (counts[l] || 0) + 1; });
      const langs = Object.keys(counts).sort((a, b) => counts[b] - counts[a]).slice(0, 9);
      host.innerHTML = '<button type="button" class="fpill" data-lang="all" aria-pressed="' + (state.langFilter === 'all') + '">' + esc(t('filter.all')) + ' <span class="count">' + allRepos().length + '</span></button>'
        + langs.map(l => '<button type="button" class="fpill" data-lang="' + esc(l) + '" aria-pressed="' + (state.langFilter === l) + '">' + esc(l) + ' <span class="count">' + counts[l] + '</span></button>').join('');
      $$('button', host).forEach(b => b.addEventListener('click', () => { state.langFilter = b.getAttribute('data-lang'); renderFilters(); renderGrid(); }));
      return;
    }
    const counts = {}; D.projects.forEach(p => { counts[p.cat] = (counts[p.cat] || 0) + 1; });
    host.innerHTML = '<button type="button" class="fpill" data-cat="all" aria-pressed="' + (state.cat === 'all') + '">' + esc(t('filter.all')) + ' <span class="count">' + D.projects.length + '</span></button>'
      + D.domains.map(d => '<button type="button" class="fpill" data-cat="' + d.id + '" aria-pressed="' + (state.cat === d.id) + '" style="--c:var(--c-' + d.id + ')"><span class="sw" aria-hidden="true"></span>' + esc(d[state.lang]) + ' <span class="count">' + (counts[d.id] || 0) + '</span></button>').join('');
    $$('button', host).forEach(b => b.addEventListener('click', () => { setCat(b.getAttribute('data-cat')); }));
  }
  function setCat(cat) { state.cat = cat; renderFilters(); renderGrid(); }
  function renderQuickTags() {
    const host = $('#quicktags');
    if (state.mode === 'all') { host.innerHTML = ''; return; }
    host.innerHTML = '<span class="lbl">tags</span>' + D.quickTags.map(tag => '<button type="button" class="tagbtn" data-tag="' + esc(tag) + '" aria-pressed="' + (state.tag === tag) + '">' + esc(tag) + '</button>').join('');
    $$('button', host).forEach(b => b.addEventListener('click', () => { const tag = b.getAttribute('data-tag'); state.tag = state.tag === tag ? null : tag; renderQuickTags(); renderGrid(); }));
  }
  function allRepos() { return state.gh ? state.gh.repos.filter(r => !r.fork) : []; }
  function matches(p, q) {
    if (!q) return true; const hay = [p.name, p.ar, p.desc, (p.tags || []).join(' '), p.repo || '', dLabel(p.cat), dLabel(p.cat, true), p.id].join(' ').toLowerCase();
    return q.split(/\s+/).filter(Boolean).every(w => hay.includes(w));
  }
  function curatedList() {
    const q = state.q.trim().toLowerCase();
    let list = D.projects.filter(p => (state.cat === 'all' || p.cat === state.cat) && (!state.tag || p.tags.some(x => x.toLowerCase() === state.tag.toLowerCase())) && matches(p, q));
    const live = p => repoByName(repoName(p));
    if (state.sort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
    else if (state.sort === 'updated' && state.gh) list.sort((a, b) => ((live(b) || {}).pushed || '').localeCompare((live(a) || {}).pushed || ''));
    else if (state.sort === 'stars' && state.gh) list.sort((a, b) => ((live(b) || {}).stars || 0) - ((live(a) || {}).stars || 0));
    else list.sort((a, b) => (b.featured ? 1 : 0) - (a.featured ? 1 : 0));
    return list;
  }
  function repoList() {
    const q = state.q.trim().toLowerCase();
    let list = allRepos().filter(r => (state.langFilter === 'all' || (r.language || 'Other') === state.langFilter) && (!q || q.split(/\s+/).filter(Boolean).every(w => [r.name, r.description || '', r.language || '', r.topics.join(' ')].join(' ').toLowerCase().includes(w))));
    if (state.sort === 'name') list.sort((a, b) => a.name.localeCompare(b.name));
    else if (state.sort === 'stars') list.sort((a, b) => (b.stars || 0) - (a.stars || 0));
    else if (state.sort === 'featured') { const cur = new Set(D.projects.map(p => (repoName(p) || '').toLowerCase())); list.sort((a, b) => (cur.has(b.name.toLowerCase()) ? 1 : 0) - (cur.has(a.name.toLowerCase()) ? 1 : 0) || (b.pushed || '').localeCompare(a.pushed || '')); }
    else list.sort((a, b) => (b.pushed || '').localeCompare(a.pushed || ''));
    return list;
  }
  const starSvg = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 .25a.75.75 0 0 1 .67.42l1.88 3.8 4.2.61a.75.75 0 0 1 .42 1.28l-3.04 2.96.72 4.18a.75.75 0 0 1-1.09.79L8 12.35l-3.76 1.98a.75.75 0 0 1-1.09-.79l.72-4.18L.83 6.36a.75.75 0 0 1 .42-1.28l4.2-.61L7.33.67A.75.75 0 0 1 8 .25z"/></svg>';
  const forkSvg = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M5 5.37v.88c0 .34.28.62.62.62h4.76c.34 0 .62-.28.62-.62v-.88a2.25 2.25 0 1 1 1.5 0v.88A2.12 2.12 0 0 1 10.38 8.37H8.75v2.26a2.25 2.25 0 1 1-1.5 0V8.37H5.62A2.12 2.12 0 0 1 3.5 6.25v-.88a2.25 2.25 0 1 1 1.5 0z"/></svg>';
  function metaHtml(r) {
    if (!r) return '';
    return '<div class="meta">' + (r.language ? '<span><i class="lang-dot"></i>' + esc(r.language) + '</span>' : '') + '<span>' + starSvg + fmt(r.stars) + '</span>' + (r.pushed ? '<span title="' + esc(r.pushed) + '">' + esc(t('card.updated', { t: timeAgo(r.pushed) })) + '</span>' : '') + '</div>';
  }
  function cardCurated(p) {
    const r = repoByName(repoName(p));
    return '<article class="proj" data-cat="' + p.cat + '" data-id="' + p.id + '">'
      + '<div class="proj-top"><span><span class="cat">' + esc(dLabel(p.cat, true)) + '</span>' + (p.featured ? '<span class="featured-star" title="Featured">★</span>' : '') + '</span>'
      + '<a class="abtn" href="' + esc(projectUrl(p)) + '" target="_blank" rel="noopener" aria-label="' + esc(p.name) + '">' + (p.live ? '↗' : '') + (p.live ? esc(t('card.live')) : esc(t('card.repo'))) + '</a></div>'
      + '<h3 class="proj-name"><button type="button" class="proj-open" data-id="' + p.id + '">' + esc(p.name) + '</button>' + (p.ar ? '<span class="ar">' + esc(p.ar) + '</span>' : '') + '</h3>'
      + '<p class="proj-desc">' + esc(p.desc) + '</p>'
      + '<div class="tags">' + p.tags.map(x => '<button type="button" class="tag" data-tag="' + esc(x) + '">' + esc(x) + '</button>').join('') + '</div>'
      + '<div class="proj-foot">' + (metaHtml(r) || '<span class="meta"><span>' + esc(D.profile.handle) + (p.repo ? '/' + esc(repoName(p)) : '') + '</span></span>') + '<div class="proj-actions"><button type="button" class="abtn primary proj-open" data-id="' + p.id + '">' + esc(t('card.details')) + '</button></div></div>'
      + '</article>';
  }
  function cardRepo(r) {
    const cur = D.projects.find(p => (repoName(p) || '').toLowerCase() === r.name.toLowerCase());
    return '<article class="proj" data-cat="' + (cur ? cur.cat : '') + '" data-repo="' + esc(r.name) + '">'
      + '<div class="proj-top"><span><span class="cat">' + esc(cur ? dLabel(cur.cat, true) : (r.language || 'repo')) + '</span>' + (cur ? '<span class="featured-star" title="Flagship">★</span>' : '') + '</span><a class="abtn" href="' + esc(r.url) + '" target="_blank" rel="noopener">' + esc(t('card.repo')) + '</a></div>'
      + '<h3 class="proj-name"><button type="button" class="repo-open" data-repo="' + esc(r.name) + '">' + esc(r.name) + '</button>' + (cur && cur.ar ? '<span class="ar">' + esc(cur.ar) + '</span>' : '') + '</h3>'
      + '<p class="proj-desc">' + esc(r.description || (cur ? cur.desc : '')) + '</p>'
      + (r.topics.length ? '<div class="tags">' + r.topics.slice(0, 5).map(x => '<span class="tag">' + esc(x) + '</span>').join('') + '</div>' : '')
      + '<div class="proj-foot">' + metaHtml(r) + '<div class="proj-actions"><button type="button" class="abtn primary repo-open" data-repo="' + esc(r.name) + '">' + esc(t('card.details')) + '</button></div></div>'
      + '</article>';
  }
  function renderGrid() {
    const grid = $('#grid'), empty = $('#empty'), note = $('#mode-note');
    const list = state.mode === 'all' ? repoList() : curatedList();
    grid.classList.toggle('list', state.view === 'list');
    grid.innerHTML = list.map(state.mode === 'all' ? cardRepo : cardCurated).join('');
    empty.hidden = list.length > 0;
    $('#results-count').textContent = list.length === 1 ? t('work.results1') : t('work.results', { n: list.length });
    note.hidden = state.mode !== 'all'; if (state.mode === 'all') note.textContent = t('work.allNote');
    $('#btn-allrepos').innerHTML = '<span>' + esc(t(state.mode === 'all' ? 'work.curated' : 'work.all')) + '</span>';
    $$('.proj-open', grid).forEach(b => b.addEventListener('click', () => openProject(b.getAttribute('data-id'))));
    $$('.repo-open', grid).forEach(b => b.addEventListener('click', () => openRepo(b.getAttribute('data-repo'))));
    $$('button.tag', grid).forEach(b => b.addEventListener('click', () => { const tag = b.getAttribute('data-tag'); state.q = ''; $('#search').value = ''; state.tag = D.quickTags.includes(tag) ? tag : null; if (!D.quickTags.includes(tag)) { state.q = tag; $('#search').value = tag; } renderQuickTags(); renderGrid(); }));
    $$('.proj', grid).forEach(card => card.addEventListener('mousemove', e => { const r = card.getBoundingClientRect(); card.style.setProperty('--mx', ((e.clientX - r.left) / r.width * 100) + '%'); }, { passive: true }));
  }
  function clearFilters() { state.q = ''; state.cat = 'all'; state.tag = null; state.langFilter = 'all'; $('#search').value = ''; renderFilters(); renderQuickTags(); renderGrid(); }
  async function toggleAllRepos() {
    const btn = $('#btn-allrepos');
    if (state.mode === 'all') { state.mode = 'curated'; state.langFilter = 'all'; renderFilters(); renderQuickTags(); renderGrid(); return; }
    btn.innerHTML = '<span>' + esc(t('work.allLoading')) + '</span>'; btn.disabled = true;
    const gh = await loadGitHub(state.ghStatus === 'static');
    btn.disabled = false;
    if (!gh) { toast(t('work.allFail')); renderGrid(); return; }
    state.mode = 'all'; if (state.sort === 'featured') state.sort = 'updated'; renderSortOptions(); renderFilters(); renderQuickTags(); renderGrid();
    document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
  }

  /* ---------- dialogs ---------- */
  let lastFocus = null;
  function openDialog(id) { lastFocus = document.activeElement; const el = $('#' + id); el.hidden = false; document.body.style.overflow = 'hidden'; }
  function closeDialog(id) { const el = $('#' + id); if (el.hidden) return; el.hidden = true; if (!$$('.overlay:not([hidden])').length) document.body.style.overflow = ''; if (lastFocus && lastFocus.focus) lastFocus.focus(); }
  function closeAll() { ['modal', 'palette', 'term'].forEach(closeDialog); if (location.hash.startsWith('#p/')) history.replaceState(null, '', location.pathname + location.search); }
  $$('.overlay').forEach(ov => ov.addEventListener('click', e => { if (e.target === ov) closeAll(); }));

  function statBox(label, val) { return '<div class="mstat"><b>' + esc(label) + '</b><span>' + val + '</span></div>'; }
  function openProject(id) {
    const p = D.projects.find(x => x.id === id); if (!p) return;
    const r = repoByName(repoName(p));
    const links = [];
    if (p.repo) links.push('<a class="btn btn-primary" href="https://github.com/' + esc(p.repo) + '" target="_blank" rel="noopener">' + esc(t('card.repo')) + ' ↗</a>');
    if (p.live) links.push('<a class="btn ' + (p.repo ? 'btn-ghost' : 'btn-primary') + '" href="' + esc(p.live) + '" target="_blank" rel="noopener">' + esc(t('card.live')) + ' ↗</a>');
    if (p.releases && p.repo) links.push('<a class="btn btn-ghost" href="https://github.com/' + esc(p.repo) + '/releases" target="_blank" rel="noopener">' + esc(t('card.releases')) + '</a>');
    links.push('<button type="button" class="btn btn-ghost" id="modal-copy">' + esc(t('modal.copy')) + '</button>');
    const similar = D.projects.filter(x => x.cat === p.cat && x.id !== p.id).slice(0, 6);
    $('#modal-card').innerHTML = '<div class="modal-head"><div><span class="cat" style="--c:var(--c-' + p.cat + ')">' + esc(dLabel(p.cat)) + '</span><h2 class="modal-title" id="modal-title" style="margin-top:10px">' + esc(p.name) + (p.ar ? '<span class="ar">' + esc(p.ar) + '</span>' : '') + '</h2></div><button type="button" class="xbtn" id="modal-close" aria-label="' + esc(t('modal.close')) + '">✕</button></div>'
      + '<p class="modal-desc">' + esc(p.desc) + '</p>'
      + '<div class="tags" style="margin-top:14px">' + p.tags.map(x => '<span class="tag">' + esc(x) + '</span>').join('') + '</div>'
      + (r ? '<div class="modal-stats">' + statBox(t('modal.stars'), fmt(r.stars)) + statBox(t('modal.forks'), fmt(r.forks)) + statBox(t('modal.lang'), esc(r.language || '—')) + statBox(t('modal.updated'), esc(timeAgo(r.pushed))) + '</div>' : '')
      + (r && r.topics.length ? '<div class="tags" style="margin-top:12px">' + r.topics.map(x => '<span class="tag">#' + esc(x) + '</span>').join('') + '</div>' : '')
      + '<div class="modal-links">' + links.join('') + '</div>'
      + (similar.length ? '<div class="similar"><h4>' + esc(t('modal.similar')) + '</h4><div class="similar-row">' + similar.map(s => '<button type="button" data-id="' + s.id + '">' + esc(s.name) + '</button>').join('') + '</div></div>' : '');
    wireModal(); history.replaceState(null, '', '#p/' + p.id); openDialog('modal'); $('#modal-close').focus();
    $('#modal-copy').addEventListener('click', () => copy(location.href.split('#')[0] + '#p/' + p.id));
  }
  function openRepo(name) {
    const r = repoByName(name); if (!r) return;
    const cur = D.projects.find(p => (repoName(p) || '').toLowerCase() === name.toLowerCase());
    if (cur) return openProject(cur.id);
    $('#modal-card').innerHTML = '<div class="modal-head"><div><span class="cat">' + esc(r.language || 'repo') + '</span><h2 class="modal-title" id="modal-title" style="margin-top:10px">' + esc(r.name) + '</h2></div><button type="button" class="xbtn" id="modal-close" aria-label="' + esc(t('modal.close')) + '">✕</button></div>'
      + '<p class="modal-desc">' + esc(r.description || '') + '</p>'
      + '<div class="modal-stats">' + statBox(t('modal.stars'), fmt(r.stars)) + statBox(t('modal.forks'), fmt(r.forks)) + statBox(t('modal.lang'), esc(r.language || '—')) + statBox(t('modal.updated'), esc(timeAgo(r.pushed))) + '</div>'
      + (r.topics.length ? '<div class="tags" style="margin-top:12px">' + r.topics.map(x => '<span class="tag">#' + esc(x) + '</span>').join('') + '</div>' : '')
      + '<div class="modal-links"><a class="btn btn-primary" href="' + esc(r.url) + '" target="_blank" rel="noopener">' + esc(t('card.repo')) + ' ↗</a>' + (r.homepage ? '<a class="btn btn-ghost" href="' + esc(r.homepage) + '" target="_blank" rel="noopener">' + esc(t('card.live')) + ' ↗</a>' : '') + '</div>';
    wireModal(); openDialog('modal'); $('#modal-close').focus();
  }
  function wireModal() {
    $('#modal-close').addEventListener('click', closeAll);
    $$('.similar-row button', $('#modal-card')).forEach(b => b.addEventListener('click', () => openProject(b.getAttribute('data-id'))));
  }

  /* ---------- charts ---------- */
  const chartMode = { domains: 'chart', langs: 'chart', activity: 'chart' };
  function chartTools(key) {
    return '<button type="button" data-mode="chart" aria-pressed="' + (chartMode[key] === 'chart') + '">' + esc(t('chart.chart')) + '</button><button type="button" data-mode="table" aria-pressed="' + (chartMode[key] === 'table') + '">' + esc(t('chart.table')) + '</button>';
  }
  function barPath(x, y, w, h, r) { r = Math.min(r, w / 2, h / 2); if (w <= 0) return ''; return 'M' + x + ',' + y + ' H' + (x + w - r) + ' A' + r + ',' + r + ' 0 0 1 ' + (x + w) + ',' + (y + r) + ' V' + (y + h - r) + ' A' + r + ',' + r + ' 0 0 1 ' + (x + w - r) + ',' + (y + h) + ' H' + x + ' Z'; }
  function vBarPath(x, y, w, h, r) { r = Math.min(r, w / 2, h / 2); if (h <= 0) return ''; return 'M' + x + ',' + (y + h) + ' V' + (y + r) + ' A' + r + ',' + r + ' 0 0 1 ' + (x + r) + ',' + y + ' H' + (x + w - r) + ' A' + r + ',' + r + ' 0 0 1 ' + (x + w) + ',' + (y + r) + ' V' + (y + h) + ' Z'; }
  function tableHtml(rows, colA, colB) { return '<table class="chart-table"><thead><tr><th>' + esc(colA) + '</th><th style="text-align:end">' + esc(colB) + '</th></tr></thead><tbody>' + rows.map(r => '<tr><td>' + esc(r.label) + '</td><td>' + fmt(r.value) + '</td></tr>').join('') + '</tbody></table>'; }
  function hBars(rows, unit, onClick) {
    const W = 400, rowH = 28, labelW = 138, pad = 10, max = Math.max(1, ...rows.map(r => r.value)); const H = rows.length * rowH + pad;
    let s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="bar chart">';
    rows.forEach((r, i) => {
      const y = pad / 2 + i * rowH, bw = Math.max(2, (r.value / max) * (W - labelW - 44)), bh = 17;
      s += '<text x="' + (labelW - 10) + '" y="' + (y + 14) + '" text-anchor="end">' + esc(r.label) + '</text>'
        + '<path class="bar' + (onClick ? ' clickable' : '') + '" data-i="' + i + '" d="' + barPath(labelW, y + 3, bw, bh, 4) + '"/>'
        + '<text class="val" x="' + (labelW + bw + 8) + '" y="' + (y + 14) + '">' + fmt(r.value) + '</text>'
        + '<rect class="hit" data-i="' + i + '" x="0" y="' + y + '" width="' + W + '" height="' + rowH + '"/>';
    });
    s += '<line class="axis" x1="' + labelW + '" y1="0" x2="' + labelW + '" y2="' + H + '"/></svg><div class="tip"></div>';
    return s;
  }
  function wireTips(body, rows, unit, onClick) {
    const tip = $('.tip', body); const bars = $$('.bar', body);
    function show(i, e) {
      const r = rows[i]; tip.innerHTML = esc(r.label) + ' · <b>' + fmt(r.value) + '</b> ' + esc(unit); tip.classList.add('show');
      const br = body.getBoundingClientRect(); tip.style.left = (e.clientX - br.left) + 'px'; tip.style.top = (e.clientY - br.top) + 'px';
      body.classList.add('dim'); bars.forEach(b => b.classList.toggle('hot', +b.getAttribute('data-i') === i));
    }
    function hide() { tip.classList.remove('show'); body.classList.remove('dim'); bars.forEach(b => b.classList.remove('hot')); }
    $$('.hit, .bar', body).forEach(el => {
      const i = +el.getAttribute('data-i');
      el.addEventListener('mousemove', e => show(i, e)); el.addEventListener('mouseleave', hide);
      if (onClick) el.addEventListener('click', () => onClick(rows[i]));
    });
  }
  function renderChart(key, rows, unit, opts) {
    const fig = $('#chart-' + key); const body = $('.chart-body', fig); const tools = $('.chart-tools', fig);
    if (!rows) { tools.innerHTML = ''; body.innerHTML = '<div class="chart-note">' + esc(t('chart.noLive')) + '</div>'; return; }
    tools.innerHTML = chartTools(key);
    $$('button', tools).forEach(b => b.addEventListener('click', () => { chartMode[key] = b.getAttribute('data-mode'); renderCharts(); }));
    if (chartMode[key] === 'table') { body.innerHTML = tableHtml(rows, opts.colA, opts.colB); return; }
    body.innerHTML = opts.vertical ? vBars(rows) : hBars(rows, unit, opts.onClick);
    wireTips(body, rows, unit, opts.onClick);
  }
  function vBars(rows) {
    const W = 400, H = 180, padL = 8, padB = 26, padT = 18, n = rows.length, gap = 5, bw = (W - padL * 2 - gap * (n - 1)) / n, max = Math.max(1, ...rows.map(r => r.value));
    const maxI = rows.reduce((m, r, i) => r.value > rows[m].value ? i : m, 0);
    let s = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="bar chart"><line class="axis" x1="' + padL + '" y1="' + (H - padB) + '" x2="' + (W - padL) + '" y2="' + (H - padB) + '"/>';
    rows.forEach((r, i) => {
      const x = padL + i * (bw + gap), bh = (r.value / max) * (H - padB - padT), y = H - padB - bh;
      s += '<path class="bar" data-i="' + i + '" d="' + vBarPath(x, y, bw, bh, 4) + '"/>';
      if (i === maxI || i === n - 1) s += '<text class="val" x="' + (x + bw / 2) + '" y="' + (y - 5) + '" text-anchor="middle">' + fmt(r.value) + '</text>';
      if (i % 3 === 0 || i === n - 1) s += '<text x="' + (x + bw / 2) + '" y="' + (H - 8) + '" text-anchor="middle" style="font-size:11px">' + esc(r.short) + '</text>';
      s += '<rect class="hit" data-i="' + i + '" x="' + x + '" y="0" width="' + (bw + gap) + '" height="' + H + '"/>';
    });
    return s + '</svg><div class="tip"></div>';
  }
  function renderCharts() {
    const counts = {}; D.projects.forEach(p => { counts[p.cat] = (counts[p.cat] || 0) + 1; });
    renderChart('domains', D.domains.map(d => ({ label: d[state.lang], value: counts[d.id] || 0, id: d.id })).sort((a, b) => b.value - a.value), t('chart.tools'),
      { colA: state.lang === 'ar' ? 'المجال' : 'Domain', colB: t('chart.tools'), onClick: r => { state.mode = 'curated'; setCat(r.id); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }); } });
    const langFig = $('#chart-langs .chart-title');
    if (state.gh) {
      langFig.textContent = t('chart.langs');
      const lc = {}; allRepos().forEach(r => { if (r.language) lc[r.language] = (lc[r.language] || 0) + 1; });
      let rows = Object.keys(lc).map(k => ({ label: k, value: lc[k] })).sort((a, b) => b.value - a.value);
      if (rows.length > 8) { const rest = rows.slice(7).reduce((a, r) => a + r.value, 0); rows = rows.slice(0, 7).concat([{ label: state.lang === 'ar' ? 'أخرى' : 'Other', value: rest }]); }
      renderChart('langs', rows, t('chart.repos'), { colA: state.lang === 'ar' ? 'اللغة' : 'Language', colB: t('chart.repos'), onClick: r => { if (r.label === 'Other' || r.label === 'أخرى') return; state.mode = 'all'; state.langFilter = r.label; renderSortOptions(); renderFilters(); renderQuickTags(); renderGrid(); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }); } });
    } else {
      langFig.textContent = t('chart.langsStatic');
      const lc = {}; D.projects.forEach(p => { const l = p.tags.find(x => /^(Python|Bash|JavaScript|TypeScript|HTML|Node\.js|PowerShell)$/.test(x)); if (l) lc[l] = (lc[l] || 0) + 1; });
      renderChart('langs', Object.keys(lc).map(k => ({ label: k, value: lc[k] })).sort((a, b) => b.value - a.value), t('chart.tools'), { colA: state.lang === 'ar' ? 'اللغة' : 'Language', colB: t('chart.tools'), onClick: r => { state.q = r.label; $('#search').value = r.label; state.mode = 'curated'; renderFilters(); renderQuickTags(); renderGrid(); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }); } });
    }
    if (state.gh && state.gh.events && state.gh.events.length) {
      const weeks = []; const now = new Date(); const day = now.getDay(); const start = new Date(now); start.setHours(0, 0, 0, 0); start.setDate(now.getDate() - day - 7 * 11);
      for (let i = 0; i < 12; i++) { const ws = new Date(start); ws.setDate(start.getDate() + i * 7); weeks.push({ ws, value: 0 }); }
      state.gh.events.forEach(e => { const d = new Date(e.at); const idx = Math.floor((d - start) / (7 * 86400000)); if (idx >= 0 && idx < 12) weeks[idx].value += 1; });
      const mon = state.lang === 'ar' ? ['ينا', 'فبر', 'مار', 'أبر', 'ماي', 'يون', 'يول', 'أغس', 'سبت', 'أكت', 'نوف', 'ديس'] : ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const rows = weeks.map(w => ({ label: t('chart.week') + ' ' + w.ws.getDate() + ' ' + mon[w.ws.getMonth()], short: w.ws.getDate() + ' ' + mon[w.ws.getMonth()], value: w.value }));
      renderChart('activity', rows, t('chart.pushes'), { vertical: true, colA: state.lang === 'ar' ? 'الأسبوع' : 'Week', colB: t('chart.pushes') });
    } else renderChart('activity', null);
  }

  /* ---------- playbooks ---------- */
  const pbState = { cat: 'all', q: '' };
  function renderPlaybooks() {
    const host = $('#pb-filters');
    host.innerHTML = '<button type="button" class="fpill" data-cat="all" aria-pressed="' + (pbState.cat === 'all') + '">' + esc(t('pb.all')) + ' <span class="count">' + published.length + '</span></button>'
      + D.playbookCats.map(c => '<button type="button" class="fpill" data-cat="' + c.id + '" aria-pressed="' + (pbState.cat === c.id) + '">' + esc(c[state.lang]) + ' <span class="count">' + published.filter(p => p.cat === c.id).length + '</span></button>').join('');
    $$('button', host).forEach(b => b.addEventListener('click', () => { pbState.cat = b.getAttribute('data-cat'); renderPlaybooks(); }));
    const q = pbState.q.trim().toLowerCase();
    const list = published.filter(p => (pbState.cat === 'all' || p.cat === pbState.cat) && (!q || [p.id, p.title, p.objective, p.mitre.join(' '), pbCat(p.cat).en, pbCat(p.cat).ar].join(' ').toLowerCase().includes(q)));
    const base = 'https://github.com/SiteQ8/SiteQ8/blob/main/playbooks/';
    $('#pb-grid').innerHTML = list.map(p => '<article class="pb"><div class="pb-head"><span class="pb-id">' + esc(p.id) + '</span><span class="sev sev-' + p.severity + '">' + (p.severity === 'critical' ? '⬤' : '▲') + ' ' + esc(t('sev.' + p.severity)) + '</span></div>'
      + '<h3 class="pb-title">' + esc(p.title) + '</h3><div class="pb-cat">' + esc(pbCat(p.cat)[state.lang]) + ' · NIST SP 800-61</div><p class="pb-obj">' + esc(p.objective) + '</p>'
      + '<div class="pb-mitre">' + p.mitre.map(m => '<a class="tech" href="https://attack.mitre.org/techniques/' + m.replace('.', '/') + '/" target="_blank" rel="noopener">' + esc(m) + '</a>').join('') + '</div>'
      + '<div class="pb-foot"><span>' + esc(t('pb.updated', { t: p.updated })) + '</span><a class="abtn primary" href="' + base + pbCat(p.cat).dir + '/' + p.file + '.md" target="_blank" rel="noopener">' + esc(t('pb.open')) + ' ↗</a></div></article>').join('');
    $('#pb-empty').hidden = list.length > 0;
    const planned = D.playbooks.filter(p => p.status === 'planned' && (pbState.cat === 'all' || p.cat === pbState.cat));
    $('#pb-planned').innerHTML = planned.length ? '<h3>' + esc(t('pb.planned')) + '</h3><div class="pb-mini-row">' + planned.map(p => '<span class="pb-mini"><b>' + esc(p.id) + '</b>' + esc(p.title) + '</span>').join('') + '<a class="pb-mini" href="https://github.com/SiteQ8/SiteQ8/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener" style="border-style:solid;color:var(--accent)">' + esc(t('pb.contribute')) + ' ↗</a></div>' : '';
  }

  /* ---------- focus & skills ---------- */
  function renderFocus() {
    $('#focusgrid').innerHTML = D.focus.map((f, i) => '<button type="button" class="focus" data-i="' + i + '"><div class="ficon" aria-hidden="true">' + f.icon + '</div><h3 class="ftitle">' + esc(f[state.lang]) + '</h3><p class="fdesc">' + esc(state.lang === 'ar' ? f.dar : f.den) + '</p><div class="ftags">' + f.tags.map(x => '<span class="ftag">' + esc(x) + '</span>').join('') + '</div><div class="fgo">' + (state.lang === 'ar' ? 'عرض الأدوات ←' : 'See the tools →') + '</div></button>').join('');
    $$('#focusgrid .focus').forEach(b => b.addEventListener('click', () => {
      const f = D.focus[+b.getAttribute('data-i')]; state.mode = 'curated'; state.tag = null;
      if (f.go.cat) { state.q = ''; $('#search').value = ''; setCat(f.go.cat); } else { state.cat = 'all'; state.q = f.go.q; $('#search').value = f.go.q; renderFilters(); renderGrid(); }
      renderQuickTags(); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' });
    }));
  }
  function renderSkills() {
    $('#skills-list').innerHTML = D.skills.map(g => '<div class="skillgroup reveal in"><div class="skilllbl">' + esc(g[state.lang]) + '</div><div class="chips">' + g.items.map(x => '<button type="button" class="chip' + (g.green ? ' chip-green' : '') + '" data-q="' + esc(x) + '">' + esc(x) + '</button>').join('') + '</div></div>').join('');
    $$('#skills-list .chip').forEach(b => b.addEventListener('click', () => { const q = b.getAttribute('data-q'); state.mode = 'curated'; state.cat = 'all'; state.tag = null; state.q = q; $('#search').value = q; renderFilters(); renderQuickTags(); renderGrid(); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }); }));
  }

  /* ---------- command palette ---------- */
  const palette = (() => {
    const ov = $('#palette'), input = $('#palette-input'), list = $('#palette-list'); let items = [], active = 0;
    const actions = () => [
      { g: 'actions', ico: '◐', name: t('act.theme'), run: () => applyTheme(state.theme === 'dark' ? 'light' : 'dark', true) },
      { g: 'actions', ico: 'ع', name: t('act.lang'), run: () => applyLang(state.lang === 'ar' ? 'en' : 'ar', true) },
      { g: 'actions', ico: '>_', name: t('act.term'), run: () => term.open() },
      { g: 'actions', ico: '@', name: t('act.copy'), sub: D.profile.email, run: () => copy(D.profile.email) },
      { g: 'actions', ico: 'gh', name: t('act.gh'), sub: 'github.com/SiteQ8', run: () => openExternal(D.profile.github) },
      { g: 'actions', ico: '🌐', name: t('act.site'), sub: '3li.info', run: () => openExternal(D.profile.site) },
      { g: 'actions', ico: 'in', name: t('act.li'), run: () => openExternal(D.profile.linkedin) },
      { g: 'actions', ico: '∞', name: t('act.all'), run: () => { if (state.mode !== 'all') toggleAllRepos(); else document.getElementById('work').scrollIntoView(); } },
      { g: 'actions', ico: '↑', name: t('act.top'), run: () => window.scrollTo({ top: 0 }) }
    ];
    const sections = () => ['work', 'numbers', 'playbooks', 'expertise', 'about'].map(id => ({ g: 'sections', ico: '#', name: t('nav.' + id), sub: '#' + id, run: () => document.getElementById(id).scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }) }));
    const projects = () => D.projects.map(p => ({ g: 'projects', ico: domainOf(p.cat).icon, name: p.name + (p.ar ? ' ' + p.ar : ''), sub: dLabel(p.cat, true), keys: p.tags.join(' ') + ' ' + p.desc, run: () => openProject(p.id) }));
    const playbooks = () => published.map(p => ({ g: 'playbooks', ico: 'PB', name: p.id + ' ' + p.title, sub: p.mitre.join(' '), keys: p.objective, run: () => openExternal('https://github.com/SiteQ8/SiteQ8/blob/main/playbooks/' + pbCat(p.cat).dir + '/' + p.file + '.md') }));
    const repos = q => (q.length >= 2 && state.gh) ? allRepos().filter(r => !D.projects.some(p => (repoName(p) || '').toLowerCase() === r.name.toLowerCase())).map(r => ({ g: 'repos', ico: '◇', name: r.name, sub: r.language || '', keys: r.description || '', run: () => openRepo(r.name) })) : [];
    function score(it, q) {
      if (!q) return 1; const n = it.name.toLowerCase(), k = (it.keys || '').toLowerCase(), s = (it.sub || '').toLowerCase();
      if (n.startsWith(q)) return 100; if (n.includes(q)) return 80; if (s.includes(q)) return 60; if (k.includes(q)) return 40;
      let i = 0; for (const c of n) { if (c === q[i]) i++; if (i === q.length) return 20; } return 0;
    }
    function render() {
      const q = input.value.trim().toLowerCase();
      const all = sections().concat(actions(), projects(), playbooks(), repos(q));
      items = all.map(it => ({ it, s: score(it, q) })).filter(x => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 40).map(x => x.it);
      active = 0;
      if (!items.length) { list.innerHTML = '<li class="pal-empty">' + esc(t('pal.empty')) + '</li>'; return; }
      let html = '', lastG = null;
      items.forEach((it, i) => { if (it.g !== lastG) { html += '<li class="pal-group">' + esc(t('pal.' + it.g)) + '</li>'; lastG = it.g; } html += '<li class="pal-item' + (i === active ? ' active' : '') + '" data-i="' + i + '" role="option"><span class="ico">' + it.ico + '</span><span class="pal-name">' + esc(it.name) + '</span>' + (it.sub ? '<span class="sub">' + esc(it.sub) + '</span>' : '') + '</li>'; });
      list.innerHTML = html;
      $$('.pal-item', list).forEach(li => { li.addEventListener('click', () => choose(+li.getAttribute('data-i'))); li.addEventListener('mousemove', () => { active = +li.getAttribute('data-i'); mark(); }); });
    }
    function mark() { $$('.pal-item', list).forEach(li => li.classList.toggle('active', +li.getAttribute('data-i') === active)); const el = $('.pal-item.active', list); if (el) el.scrollIntoView({ block: 'nearest' }); }
    function choose(i) { const it = items[i]; if (!it) return; close(); it.run(); }
    function open() { closeDialog('modal'); closeDialog('term'); openDialog('palette'); input.value = ''; render(); setTimeout(() => input.focus(), 0); }
    function close() { closeDialog('palette'); }
    input.addEventListener('input', render);
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(items.length - 1, active + 1); mark(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); mark(); }
      else if (e.key === 'Enter') { e.preventDefault(); choose(active); }
    });
    return { open, close, toggle: () => ov.hidden ? open() : close() };
  })();

  /* ---------- terminal ---------- */
  const term = (() => {
    const ov = $('#term'), out = $('#term-out'), input = $('#term-in'), form = $('#term-form');
    const history = []; let hIdx = -1, booted = false;
    const print = (html, cls) => { const div = document.createElement('div'); if (cls) div.className = cls; div.innerHTML = html; out.appendChild(div); out.scrollTop = out.scrollHeight; };
    const link = (url, label) => '<a href="' + esc(url) + '" target="_blank" rel="noopener">' + esc(label || url) + '</a>';
    const findProject = q => { q = q.toLowerCase(); return D.projects.find(p => p.id === q || p.name.toLowerCase() === q) || D.projects.find(p => p.id.includes(q) || p.name.toLowerCase().includes(q) || (repoName(p) || '').toLowerCase().includes(q)); };
    const commands = {
      help: () => print(['<span class="ac">help</span>              this list', '<span class="ac">whoami</span>            who runs this site', '<span class="ac">ls</span> [domain]       list domains, or the tools in one (ls cloud)', '<span class="ac">cat</span> about|certs|contact|skills', '<span class="ac">open</span> &lt;project|github|3li|linkedin&gt;', '<span class="ac">find</span> &lt;word&gt;       search the tools', '<span class="ac">playbooks</span>         list the SecOps playbooks', '<span class="ac">stats</span>             live GitHub numbers', '<span class="ac">neofetch</span>          the card', '<span class="ac">theme</span> dark|light   <span class="ac">lang</span> en|ar', '<span class="ac">clear</span>  <span class="ac">history</span>  <span class="ac">exit</span>', '<span class="muted">tab completes project names · ↑↓ recalls history</span>'].join('\n')),
      whoami: () => print('<b>' + esc(D.profile.name) + '</b> (' + esc(D.profile.nameAr) + ') · @' + D.profile.handle + '\n' + esc(D.i18n.en['hero.eyebrow']) + '\n' + esc(D.i18n.en['hero.tag1']) + ' ' + esc(D.i18n.en['hero.tag2']) + '.'),
      ls: a => {
        if (!a) { const c = {}; D.projects.forEach(p => { c[p.cat] = (c[p.cat] || 0) + 1; }); return print(D.domains.map(d => '<span class="ac">' + d.id.padEnd(8) + '</span> ' + esc(d.en) + ' <span class="muted">(' + c[d.id] + ')</span>').join('\n') + '\n<span class="ac">playbooks</span>/'); }
        if (a === 'playbooks') return commands.playbooks();
        const d = domainOf(a); if (!d) return print('ls: ' + esc(a) + ': no such domain. Try: ' + D.domains.map(x => x.id).join(', '), 'err');
        print(D.projects.filter(p => p.cat === a).map(p => '<span class="ac">' + esc(p.id).padEnd(24) + '</span> ' + esc(p.desc.split('. ')[0]) + '.').join('\n'));
      },
      cat: a => {
        const strip = s => s.replace(/<[^>]+>/g, '');
        if (a === 'about') return print([1, 2, 3].map(i => strip(D.i18n.en['about.p' + i])).join('\n\n'));
        if (a === 'certs') return print('Education: ' + D.profile.education.join(' · ') + '\nCertifications: ' + D.profile.certs.join(' · '));
        if (a === 'contact') return print('email     ' + link('mailto:' + D.profile.email, D.profile.email) + '\nweb       ' + link(D.profile.site) + '\ngithub    ' + link(D.profile.github) + '\nlinkedin  ' + link(D.profile.linkedin));
        if (a === 'skills') return print(D.skills.map(g => '<span class="ac">' + esc(g.en) + '</span>: ' + g.items.join(', ')).join('\n'));
        const p = a && findProject(a); if (p) return print('<b>' + esc(p.name) + '</b>' + (p.ar ? ' ' + esc(p.ar) : '') + '  <span class="muted">[' + esc(p.cat) + ']</span>\n' + esc(p.desc) + '\n' + link(projectUrl(p)));
        print('cat: ' + esc(a || '') + ': try about, certs, contact, skills, or a project name', 'err');
      },
      open: a => {
        if (!a) return print('open: what? a project name, github, 3li, or linkedin', 'err');
        const map = { github: D.profile.github, gh: D.profile.github, '3li': D.profile.site, site: D.profile.site, linkedin: D.profile.linkedin, in: D.profile.linkedin };
        if (map[a]) { print('opening ' + link(map[a]), 'ok'); return openExternal(map[a]); }
        const p = findProject(a); if (!p) return print('open: ' + esc(a) + ': not found', 'err');
        print('opening ' + esc(p.name) + ' → ' + link(projectUrl(p)), 'ok'); openProject(p.id);
      },
      find: a => { if (!a) return print('find: give me a word', 'err'); const q = a.toLowerCase(); const hits = D.projects.filter(p => matches(p, q)); print(hits.length ? hits.map(p => '<span class="ac">' + esc(p.id) + '</span>  ' + esc(p.name) + ' <span class="muted">[' + p.cat + ']</span>').join('\n') : 'no matches'); },
      playbooks: () => print(published.map(p => '<span class="ac">' + p.id + '</span>  ' + esc(p.title) + '  <span class="muted">' + p.mitre.join(' ') + '</span>').join('\n') + '\n<span class="muted">' + (D.playbooks.length - published.length) + ' more planned · ' + link('https://github.com/SiteQ8/SiteQ8/tree/main/playbooks', 'browse') + '</span>'),
      stats: async () => { print('fetching…', 'muted'); const gh = await loadGitHub(); if (!gh) return print('GitHub API unavailable (rate limit or offline). Static: ' + D.profile.fallback.public_repos + ' public repos.', 'err'); const stars = allRepos().reduce((a, r) => a + (r.stars || 0), 0); const top = allRepos().slice().sort((a, b) => b.stars - a.stars).slice(0, 5); print('public repos  ' + gh.user.public_repos + '\nfollowers     ' + gh.user.followers + '\nstars         ' + stars + '\ntop starred   ' + top.map(r => r.name + ' (' + r.stars + ')').join(', ') + '\nlast push     ' + (allRepos()[0] ? allRepos()[0].name + ' · ' + timeAgo(allRepos()[0].pushed) : '—')); },
      neofetch: () => print(['<span class="ac">        █████╗ ██╗     ██╗</span>   <b>' + D.profile.name + '</b>@3li.info', '<span class="ac">       ██╔══██╗██║     ██║</span>   ─────────────────────────', '<span class="ac">       ███████║██║     ██║</span>   role      Cybersecurity Expert', '<span class="ac">       ██╔══██║██║     ██║</span>   location  Kuwait', '<span class="ac">       ██║  ██║███████╗██║</span>   tools     ' + D.projects.length + ' flagship · ' + D.profile.fallback.public_repos + '+ repos', '<span class="ac">       ╚═╝  ╚═╝╚══════╝╚═╝</span>   domains   ' + D.domains.map(d => d.id).join(' '), '                             stack     Python Bash KQL JS TS', '                             langs     Arabic · English', '                             motto     defense in the open'].join('\n')),
      theme: a => { if (a !== 'dark' && a !== 'light') return print('theme: dark | light', 'err'); applyTheme(a, true); print('theme → ' + a, 'ok'); },
      lang: a => { if (a !== 'en' && a !== 'ar') return print('lang: en | ar', 'err'); applyLang(a, true); print('lang → ' + a, 'ok'); },
      clear: () => { out.innerHTML = ''; },
      history: () => print(history.map((h, i) => '<span class="muted">' + String(i + 1).padStart(3) + '</span>  ' + esc(h)).join('\n') || 'empty'),
      exit: () => close(), quit: () => close(), q: () => close(),
      pwd: () => print('/home/visitor'), date: () => print(new Date().toString()), echo: a => print(esc(a || '')),
      top: () => { window.scrollTo({ top: 0 }); close(); },
      sudo: () => print('Nice try. Everything here is already open source.', 'err'),
      rm: () => print('rm: permission denied. This is a read only exposure auditor kind of place.', 'err'),
      banner: () => commands.neofetch(),
      motd: () => print('Welcome to 3li.info. Type <span class="ac">help</span> to begin.')
    };
    function run(line) {
      const raw = line.trim(); if (!raw) return; history.push(raw); hIdx = history.length;
      print('<b>visitor@3li.info:~$</b> ' + esc(raw), 'cmdline');
      const [cmd, ...rest] = raw.split(/\s+/); const arg = rest.join(' ');
      const fn = commands[cmd.toLowerCase()];
      if (fn) fn(arg); else print('bash: ' + esc(cmd) + ': command not found. Try <span class="ac">help</span>.', 'err');
    }
    form.addEventListener('submit', e => { e.preventDefault(); run(input.value); input.value = ''; });
    input.addEventListener('keydown', e => {
      if (e.key === 'ArrowUp') { e.preventDefault(); if (hIdx > 0) { hIdx--; input.value = history[hIdx]; } }
      else if (e.key === 'ArrowDown') { e.preventDefault(); if (hIdx < history.length - 1) { hIdx++; input.value = history[hIdx]; } else { hIdx = history.length; input.value = ''; } }
      else if (e.key === 'Tab') {
        e.preventDefault(); const parts = input.value.split(/\s+/); const last = parts[parts.length - 1].toLowerCase(); if (!last) return;
        const pool = parts.length === 1 ? Object.keys(commands) : D.projects.map(p => p.id).concat(D.domains.map(d => d.id), ['about', 'certs', 'contact', 'skills', 'github', '3li', 'linkedin', 'playbooks']);
        const hits = pool.filter(x => x.startsWith(last)); if (hits.length === 1) { parts[parts.length - 1] = hits[0]; input.value = parts.join(' ') + ' '; } else if (hits.length > 1) print(hits.join('  '), 'muted');
      }
      else if (e.key === 'l' && e.ctrlKey) { e.preventDefault(); commands.clear(); }
    });
    function open() {
      closeDialog('modal'); closeDialog('palette'); openDialog('term');
      if (!booted) { booted = true; print('<span class="ok">3li.info</span> · ' + esc(D.profile.name) + ' · <span class="muted">' + new Date().toDateString() + '</span>\nType <span class="ac">help</span> for commands, <span class="ac">ls</span> to browse, <span class="ac">open raqib</span> to jump in.\n'); }
      setTimeout(() => input.focus(), 0);
    }
    function close() { closeDialog('term'); }
    $('#term-close').addEventListener('click', close);
    return { open, close, toggle: () => ov.hidden ? open() : close() };
  })();

  /* ---------- wiring ---------- */
  $('#btn-theme').addEventListener('click', () => applyTheme(state.theme === 'dark' ? 'light' : 'dark', true));
  $('#btn-lang').addEventListener('click', () => applyLang(state.lang === 'ar' ? 'en' : 'ar', true));
  $('#btn-palette').addEventListener('click', palette.open);
  $('#btn-terminal').addEventListener('click', term.open);
  $('#btn-allrepos').addEventListener('click', toggleAllRepos);
  $('#btn-clear').addEventListener('click', clearFilters);
  $('#btn-copy').addEventListener('click', () => copy(D.profile.email));
  $('#search').addEventListener('input', e => { state.q = e.target.value; renderGrid(); });
  $('#pb-search').addEventListener('input', e => { pbState.q = e.target.value; renderPlaybooks(); });
  $('#sort').addEventListener('change', e => { state.sort = e.target.value; renderGrid(); });
  $$('#view button').forEach(b => b.addEventListener('click', () => { state.view = b.getAttribute('data-view'); $$('#view button').forEach(x => x.setAttribute('aria-pressed', String(x === b))); store('view', state.view); renderGrid(); }));
  if (navigator.share) { const sb = $('#btn-share'); sb.hidden = false; sb.addEventListener('click', () => navigator.share({ title: document.title, url: location.href.split('#')[0] }).catch(() => { })); }
  $('#year').textContent = String(new Date().getFullYear());
  document.addEventListener('keydown', e => {
    const tag = (e.target.tagName || '').toLowerCase(); const typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); palette.toggle(); return; }
    if (e.key === 'Escape') { closeAll(); return; }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); $('#search').focus(); $('#search').select(); document.getElementById('work').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth' }); }
    else if (e.key === '`') { e.preventDefault(); term.toggle(); }
  });
  function route() { const h = location.hash; if (h.startsWith('#p/')) { const id = h.slice(3); if (D.projects.some(p => p.id === id)) openProject(id); } }
  window.addEventListener('hashchange', route);

  /* ---------- boot ---------- */
  const savedView = load('view'); if (savedView === 'list' || savedView === 'grid') { state.view = savedView; $$('#view button').forEach(x => x.setAttribute('aria-pressed', String(x.getAttribute('data-view') === savedView))); }
  applyTheme(state.theme, false);
  applyLang(state.lang, false);
  route();
  if (!isFile) loadGitHub(); else { state.ghStatus = 'static'; updateLiveLine(); }
  if ('serviceWorker' in navigator && location.protocol === 'https:') { window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => { })); }
})();
