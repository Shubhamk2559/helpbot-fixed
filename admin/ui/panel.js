/* HelpBot admin shell. Everything is built with textContent and DOM nodes (XSS-safe, CSP-friendly).
 * Later phases add a section with:  Admin.section('files', function (root) { ... });
 * and call APIs with:               Admin.api('POST', '/files/delete', {token: t, confirm: true})
 */
(function () {
  'use strict';
  var state = { csrf: '', sections: [] };
  var renderers = {};
  var current = document.body.dataset.section || 'dashboard';

  function h(tag, attrs) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'class') el.className = attrs[k];
      else if (k.indexOf('on') === 0) el.addEventListener(k.slice(2), attrs[k]);
      else el.setAttribute(k, attrs[k]);
    });
    (function add(list) {
      list.forEach(function (c) {
        if (c === null || c === undefined || c === false) return;
        if (Array.isArray(c)) { add(c); return; }
        el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
      });
    })(Array.prototype.slice.call(arguments, 2));
    return el;
  }

  var toastTimer;
  function toast(text, kind) {
    var t = document.getElementById('toast');
    t.textContent = text; t.className = kind || ''; clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.className = 'hide'; }, 4000);
  }

  function api(method, path, body) {
    var opt = { method: method, credentials: 'same-origin', headers: {} };
    if (method !== 'GET') {
      opt.headers['Content-Type'] = 'application/json';
      opt.headers['X-CSRF-Token'] = state.csrf;
      opt.body = JSON.stringify(body || {});
    }
    return fetch('/admin/api' + path, opt).then(function (r) {
      return r.json().catch(function () { return { ok: false, code: 'bad_response', error: 'Unexpected response' }; })
        .then(function (j) {
          if (r.status === 401) { location.href = '/admin/login'; }
          return j;
        });
    }).catch(function () { return { ok: false, code: 'network', error: 'Network error' }; });
  }

  /* destructive actions: resolves true only if the owner clicks the red button */
  function confirmDialog(text, label) {
    return new Promise(function (resolve) {
      var ov;
      function done(v) { document.body.removeChild(ov); resolve(v); }
      ov = h('div', { 'class': 'overlay' },
        h('div', { 'class': 'dialog', role: 'dialog', 'aria-modal': 'true' },
          h('p', {}, text),
          h('div', { 'class': 'row' },
            h('button', { 'class': 'danger', type: 'button', onclick: function () { done(true); } }, label || 'Confirm'),
            h('button', { 'class': 'ghost', type: 'button', onclick: function () { done(false); } }, 'Cancel'))));
      document.body.appendChild(ov);
    });
  }

  function fmt(n) { return (n === null || n === undefined) ? '–' : Number(n).toLocaleString(); }
  function pct(v) { return (v === null || v === undefined) ? '–' : Math.round(v * 100) + '%'; }
  function usd(v) { return (v === null || v === undefined) ? '–' : '$' + Number(v).toFixed(2); }
  function when(t) { return t ? new Date(t * 1000).toLocaleString() : '–'; }
  function stat(label, value) { return h('dl', { 'class': 'stat' }, h('dt', {}, label), h('dd', {}, value)); }
  function card(title) { var c = h('section', { 'class': 'card' }); if (title) c.appendChild(h('h2', {}, title)); return c; }
  function table(head, rows) {
    return h('div', { 'class': 'tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, head.map(function (x) { return h('th', { 'class': x.num ? 'num' : '' }, x.t); }))),
      h('tbody', {}, rows.map(function (r) {
        return h('tr', {}, r.map(function (v, i) { return h('td', { 'class': head[i].num ? 'num' : '' }, v); }));
      }))));
  }

  function barChart(points) {
    var ns = 'http://www.w3.org/2000/svg', W = 420, Hh = 150, n = points.length || 1;
    var max = Math.max.apply(null, points.map(function (p) { return p.views; }).concat([1]));
    var svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + Hh); svg.setAttribute('class', 'chart');
    svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Views, last 7 days');
    var bw = W / n;
    points.slice().reverse().forEach(function (p, i) {
      var bh = Math.round((p.views / max) * 100), x = i * bw + 8;
      var r = document.createElementNS(ns, 'rect');
      r.setAttribute('x', x); r.setAttribute('y', 110 - bh); r.setAttribute('width', bw - 16);
      r.setAttribute('height', Math.max(bh, 1)); r.setAttribute('rx', 3); svg.appendChild(r);
      var v = document.createElementNS(ns, 'text'); v.setAttribute('class', 'v');
      v.setAttribute('x', x + (bw - 16) / 2); v.setAttribute('y', 104 - bh); v.textContent = p.views; svg.appendChild(v);
      var d = document.createElementNS(ns, 'text'); d.setAttribute('x', x + (bw - 16) / 2); d.setAttribute('y', 130);
      d.textContent = p.day.slice(5); svg.appendChild(d);
    });
    return svg;
  }

  /* ------------------------------------------------ sections */
  renderers.dashboard = function (root) {
    root.appendChild(h('p', { 'class': 'muted' }, 'Loading…'));
    api('GET', '/dashboard').then(function (j) {
      root.textContent = '';
      if (!j.ok) { root.appendChild(h('p', { 'class': 'bad' }, j.error || 'Failed to load')); return; }
      var d = j.data, a = d.ads || {};
      var top = card('Overview');
      top.appendChild(h('div', { 'class': 'grid' },
        stat('Deliveries today', fmt(d.views_today)), stat('Deliveries total', fmt(d.views_total)),
        stat('Files / posts', fmt(d.files_total)), stat('Posts', fmt(d.posts_total)),
        stat('Bulk imported', fmt(d.bulk_imported)), stat('Users (recent)', fmt(d.users_recent)),
        stat('Bots active', fmt(d.bots_active) + ' / ' + fmt(d.bots.length))));
      top.appendChild(h('p', { 'class': 'muted' }, 'Delivery = a user watched the ad(s) and received the file (same as the bot\'s “views”). ' + (d.users_note || '')));
      root.appendChild(top);

      var c7 = card('Last 7 days'); c7.appendChild(barChart(d.last_7_days)); root.appendChild(c7);

      var bots = card('Per bot');
      bots.appendChild(d.bots.length ? table(
        [{ t: 'Bot' }, { t: 'Status' }, { t: 'Sessions', num: 1 }, { t: 'Delivered', num: 1 }, { t: 'Users', num: 1 }],
        d.bots.map(function (b) {
          return [b.username ? '@' + b.username : b.bot_id, b.status || '–', fmt(b.sessions), fmt(b.delivered), fmt(b.users)];
        })) : h('p', { 'class': 'muted' }, 'No bots yet.'));
      bots.appendChild(h('p', { 'class': 'muted' }, 'Session counts cover only the SESSION_TTL window (sessions expire); there are no lifetime per-bot totals in the database.'));
      root.appendChild(bots);

      var ads = card('Ads — last ' + (a.window_days || 7) + ' days' + (a.mode ? ' (' + a.mode + ')' : ''));
      if (a.error || !a.totals) { ads.appendChild(h('p', { 'class': 'muted' }, 'Ad stats unavailable.')); }
      else {
        var t = a.totals;
        ads.appendChild(h('div', { 'class': 'grid' },
          stat('Requests', fmt(t.requests)), stat('Shown', fmt(t.shown)), stat('Completed', fmt(t.completed)),
          stat('Failed', fmt(t.failed)), stat('Fill rate', pct(t.fill_rate)),
          stat('Confirmed rev.', usd(t.confirmed_revenue_usd)), stat('Estimated rev.', usd(t.estimated_revenue_usd))));
        var nets = Object.keys(a.networks || {});
        if (nets.length) ads.appendChild(table([{ t: 'Network' }, { t: 'Status' }, { t: 'Verified', num: 1 }, { t: 'Today', num: 1 }, { t: 'Fill', num: 1 }],
          nets.map(function (k) { var n = a.networks[k]; return [n.label, n.status, fmt(n.verified), fmt(n.today_verified), pct(n.fill_rate)]; })));
        ads.appendChild(h('p', { 'class': 'muted' }, 'Estimated revenue is an estimate, not a payout. Confirmed = what you entered from the network dashboard.'));
      }
      root.appendChild(ads);
    });
  };

  renderers.settings = function (root) {
    root.appendChild(h('p', { 'class': 'muted' }, 'Loading…'));
    api('GET', '/settings').then(function (j) {
      root.textContent = '';
      if (!j.ok) { root.appendChild(h('p', { 'class': 'bad' }, j.error || 'Failed to load')); return; }
      var p = j.panel, pc = card('Admin panel');
      pc.appendChild(h('div', { 'class': 'row' },
        h('span', {}, '2FA (TOTP): '), h('span', { 'class': 'pill ' + (p.totp_enabled ? 'on' : 'off') }, p.totp_enabled ? 'on' : 'off')));
      pc.appendChild(h('p', { 'class': 'muted' }, 'Session ' + p.session_hours + ' h · lock after ' + p.max_fails + ' failed logins for ' + p.lockout_minutes +
        ' min · activity kept ' + p.activity_days + ' days · secure cookie: ' + (p.cookie_secure ? 'yes' : 'NO') + ' · proxy hops: ' + p.proxy_hops));
      root.appendChild(pc);
      var ec = card('Environment variables');
      ec.appendChild(h('p', { 'class': 'muted' }, 'Only whether each variable is set. Values are never sent to the browser. Change them in your host\'s dashboard and redeploy.'));
      Object.keys(j.env).forEach(function (g) {
        ec.appendChild(h('h2', {}, g));
        ec.appendChild(h('div', { 'class': 'envgrid' }, j.env[g].map(function (v) {
          return h('div', {}, h('span', {}, v.name), h('span', { 'class': 'pill ' + (v.set ? 'on' : 'off') }, v.set ? 'set' : 'unset'));
        })));
      });
      root.appendChild(ec);
    });
  };

  renderers.activity = function (root) {
    var page = 1, limit = 50, body = h('div', {}), c = card('Activity log');
    var filter = h('select', { 'aria-label': 'Filter' },
      h('option', { value: '' }, 'All'), h('option', { value: 'true' }, 'Succeeded'), h('option', { value: 'false' }, 'Failed'));
    var prev = h('button', { 'class': 'ghost', type: 'button' }, '‹ Newer'), next = h('button', { 'class': 'ghost', type: 'button' }, 'Older ›');
    var info = h('span', { 'class': 'muted' });
    c.appendChild(h('div', { 'class': 'row' }, filter, prev, next, info)); c.appendChild(body); root.appendChild(c);
    function load() {
      var q = '?page=' + page + '&limit=' + limit + (filter.value ? '&ok=' + filter.value : '');
      api('GET', '/activity' + q).then(function (j) {
        body.textContent = '';
        if (!j.ok) { body.appendChild(h('p', { 'class': 'bad' }, j.error || 'Failed')); return; }
        info.textContent = j.total + ' entries';
        prev.disabled = page <= 1; next.disabled = page * limit >= j.total;
        body.appendChild(j.items.length ? table([{ t: 'Time' }, { t: 'Action' }, { t: 'Result' }, { t: 'IP' }, { t: 'Detail' }],
          j.items.map(function (i) {
            return [when(i.t), i.action, h('span', { 'class': i.ok ? 'ok' : 'bad' }, i.ok ? 'ok ' + i.status : 'fail ' + i.status), i.ip || '–',
              Object.keys(i.detail).length ? JSON.stringify(i.detail) : ''];
          })) : h('p', { 'class': 'muted' }, 'Nothing logged yet.'));
      });
    }
    filter.addEventListener('change', function () { page = 1; load(); });
    prev.addEventListener('click', function () { page--; load(); });
    next.addEventListener('click', function () { page++; load(); });
    load();
  };

  function comingSoon(title) {
    return function (root) {
      root.appendChild(h('section', { 'class': 'card soon-box' }, h('h2', {}, title), h('p', { 'class': 'muted' }, 'Coming soon — this section is built in a later phase. The bot\'s owner menu keeps working meanwhile.')));
    };
  }

  /* ------------------------------------------------ boot */
  function nav(sections) {
    ['side', 'nbar'].forEach(function (id) {
      var el = document.getElementById(id); el.textContent = '';
      sections.forEach(function (s) {
        el.appendChild(h('a', { href: s.path, 'class': (s.id === current ? 'on ' : '') + (s.built ? '' : 'soon') },
          h('span', {}, s.title), (!s.built && id === 'side') ? h('span', { 'class': 'tag' }, 'soon') : null));
      });
    });
  }

  document.getElementById('logout').addEventListener('click', function () {
    api('POST', '/logout', {}).then(function () { location.href = '/admin/login'; });
  });

  function boot() {
    api('GET', '/session').then(function (j) {
      if (!j.ok) { location.href = '/admin/login'; return; }
      state.csrf = j.csrf; state.sections = j.sections; nav(j.sections);
      var main = document.getElementById('main'); main.textContent = '';
      var meta = j.sections.filter(function (s) { return s.id === current; })[0] || { title: current };
      (renderers[current] || comingSoon(meta.title))(main);
    });
  }

  window.Admin = { api: api, h: h, toast: toast, confirmDialog: confirmDialog, fmt: fmt, usd: usd, pct: pct, when: when,
    card: card, table: table, stat: stat, section: function (id, fn) { renderers[id] = fn; } };
  boot();
})();
