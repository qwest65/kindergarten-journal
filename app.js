'use strict';
/*
 * Журнал детского сада.
 *
 * Код сайта лежит в публичном репозитории (GitHub Pages), данные — в приватном.
 * Вход по паролю: в публичном файле auth/users.json для каждого сотрудника хранится
 * ключ доступа GitHub, зашифрованный его паролем (PBKDF2 + AES-GCM). Пароль никуда
 * не отправляется, расшифровка выполняется в браузере.
 * Каждое изменение — один коммит в репозиторий данных вместе с записью в журнал действий.
 */

const CONFIG = {
  siteRepo: 'qwest65/kindergarten-journal',
  siteBranch: 'main',
  authPath: 'auth/users.json',
  defaultDataRepo: 'qwest65/kindergarten-journal-data',
  dataBranch: 'main',
  pbkdf2Iterations: 600000,
  xlsxUrl: 'https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js',
};

const STATUSES = [
  { k: 'p', label: 'Был', short: 'Был', code: '+' },
  { k: 'a', label: 'Не был', short: 'Не был', code: 'Н' },
  { k: 's', label: 'Болеет', short: 'Болеет', code: 'Б' },
  { k: 'v', label: 'Отпуск', short: 'Отпуск', code: 'О' },
  { k: 'o', label: 'Уважительная причина', short: 'Уваж.', code: 'У' },
];
const ST = Object.fromEntries(STATUSES.map(s => [s.k, s]));
const LESSON_STATUS = { done: 'Проведено', planned: 'Запланировано', cancelled: 'Отменено' };
const ROLE = { admin: 'Заведующая', teacher: 'Воспитатель' };

/* ================= Утилиты ================= */

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const pad = n => String(n).padStart(2, '0');
const isoDate = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
const today = () => isoDate(new Date());
const thisMonth = () => today().slice(0, 7);
const nowIso = () => new Date().toISOString();
const parseDate = s => { const [y, m, d] = s.split('-').map(Number); return new Date(y, m - 1, d); };
const addDays = (s, n) => { const d = parseDate(s); d.setDate(d.getDate() + n); return isoDate(d); };
const fmtDate = s => s ? s.slice(8, 10) + '.' + s.slice(5, 7) + '.' + s.slice(0, 4) : '—';
const fmtDateTime = iso => { if (!iso) return '—'; const d = new Date(iso); return pad(d.getDate()) + '.' + pad(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()); };
const fmtTime = iso => { if (!iso) return ''; const d = new Date(iso); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
const MONTHS = ['январь', 'февраль', 'март', 'апрель', 'май', 'июнь', 'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь'];
const WD = ['вс', 'пн', 'вт', 'ср', 'чт', 'пт', 'сб'];
const monthTitle = ym => { const m = MONTHS[Number(ym.slice(5, 7)) - 1]; return m[0].toUpperCase() + m.slice(1) + ' ' + ym.slice(0, 4); };
const daysInMonth = ym => new Date(Number(ym.slice(0, 4)), Number(ym.slice(5, 7)), 0).getDate();
const weekday = s => parseDate(s).getDay();
const isWeekend = s => { const w = weekday(s); return w === 0 || w === 6; };
const byName = (a, b) => a.name.localeCompare(b.name, 'ru');
const pct = (a, b) => b ? Math.round(a / b * 100) : null;
const pctText = v => v == null ? '—' : v + '%';

const store = {
  get(k) { for (const s of [localStorage, sessionStorage]) { try { const v = s.getItem(k); if (v) return JSON.parse(v); } catch (e) { /* хранилище недоступно */ } } return null; },
  set(k, v, persistent) { try { (persistent ? localStorage : sessionStorage).setItem(k, JSON.stringify(v)); } catch (e) { /* нет хранилища */ } },
  del(k) { for (const s of [localStorage, sessionStorage]) { try { s.removeItem(k); } catch (e) { /* ignore */ } } },
};

const b64enc = bytes => { let s = ''; bytes.forEach(b => { s += String.fromCharCode(b); }); return btoa(s); };
const b64dec = str => Uint8Array.from(atob(str.replace(/\s/g, '')), c => c.charCodeAt(0));
const utf8 = bytes => new TextDecoder().decode(bytes);
const utf8bytes = str => new TextEncoder().encode(str);

function genPassword() {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const chars = Array.from(bytes, b => alphabet[b % alphabet.length]);
  return chars.slice(0, 4).join('') + '-' + chars.slice(4, 8).join('') + '-' + chars.slice(8).join('');
}

/* ================= Шифрование ================= */

async function deriveKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8bytes(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function seal(obj, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const it = CONFIG.pbkdf2Iterations;
  const key = await deriveKey(password, salt, it);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8bytes(JSON.stringify(obj))));
  return { it, salt: b64enc(salt), iv: b64enc(iv), ct: b64enc(ct) };
}
async function unseal(entry, password) {
  const key = await deriveKey(password, b64dec(entry.salt), entry.it || CONFIG.pbkdf2Iterations);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64dec(entry.iv) }, key, b64dec(entry.ct));
  return JSON.parse(utf8(new Uint8Array(pt)));
}
async function loginHash(login) {
  const d = await crypto.subtle.digest('SHA-256', utf8bytes('kj1:' + normLogin(login)));
  return Array.from(new Uint8Array(d), b => b.toString(16).padStart(2, '0')).join('');
}
const normLogin = l => String(l || '').trim().toLowerCase();

/* ================= GitHub API ================= */

class GitHub {
  constructor(token) { this.token = token; }

  async api(method, path, body) {
    const headers = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
    if (this.token) headers.Authorization = 'Bearer ' + this.token;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch('https://api.github.com' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
    } catch (e) {
      const err = new Error('Нет связи с GitHub. Проверьте интернет и попробуйте ещё раз.');
      err.status = 0; throw err;
    }
    if (res.status === 204) return null;
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { /* не JSON */ }
    if (!res.ok) {
      const err = new Error((json && json.message) || ('Ошибка GitHub ' + res.status));
      err.status = res.status; throw err;
    }
    return json;
  }

  async readJSON(repo, path, ref) {
    const q = ref ? '?ref=' + encodeURIComponent(ref) : '';
    let r;
    try {
      r = await this.api('GET', `/repos/${repo}/contents/${path.split('/').map(encodeURIComponent).join('/')}${q}`);
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
    let text = '';
    if (r.content) text = utf8(b64dec(r.content));
    else if (r.size > 0) { // файл больше 1 МБ — читаем через blob
      const blob = await this.api('GET', `/repos/${repo}/git/blobs/${r.sha}`);
      text = utf8(b64dec(blob.content));
    }
    return { data: text.trim() ? JSON.parse(text) : null, sha: r.sha };
  }

  /*
   * Атомарный коммит нескольких JSON-файлов. update(old) получает свежие данные
   * и возвращает новые (или undefined — файл не менять). При одновременной записи
   * другим сотрудником всё перечитывается и применяется заново.
   */
  async commit(repo, branch, message, changes) {
    for (let attempt = 0; attempt < 6; attempt++) {
      let head;
      try {
        head = await this.api('GET', `/repos/${repo}/git/ref/heads/${branch}`);
      } catch (e) {
        if (e.status === 409 || e.status === 404) {
          const err = new Error(`Репозиторий ${repo} пуст или недоступен. При создании репозитория нужно поставить галочку «Add a README file».`);
          err.status = e.status; throw err;
        }
        throw e;
      }
      const headSha = head.object.sha;
      const headCommit = await this.api('GET', `/repos/${repo}/git/commits/${headSha}`);
      const ctx = {}, out = {}, tree = [];
      for (const ch of changes) {
        const cur = await this.readJSON(repo, ch.path, headSha);
        const next = ch.update(cur ? cur.data : null, ctx);
        if (next === undefined) continue;
        out[ch.path] = next;
        tree.push({ path: ch.path, mode: '100644', type: 'blob', content: JSON.stringify(next, null, 1) + '\n' });
      }
      if (!tree.length) return { out, ctx, empty: true };
      const t = await this.api('POST', `/repos/${repo}/git/trees`, { base_tree: headCommit.tree.sha, tree });
      const msg = typeof message === 'function' ? message(ctx) : message;
      const c = await this.api('POST', `/repos/${repo}/git/commits`, { message: String(msg).slice(0, 2000), tree: t.sha, parents: [headSha] });
      try {
        await this.api('PATCH', `/repos/${repo}/git/refs/heads/${branch}`, { sha: c.sha, force: false });
        return { out, ctx };
      } catch (e) {
        if (e.status === 422 || e.status === 409) { await sleep(400 + Math.random() * 900); continue; }
        throw e;
      }
    }
    throw new Error('Не удалось сохранить: одновременно идёт много изменений. Попробуйте ещё раз.');
  }
}

function humanError(e) {
  if (!e) return 'Неизвестная ошибка';
  if (e.status === 401) return 'Ключ доступа GitHub недействителен или истёк. Обратитесь к заведующей.';
  if (e.status === 403) return 'GitHub отказал в доступе (нет прав или превышен лимит запросов). ' + (e.message || '');
  if (e.status === 404) return 'Не найдено на GitHub. Проверьте название репозитория и права ключа доступа.';
  return e.message || String(e);
}

/* ================= Состояние ================= */

const S = {
  gh: null, token: null, dataRepo: null, me: null,
  users: [], groups: [], children: [],
  cache: new Map(),
  view: 'mark',
  mark: { groupId: null, date: null, draft: {}, base: {}, key: null },
  filters: { month: thisMonth(), groupId: '', user: '', q: '' },
  adminTab: 'children',
};

const isAdmin = () => S.me && S.me.role === 'admin';
const groupById = id => S.groups.find(g => g.id === id);
const groupName = id => (groupById(id) || {}).name || '—';
const childById = id => S.children.find(c => c.id === id);
const userName = id => (S.users.find(u => u.id === id) || {}).name || '—';
function myGroups(includeArchived) {
  const list = S.groups.filter(g => includeArchived || !g.archived);
  return (isAdmin() ? list : list.filter(g => (S.me.groups || []).includes(g.id))).slice().sort(byName);
}
const groupKids = gid => S.children.filter(c => c.groupId === gid && !c.archived).sort(byName);
const monthPath = (kind, ym) => `data/${kind}/${ym}.json`;

async function loadCore() {
  const [u, g, c] = await Promise.all([
    S.gh.readJSON(S.dataRepo, 'data/users.json', CONFIG.dataBranch),
    S.gh.readJSON(S.dataRepo, 'data/groups.json', CONFIG.dataBranch),
    S.gh.readJSON(S.dataRepo, 'data/children.json', CONFIG.dataBranch),
  ]);
  S.users = (u && u.data && u.data.users) || [];
  S.groups = (g && g.data && g.data.groups) || [];
  S.children = (c && c.data && c.data.children) || [];
}

async function loadMonth(kind, ym, force) {
  const path = monthPath(kind, ym);
  if (!force && S.cache.has(path)) return S.cache.get(path);
  const r = await S.gh.readJSON(S.dataRepo, path, CONFIG.dataBranch);
  const data = (r && r.data) || defaultFor(path);
  S.cache.set(path, data);
  return data;
}

function defaultFor(path) {
  if (path.startsWith('data/attendance/')) return {};
  if (path.startsWith('data/lessons/')) return { lessons: [] };
  if (path.startsWith('data/log/')) return { entries: [] };
  if (path === 'data/users.json') return { users: [] };
  if (path === 'data/groups.json') return { groups: [] };
  if (path === 'data/children.json') return { children: [] };
  return {};
}

function logChange(action, textFn) {
  return {
    path: monthPath('log', thisMonth()),
    update: (d, ctx) => {
      d = d || { entries: [] };
      const text = typeof textFn === 'function' ? textFn(ctx) : textFn;
      d.entries.push({ at: nowIso(), by: S.me.id, name: S.me.name, action, text });
      ctx.logText = text;
      return d;
    },
  };
}

/* Сохранение изменений в репозиторий данных с записью в журнал действий. */
async function saveData(action, changes, logText, busyText) {
  const all = changes.concat([logChange(action, logText)]);
  showBusy(busyText || 'Сохраняю…');
  try {
    const res = await S.gh.commit(S.dataRepo, CONFIG.dataBranch, ctx => `${S.me.name}: ${ctx.logText || action}`, all);
    for (const [path, data] of Object.entries(res.out)) applyLocal(path, data);
    return res;
  } finally { hideBusy(); }
}

function applyLocal(path, data) {
  if (path === 'data/users.json') S.users = data.users;
  else if (path === 'data/groups.json') S.groups = data.groups;
  else if (path === 'data/children.json') S.children = data.children;
  else S.cache.set(path, data);
}

/* Коммит в публичный репозиторий сайта (только зашифрованные ключи, без имён). */
async function saveAuth(mutator, gh) {
  return (gh || S.gh).commit(CONFIG.siteRepo, CONFIG.siteBranch, 'Обновление доступа', [{
    path: CONFIG.authPath,
    update: d => {
      d = d || { version: 1, users: {} };
      d.users = d.users || {};
      d.dataRepo = S.dataRepo;
      mutator(d);
      return d;
    },
  }]);
}

/* ================= UI-хелперы ================= */

function show(screen) {
  ['loading', 'login', 'setup', 'app'].forEach(s => $('#screen-' + s).classList.toggle('hidden', s !== screen));
}
function toast(msg, isError) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = msg;
  $('#toastRoot').appendChild(el);
  setTimeout(() => el.remove(), isError ? 7000 : 3000);
}
function showBusy(text) { $('#busyText').textContent = text; $('#busy').classList.remove('hidden'); }
function hideBusy() { $('#busy').classList.add('hidden'); }
function setView(html) { $('#view').innerHTML = html; }
const loadingHtml = '<div class="empty"><div class="spinner" style="margin:0 auto 10px"></div>Загрузка…</div>';

function table(headers, rows, emptyText, cls) {
  if (!rows.length) return `<div class="empty">${emptyText || 'Нет записей'}</div>`;
  return `<div class="table-wrap"><table class="${cls || ''}"><thead><tr>${headers.join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
const th = (t, cls) => `<th class="${cls || ''}">${t}</th>`;

function groupOptions(selected, groups, withAll) {
  return (withAll ? `<option value="">${withAll}</option>` : '') +
    groups.map(g => `<option value="${esc(g.id)}" ${g.id === selected ? 'selected' : ''}>${esc(g.name)}${g.archived ? ' (архив)' : ''}</option>`).join('');
}

/*
 * Модальное окно. onOk(form) — async; вернуть false, чтобы окно осталось открытым.
 * Ошибка из onOk показывается внутри окна.
 */
function openModal({ title, body, okText, onOk, wide, cancelText, noCancel }) {
  const root = $('#modalRoot');
  root.innerHTML = `<div class="modal-backdrop"><form class="modal ${wide ? 'wide' : ''}" novalidate>
    <div class="modal-head"><h2>${title}</h2><button type="button" class="x-btn" data-close aria-label="Закрыть">×</button></div>
    <div>${body}</div>
    <div class="form-error" data-err></div>
    <div class="modal-foot">${noCancel ? '' : `<button type="button" class="btn" data-close>${cancelText || 'Отмена'}</button>`}${onOk ? `<button class="btn primary" type="submit">${okText || 'Сохранить'}</button>` : ''}</div>
  </form></div>`;
  const form = root.querySelector('form');
  const close = () => { root.innerHTML = ''; };
  root.querySelectorAll('[data-close]').forEach(b => { b.onclick = close; });
  form.onsubmit = async e => {
    e.preventDefault();
    if (!onOk) return close();
    if (!form.checkValidity()) { form.reportValidity(); return; }
    const btn = form.querySelector('button[type=submit]');
    btn.disabled = true;
    form.querySelector('[data-err]').textContent = '';
    try {
      const r = await onOk(form);
      if (r !== false && root.contains(form)) close();
    } catch (err) {
      console.error(err);
      form.querySelector('[data-err]').textContent = humanError(err);
    } finally { btn.disabled = false; }
  };
  const first = form.querySelector('input:not([type=checkbox]),select,textarea');
  if (first) setTimeout(() => first.focus(), 30);
  return { form, close };
}
const fval = (form, name) => (form.elements[name] ? String(form.elements[name].value).trim() : '');

function confirmModal(title, text, okText) {
  return new Promise(resolve => {
    let done = false;
    const m = openModal({
      title, body: `<p style="margin:0">${text}</p>`, okText: okText || 'Да',
      onOk: async () => { done = true; resolve(true); },
    });
    const obs = new MutationObserver(() => { if (!document.body.contains(m.form)) { obs.disconnect(); if (!done) resolve(false); } });
    obs.observe($('#modalRoot'), { childList: true });
  });
}

function credentialsHtml(rows) {
  return `<p class="hint" style="margin-top:0">Передайте эти данные сотрудникам лично. Повторно посмотреть пароль будет нельзя — только задать новый.</p>` +
    table([th('Сотрудник'), th('Логин'), th('Пароль')], rows.map(r =>
      `<tr><td>${esc(r.name)}</td><td><span class="secret">${esc(r.login)}</span></td><td><span class="secret">${esc(r.password)}</span></td></tr>`));
}

/* ================= Excel ================= */

let xlsxPromise = null;
function loadXLSX() {
  if (window.XLSX) return Promise.resolve(window.XLSX);
  if (!xlsxPromise) {
    xlsxPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = CONFIG.xlsxUrl;
      s.onload = () => resolve(window.XLSX);
      s.onerror = () => { xlsxPromise = null; reject(new Error('Не удалось загрузить модуль Excel. Проверьте интернет.')); };
      document.head.appendChild(s);
    });
  }
  return xlsxPromise;
}
const sheetName = (name, used) => {
  let base = String(name).replace(/[\[\]:*?/\\]/g, ' ').slice(0, 28).trim() || 'Лист';
  let n = base, i = 2;
  while (used.has(n.toLowerCase())) n = base.slice(0, 25) + ' ' + (i++);
  used.add(n.toLowerCase());
  return n;
};
function downloadWorkbook(XLSX, wb, filename) {
  const data = XLSX.write(wb, { bookType: 'xlsx', type: 'array', compression: true });
  const blob = new Blob([data], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
function addSheet(XLSX, wb, used, name, aoa, opts) {
  const ws = XLSX.utils.aoa_to_sheet(aoa);
  if (opts && opts.cols) ws['!cols'] = opts.cols.map(w => ({ wch: w }));
  if (opts && opts.merges) ws['!merges'] = opts.merges;
  XLSX.utils.book_append_sheet(wb, ws, sheetName(name, used));
}

/* ================= Подсчёты ================= */

/* Отметки группы за месяц: { childId: { 'YYYY-MM-DD': mark } } */
function groupMonthMarks(att, gid) {
  const res = {};
  for (const [date, day] of Object.entries(att || {})) {
    for (const [cid, m] of Object.entries(day || {})) {
      const child = childById(cid);
      const g = m.g || (child && child.groupId);
      if (g !== gid) continue;
      (res[cid] = res[cid] || {})[date] = m;
    }
  }
  return res;
}
function tabelChildren(gid, marks) {
  const ids = new Set(groupKids(gid).map(c => c.id));
  Object.keys(marks).forEach(id => ids.add(id));
  return Array.from(ids).map(id => childById(id) || { id, name: '(удалён)' }).sort(byName);
}
function childCounts(days) {
  const c = { p: 0, a: 0, s: 0, v: 0, o: 0, marked: 0 };
  Object.values(days || {}).forEach(m => { if (c[m.s] != null) { c[m.s]++; c.marked++; } });
  c.missed = c.marked - c.p;
  c.pct = pct(c.p, c.marked);
  return c;
}
function groupStats(att, gid) {
  const marks = groupMonthMarks(att, gid);
  const kids = tabelChildren(gid, marks);
  const total = { p: 0, a: 0, s: 0, v: 0, o: 0, marked: 0 };
  const dates = new Set();
  const rows = kids.map(k => {
    const c = childCounts(marks[k.id]);
    Object.keys(marks[k.id] || {}).forEach(d => dates.add(d));
    ['p', 'a', 's', 'v', 'o', 'marked'].forEach(x => { total[x] += c[x]; });
    return { child: k, c };
  });
  total.pct = pct(total.p, total.marked);
  total.days = dates.size;
  total.avg = dates.size ? Math.round(total.p / dates.size * 10) / 10 : null;
  total.kids = groupKids(gid).length;
  return { rows, total, marks, kids };
}

/* ================= Вход / настройка ================= */

async function fetchAuth() {
  const gh = new GitHub(null);
  try {
    const r = await gh.readJSON(CONFIG.siteRepo, CONFIG.authPath, CONFIG.siteBranch);
    return { ok: true, data: r ? r.data : null };
  } catch (e) {
    // лимит анонимных запросов — пробуем raw-копию
    try {
      const res = await fetch(`https://raw.githubusercontent.com/${CONFIG.siteRepo}/${CONFIG.siteBranch}/${CONFIG.authPath}`, { cache: 'no-store' });
      if (res.status === 404) return { ok: true, data: null };
      if (res.ok) return { ok: true, data: await res.json() };
    } catch (e2) { /* нет сети */ }
    return { ok: false, error: e };
  }
}

let AUTH = null;

async function boot() {
  show('loading');
  const sess = store.get('kj-session');
  if (sess && sess.t && sess.r && sess.u) {
    try {
      await startSession(sess.t, sess.r, sess.u);
      return;
    } catch (e) {
      console.warn(e);
      if (e.status === 0) { toast(humanError(e), true); }
      store.del('kj-session');
    }
  }
  const a = await fetchAuth();
  if (!a.ok) {
    show('login');
    $('#loginError').textContent = 'Не удалось связаться с GitHub. Проверьте интернет и обновите страницу.';
    return;
  }
  AUTH = a.data;
  if (!AUTH || !AUTH.users || !Object.keys(AUTH.users).length) openSetup(false);
  else show('login');
}

async function startSession(token, dataRepo, userId, remember) {
  S.gh = new GitHub(token);
  S.token = token;
  S.dataRepo = dataRepo;
  S.cache.clear();
  await loadCore();
  const me = S.users.find(u => u.id === userId);
  if (!me || me.active === false) {
    const err = new Error('Учётная запись отключена. Обратитесь к заведующей.');
    err.status = 'disabled'; throw err;
  }
  S.me = me;
  if (remember !== undefined) store.set('kj-session', { t: token, r: dataRepo, u: userId }, remember);
  enterApp();
}

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const err = $('#loginError'), btn = $('#loginBtn');
  err.textContent = '';
  btn.disabled = true; btn.textContent = 'Проверяю…';
  try {
    if (!AUTH) { const a = await fetchAuth(); if (!a.ok) throw a.error; AUTH = a.data; }
    const entry = AUTH && AUTH.users && AUTH.users[await loginHash($('#loginName').value)];
    let payload = null;
    if (entry) { try { payload = await unseal(entry, $('#loginPass').value); } catch (x) { payload = null; } }
    if (!payload) {
      // файл мог обновиться (новый пароль) — перечитываем один раз
      const a = await fetchAuth();
      if (a.ok && a.data) {
        AUTH = a.data;
        const e2 = AUTH.users && AUTH.users[await loginHash($('#loginName').value)];
        if (e2) { try { payload = await unseal(e2, $('#loginPass').value); } catch (x) { payload = null; } }
      }
    }
    if (!payload) throw new Error('Неверный логин или пароль.');
    await startSession(payload.t, payload.r, payload.u, $('#loginRemember').checked);
    $('#loginPass').value = '';
  } catch (x) {
    console.error(x);
    err.textContent = x.status === 'disabled' ? x.message : humanError(x);
  } finally {
    btn.disabled = false; btn.textContent = 'Войти';
  }
});

$('#recoverLink').onclick = () => openSetup(true);
$('#setupBack').onclick = () => { show('login'); };

let setupRecovery = false;
function openSetup(recovery) {
  setupRecovery = recovery;
  $('#setupTitle').textContent = recovery ? 'Восстановление доступа заведующей' : 'Первоначальная настройка';
  $('#setupHint').textContent = recovery
    ? 'Если заведующая забыла пароль: введите ключ доступа GitHub и логин заведующей, затем задайте новый пароль. Пароли остальных сотрудников не изменятся.'
    : 'Выполняется один раз. Нужен ключ доступа GitHub (токен) с правом записи в оба репозитория — сайта и данных.';
  $('#setupNameField').classList.toggle('hidden', recovery);
  $('#setupBack').classList.toggle('hidden', !recovery);
  $('#setupRepo').value = (AUTH && AUTH.dataRepo) || CONFIG.defaultDataRepo;
  $('#setupError').textContent = '';
  show('setup');
}

$('#setupForm').addEventListener('submit', async e => {
  e.preventDefault();
  const err = $('#setupError'), btn = $('#setupBtn');
  err.textContent = '';
  const repo = $('#setupRepo').value.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/+$/, '').replace(/\.git$/, '');
  const token = $('#setupToken').value.trim();
  const name = $('#setupName').value.trim() || 'Заведующая';
  const login = normLogin($('#setupLogin').value);
  const pass = $('#setupPass').value, pass2 = $('#setupPass2').value;
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo)) { err.textContent = 'Укажите репозиторий в виде владелец/название.'; return; }
  if (!login) { err.textContent = 'Укажите логин.'; return; }
  if (pass.length < 10) { err.textContent = 'Пароль должен быть не короче 10 символов.'; return; }
  if (pass !== pass2) { err.textContent = 'Пароли не совпадают.'; return; }
  btn.disabled = true; btn.textContent = 'Настраиваю…';
  try {
    const gh = new GitHub(token);
    let info;
    try { info = await gh.api('GET', `/repos/${repo}`); } catch (x) {
      if (x.status === 404) throw new Error(`Репозиторий ${repo} не найден, или у ключа нет к нему доступа.`);
      throw x;
    }
    if (!info.private) throw new Error(`Репозиторий ${repo} публичный! Для данных детей он должен быть приватным (Settings → Danger Zone → Change visibility).`);
    try { await gh.api('GET', `/repos/${CONFIG.siteRepo}`); } catch (x) {
      throw new Error(`У ключа нет доступа к репозиторию сайта ${CONFIG.siteRepo}. Добавьте его в настройках ключа.`);
    }
    S.gh = gh; S.token = token; S.dataRepo = repo;
    const existing = await gh.readJSON(repo, 'data/users.json', CONFIG.dataBranch);
    let me;
    if (existing && existing.data && existing.data.users && existing.data.users.length) {
      me = existing.data.users.find(u => normLogin(u.login) === login && u.role === 'admin' && u.active !== false);
      if (!me) throw new Error('В данных уже есть сотрудники, но заведующей с таким логином нет. Укажите существующий логин заведующей.');
      S.users = existing.data.users;
      S.me = me;
      await gh.commit(repo, CONFIG.dataBranch, `${me.name}: восстановление доступа`, [logChange('auth', 'Восстановлен доступ заведующей через ключ GitHub')]);
    } else {
      if (setupRecovery) throw new Error('В репозитории данных ещё нет сотрудников — выполните первоначальную настройку.');
      me = { id: uid(), login, name, role: 'admin', groups: [], active: true, createdAt: nowIso() };
      S.me = me;
      await gh.commit(repo, CONFIG.dataBranch, `${name}: первоначальная настройка`, [
        { path: 'data/users.json', update: d => { d = d || { users: [] }; d.users.push(me); return d; } },
        { path: 'data/groups.json', update: d => d || { groups: [] } },
        { path: 'data/children.json', update: d => d || { children: [] } },
        logChange('setup', 'Первоначальная настройка журнала'),
      ]);
    }
    const sealed = await seal({ t: token, r: repo, u: me.id }, pass);
    const h = await loginHash(login);
    await saveAuth(d => { d.users[h] = sealed; }, gh);
    $('#setupToken').value = ''; $('#setupPass').value = ''; $('#setupPass2').value = '';
    await startSession(token, repo, me.id, false);
    toast('Готово! Теперь можно входить по логину и паролю.');
  } catch (x) {
    console.error(x);
    err.textContent = humanError(x);
  } finally {
    btn.disabled = false; btn.textContent = 'Сохранить и войти';
  }
});

function logout() {
  if (markDirty() && !window.confirm('Есть несохранённые отметки. Всё равно выйти?')) return;
  store.del('kj-session');
  S.gh = null; S.token = null; S.me = null; S.cache.clear();
  S.mark = { groupId: null, date: null, draft: {}, base: {}, key: null };
  $('#loginName').value = ''; $('#loginPass').value = '';
  show('login');
}

/* ================= Каркас приложения ================= */

const VIEWS = [
  { id: 'mark', title: 'Отметить' },
  { id: 'tabel', title: 'Табель' },
  { id: 'lessons', title: 'Занятия' },
  { id: 'stats', title: 'Статистика' },
  { id: 'log', title: 'Журнал действий', admin: true },
  { id: 'admin', title: 'Управление', admin: true },
];

function enterApp() {
  $('#userBtn').textContent = S.me.name + ' ▾';
  renderTabs();
  show('app');
  go(S.view);
}
function renderTabs() {
  $('#tabs').innerHTML = VIEWS.filter(v => !v.admin || isAdmin())
    .map(v => `<button type="button" data-view="${v.id}" class="${v.id === S.view ? 'active' : ''}">${v.title}</button>`).join('');
}
$('#tabs').addEventListener('click', e => {
  const b = e.target.closest('[data-view]');
  if (b) go(b.dataset.view);
});
async function go(view) {
  if (S.view === 'mark' && view !== 'mark' && markDirty() && !window.confirm('Отметки не сохранены. Уйти без сохранения?')) return;
  const v = VIEWS.find(x => x.id === view && (!x.admin || isAdmin())) ? view : 'mark';
  S.view = v;
  renderTabs();
  $('#savebarRoot') && $('#savebarRoot').remove();
  await render();
}
async function render() {
  setView(loadingHtml);
  try {
    if (S.view === 'mark') await renderMark();
    else if (S.view === 'tabel') await renderTabel();
    else if (S.view === 'lessons') await renderLessons();
    else if (S.view === 'stats') await renderStats();
    else if (S.view === 'log') await renderLog();
    else if (S.view === 'admin') renderAdmin();
  } catch (e) {
    console.error(e);
    if (e.status === 401) { toast(humanError(e), true); logout(); return; }
    setView(`<div class="panel"><div class="empty">Ошибка: ${esc(humanError(e))}<br><br><button class="btn" data-act="reload">Повторить</button></div></div>`);
  }
}

$('#userBtn').onclick = () => {
  openModal({
    title: esc(S.me.name),
    body: `<p class="hint" style="margin-top:0">${ROLE[S.me.role] || ''} · логин <b>${esc(S.me.login)}</b></p>
      <div class="actions"><button type="button" class="btn" id="mChangePass">Сменить пароль</button>
      <button type="button" class="btn" id="mRefresh">Обновить данные</button>
      <button type="button" class="btn danger" id="mLogout">Выйти</button></div>`,
    cancelText: 'Закрыть',
  });
  $('#mLogout').onclick = () => { $('#modalRoot').innerHTML = ''; logout(); };
  $('#mRefresh').onclick = async () => { $('#modalRoot').innerHTML = ''; await refreshAll(); };
  $('#mChangePass').onclick = changeOwnPassword;
};

async function refreshAll() {
  showBusy('Обновляю…');
  try { await loadCore(); S.cache.clear(); S.mark.key = null; } catch (e) { toast(humanError(e), true); } finally { hideBusy(); }
  const me = S.users.find(u => u.id === S.me.id);
  if (!me || me.active === false) { toast('Учётная запись отключена.', true); logout(); return; }
  S.me = me;
  renderTabs();
  render();
}

function changeOwnPassword() {
  openModal({
    title: 'Смена пароля',
    body: `<div class="form-grid">
      <div class="field wide"><label>Новый пароль (не короче 10 символов)</label><input name="p1" type="password" minlength="10" required autocomplete="new-password"></div>
      <div class="field wide"><label>Новый пароль ещё раз</label><input name="p2" type="password" minlength="10" required autocomplete="new-password"></div></div>`,
    onOk: async f => {
      const p1 = f.elements.p1.value, p2 = f.elements.p2.value;
      if (p1.length < 10) throw new Error('Пароль должен быть не короче 10 символов.');
      if (p1 !== p2) throw new Error('Пароли не совпадают.');
      showBusy('Сохраняю пароль…');
      try {
        const sealed = await seal({ t: S.token, r: S.dataRepo, u: S.me.id }, p1);
        const h = await loginHash(S.me.login);
        await saveAuth(d => { d.users[h] = sealed; });
        await S.gh.commit(S.dataRepo, CONFIG.dataBranch, `${S.me.name}: смена пароля`, [logChange('password', 'Сменил(а) свой пароль')]);
      } finally { hideBusy(); }
      toast('Пароль изменён. Новый пароль начнёт работать через 1–2 минуты.');
    },
  });
}

/* Глобальные кнопки с data-act */
document.addEventListener('click', e => {
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const fn = ACTIONS[b.dataset.act];
  if (fn) { e.preventDefault(); fn(b.dataset, b); }
});
const ACTIONS = {
  reload: () => render(),
};

window.addEventListener('beforeunload', e => {
  if (markDirty()) { e.preventDefault(); e.returnValue = ''; }
});

/* ================= Отметка посещаемости ================= */

function markDirty() {
  if (!S.mark || !S.mark.key) return false;
  const { draft, base } = S.mark;
  const ids = new Set([...Object.keys(draft), ...Object.keys(base)]);
  for (const id of ids) if ((draft[id] || '') !== (base[id] || '')) return true;
  return false;
}

async function renderMark(force) {
  const groups = myGroups();
  if (!groups.length) {
    setView(`<div class="panel"><div class="empty">${isAdmin() ? 'Групп пока нет. Создайте группу и добавьте детей в разделе «Управление».' : 'Вам пока не назначены группы. Обратитесь к заведующей.'}</div></div>`);
    return;
  }
  const m = S.mark;
  if (!m.groupId || !groups.some(g => g.id === m.groupId)) m.groupId = groups[0].id;
  if (!m.date) m.date = today();
  const att = await loadMonth('attendance', m.date.slice(0, 7), force);
  const day = att[m.date] || {};
  const kids = groupKids(m.groupId);
  const key = m.groupId + '|' + m.date;
  if (m.key !== key || force) {
    m.base = {};
    kids.forEach(c => { if (day[c.id]) m.base[c.id] = day[c.id].s; });
    m.draft = Object.assign({}, m.base);
    m.key = key;
  }
  let last = null;
  kids.forEach(c => { const x = day[c.id]; if (x && (!last || x.at > last.at)) last = x; });

  const wd = WD[weekday(m.date)];
  setView(`
    <div class="panel">
      <div class="toolbar">
        <div class="field grow"><label>Группа</label><select id="mGroup">${groupOptions(m.groupId, groups)}</select></div>
        <div class="field grow"><label>Дата (${wd})</label>
          <div class="datenav"><button class="btn" type="button" data-act="mPrev" aria-label="Предыдущий день">‹</button>
          <input type="date" id="mDate" value="${m.date}">
          <button class="btn" type="button" data-act="mNext" aria-label="Следующий день">›</button>
          ${m.date !== today() ? '<button class="btn" type="button" data-act="mToday">Сегодня</button>' : ''}</div></div>
      </div>
      ${isWeekend(m.date) ? '<div class="notice">Выбран выходной день.</div>' : ''}
      ${last ? `<p class="hint" style="margin:-4px 0 12px">Последнее сохранение: ${esc(userName(last.by))}, ${fmtDateTime(last.at)}</p>` : ''}
      <div class="att-summary" id="mSummary"></div>
      <div class="actions" style="margin-bottom:12px">
        <button class="btn small" type="button" data-act="mAllPresent">Отметить остальных «Был»</button>
        <button class="btn small" type="button" data-act="mReset">Отменить изменения</button>
      </div>
      ${kids.length ? `<div class="att-list" id="mList">${kids.map(markRowHtml).join('')}</div>`
        : `<div class="empty">В группе нет детей.${isAdmin() ? ' Добавьте их в разделе «Управление».' : ''}</div>`}
    </div>`);
  const bar = document.createElement('div');
  bar.id = 'savebarRoot';
  bar.className = 'savebar';
  bar.innerHTML = `<div class="savebar-inner"><span class="status" id="mStatus"></span><button class="btn primary" type="button" id="mSave">Сохранить</button></div>`;
  $('#savebarRoot') && $('#savebarRoot').remove();
  document.body.appendChild(bar);
  $('#mSave').onclick = saveMark;
  $('#mGroup').onchange = e => switchMark({ groupId: e.target.value });
  $('#mDate').onchange = e => { if (e.target.value) switchMark({ date: e.target.value }); };
  const list = $('#mList');
  if (list) list.addEventListener('click', e => {
    const btn = e.target.closest('[data-st]');
    if (!btn) return;
    const row = btn.closest('[data-child]');
    const cid = row.dataset.child, st = btn.dataset.st;
    if (m.draft[cid] === st) delete m.draft[cid]; else m.draft[cid] = st;
    updateMarkRow(row);
    updateMarkSummary();
  });
  updateMarkSummary();
}

function markRowHtml(c) {
  const v = S.mark.draft[c.id] || '';
  return `<div class="att-row ${v ? '' : 'unset'}" data-child="${esc(c.id)}">
    <div class="att-name">${esc(c.name)}</div>
    <div class="seg">${STATUSES.map(s => `<button type="button" data-st="${s.k}" class="st-${s.k} ${v === s.k ? 'on' : ''}" title="${s.label}">${s.short}</button>`).join('')}</div>
  </div>`;
}
function updateMarkRow(row) {
  const v = S.mark.draft[row.dataset.child] || '';
  row.classList.toggle('unset', !v);
  row.querySelectorAll('[data-st]').forEach(b => b.classList.toggle('on', b.dataset.st === v));
}
function updateMarkSummary() {
  const kids = groupKids(S.mark.groupId);
  const counts = { p: 0, a: 0, s: 0, v: 0, o: 0 };
  let unset = 0;
  kids.forEach(c => { const v = S.mark.draft[c.id]; if (v) counts[v]++; else unset++; });
  const el = $('#mSummary');
  if (el) el.innerHTML = `<span class="pill">Всего: ${kids.length}</span>` +
    STATUSES.filter(s => counts[s.k]).map(s => `<span class="pill c-${s.k}">${s.label}: ${counts[s.k]}</span>`).join('') +
    (unset ? `<span class="pill">Не отмечено: ${unset}</span>` : '');
  const st = $('#mStatus'), dirty = markDirty();
  if (st) {
    st.textContent = dirty ? 'Есть несохранённые изменения' : (unset && kids.length ? 'Сохранено. Отмечены не все дети' : 'Всё сохранено');
    st.classList.toggle('dirty', dirty);
  }
  const sv = $('#mSave');
  if (sv) sv.disabled = !dirty;
}
function switchMark(patch) {
  if (markDirty() && !window.confirm('Отметки не сохранены. Перейти без сохранения?')) { render(); return; }
  Object.assign(S.mark, patch);
  S.mark.key = null;
  render();
}
Object.assign(ACTIONS, {
  mPrev: () => switchMark({ date: addDays(S.mark.date, -1) }),
  mNext: () => switchMark({ date: addDays(S.mark.date, 1) }),
  mToday: () => switchMark({ date: today() }),
  mAllPresent: () => {
    groupKids(S.mark.groupId).forEach(c => { if (!S.mark.draft[c.id]) S.mark.draft[c.id] = 'p'; });
    document.querySelectorAll('#mList [data-child]').forEach(updateMarkRow);
    updateMarkSummary();
  },
  mReset: () => {
    S.mark.draft = Object.assign({}, S.mark.base);
    document.querySelectorAll('#mList [data-child]').forEach(updateMarkRow);
    updateMarkSummary();
  },
});

async function saveMark() {
  const m = S.mark;
  const gid = m.groupId, date = m.date;
  const kids = groupKids(gid);
  const wanted = {};
  kids.forEach(c => { if ((m.draft[c.id] || '') !== (m.base[c.id] || '')) wanted[c.id] = m.draft[c.id] || ''; });
  if (!Object.keys(wanted).length) { toast('Нет изменений'); return; }
  const ym = date.slice(0, 7);
  try {
    await saveData('attendance', [{
      path: monthPath('attendance', ym),
      update: (d, ctx) => {
        d = d || {};
        const day = d[date] = d[date] || {};
        ctx.added = []; ctx.changed = [];
        for (const [cid, st] of Object.entries(wanted)) {
          const prev = day[cid] ? day[cid].s : '';
          if (prev === st) continue;
          if (st) day[cid] = { s: st, g: gid, by: S.me.id, at: nowIso() };
          else delete day[cid];
          (prev ? ctx.changed : ctx.added).push({ cid, prev, st });
        }
        if (!Object.keys(day).length) delete d[date];
        if (!ctx.added.length && !ctx.changed.length) return undefined;
        return d;
      },
    }], ctx => attendanceLogText(gid, date, ctx), 'Сохраняю отметки…');
    toast('Отметки сохранены');
    m.key = null;
    render();
  } catch (e) {
    console.error(e);
    toast(humanError(e), true);
  }
}
function attendanceLogText(gid, date, ctx) {
  const parts = [];
  const added = ctx.added || [], changed = ctx.changed || [];
  if (added.length) {
    const cnt = {};
    added.forEach(x => { cnt[x.st] = (cnt[x.st] || 0) + 1; });
    parts.push('отмечено ' + added.length + ' (' + STATUSES.filter(s => cnt[s.k]).map(s => s.label.toLowerCase() + ' — ' + cnt[s.k]).join(', ') + ')');
  }
  if (changed.length) {
    parts.push('исправлено: ' + changed.map(x => (childById(x.cid) || { name: '?' }).name + ': ' +
      (ST[x.prev] ? ST[x.prev].label : '—') + ' → ' + (ST[x.st] ? ST[x.st].label : 'без отметки')).join('; '));
  }
  return `Посещаемость, «${groupName(gid)}», ${fmtDate(date)}: ${parts.join('; ') || 'без изменений'}`;
}

/* ================= Табель ================= */

function monthGroupToolbar(groupsAll) {
  const groups = myGroups(true);
  if (S.filters.groupId && !groups.some(g => g.id === S.filters.groupId)) S.filters.groupId = '';
  if (!groupsAll && !S.filters.groupId && groups.length) S.filters.groupId = (myGroups()[0] || groups[0]).id;
  return `<div class="toolbar">
    <div class="field"><label>Месяц</label><input type="month" id="fMonth" value="${S.filters.month}"></div>
    <div class="field grow"><label>Группа</label><select id="fGroup">${groupOptions(S.filters.groupId, groups, groupsAll ? 'Все мои группы' : '')}</select></div>
  </div>`;
}
function bindMonthGroup() {
  const fm = $('#fMonth'), fg = $('#fGroup');
  if (fm) fm.onchange = e => { if (e.target.value) { S.filters.month = e.target.value; render(); } };
  if (fg) fg.onchange = e => { S.filters.groupId = e.target.value; render(); };
}

async function renderTabel() {
  if (!myGroups(true).length) { setView('<div class="panel"><div class="empty">Нет доступных групп.</div></div>'); return; }
  const tb = monthGroupToolbar(false);
  const ym = S.filters.month, gid = S.filters.groupId;
  const att = await loadMonth('attendance', ym);
  const { rows, total } = groupStats(att, gid);
  const n = daysInMonth(ym);
  const dates = Array.from({ length: n }, (_, i) => ym + '-' + pad(i + 1));
  const head = [th('ФИО', 'name')].concat(dates.map(d =>
    `<th class="day ${isWeekend(d) ? 'we' : ''}" data-act="gotoDay" data-date="${d}" title="Открыть отметку за ${fmtDate(d)}">${Number(d.slice(8))}<br><span class="muted">${WD[weekday(d)]}</span></th>`))
    .concat([th('Был', 'num'), th('Проп.', 'num'), th('Б', 'num'), th('%', 'num')]);
  const { marks } = groupStats(att, gid);
  const body = rows.map(r => `<tr><td class="name" title="${esc(r.child.name)}">${esc(r.child.name)}</td>` +
    dates.map(d => { const mk = marks[r.child.id] && marks[r.child.id][d]; return `<td class="${isWeekend(d) ? 'we' : ''} ${mk ? 'c-' + mk.s : ''}">${mk && ST[mk.s] ? ST[mk.s].code : ''}</td>`; }).join('') +
    `<td class="num">${r.c.p}</td><td class="num">${r.c.missed}</td><td class="num">${r.c.s}</td><td class="num">${pctText(r.c.pct)}</td></tr>`);
  setView(`<div class="panel">
    <div class="panel-head"><div><h2>Табель посещаемости</h2><p class="hint">${esc(groupName(gid))} · ${monthTitle(ym)}. Нажмите на число, чтобы открыть отметку за этот день.</p></div>
      <div class="actions"><button class="btn primary" data-act="exportTabel">⇩ Excel: эта группа</button>${myGroups(true).length > 1 ? '<button class="btn" data-act="exportTabelAll">⇩ Excel: все группы</button>' : ''}</div></div>
    ${tb}
    <div class="stats">
      <div class="stat"><div class="label">Посещаемость</div><div class="value">${pctText(total.pct)}</div></div>
      <div class="stat"><div class="label">Дней с отметками</div><div class="value">${total.days}</div></div>
      <div class="stat"><div class="label">В среднем детей в день</div><div class="value">${total.avg ?? '—'}</div></div>
      <div class="stat"><div class="label">Пропущено по болезни</div><div class="value">${total.s}</div></div>
    </div>
    ${table(head, body, 'Нет детей и отметок за этот месяц', 'tabel')}
    <div class="legend">${STATUSES.map(s => `<span><b class="c-${s.k}">${s.code}</b> — ${s.label.toLowerCase()}</span>`).join('')}</div>
  </div>`);
  bindMonthGroup();
}
Object.assign(ACTIONS, {
  gotoDay: d => { S.mark.date = d.date; if (S.filters.groupId) S.mark.groupId = S.filters.groupId; S.mark.key = null; go('mark'); },
  exportTabel: () => exportTabel([S.filters.groupId]),
  exportTabelAll: () => exportTabel(myGroups(true).map(g => g.id)),
});

async function exportTabel(gids) {
  showBusy('Готовлю Excel…');
  try {
    const XLSX = await loadXLSX();
    const ym = S.filters.month;
    const att = await loadMonth('attendance', ym);
    const lessons = await loadMonth('lessons', ym);
    const n = daysInMonth(ym);
    const dates = Array.from({ length: n }, (_, i) => ym + '-' + pad(i + 1));
    const wb = XLSX.utils.book_new();
    const used = new Set();
    const summary = [['Сводка посещаемости — ' + monthTitle(ym)], [],
      ['Группа', 'Детей в группе', 'Дней с отметками', 'Был', 'Не был', 'Болезнь', 'Отпуск', 'Уваж. причина', 'Всего отметок', 'Посещаемость, %', 'В среднем в день']];
    const sheets = [];
    for (const gid of gids) {
      const { rows, total, marks } = groupStats(att, gid);
      summary.push([groupName(gid), total.kids, total.days, total.p, total.a, total.s, total.v, total.o, total.marked, total.pct ?? '', total.avg ?? '']);
      const aoa = [[`Табель посещаемости — ${groupName(gid)} — ${monthTitle(ym)}`], [],
        ['№', 'ФИО'].concat(dates.map(d => Number(d.slice(8)))).concat(['Был', 'Не был', 'Болезнь', 'Отпуск', 'Уваж.', 'Пропущено всего', 'Посещаемость, %'])];
      rows.forEach((r, i) => {
        aoa.push([i + 1, r.child.name]
          .concat(dates.map(d => { const mk = marks[r.child.id] && marks[r.child.id][d]; return mk && ST[mk.s] ? ST[mk.s].code : ''; }))
          .concat([r.c.p, r.c.a, r.c.s, r.c.v, r.c.o, r.c.missed, r.c.pct ?? '']));
      });
      const perDay = dates.map(d => { let c = 0; rows.forEach(r => { const mk = marks[r.child.id] && marks[r.child.id][d]; if (mk && mk.s === 'p') c++; }); return c || ''; });
      aoa.push(['', 'Присутствовало'].concat(perDay).concat([total.p, total.a, total.s, total.v, total.o, total.marked - total.p, total.pct ?? '']));
      aoa.push([]);
      aoa.push(['', 'Обозначения: ' + STATUSES.map(s => s.code + ' — ' + s.label.toLowerCase()).join(', ')]);
      sheets.push({ name: groupName(gid), aoa, n });
    }
    addSheet(XLSX, wb, used, 'Сводка', summary, { cols: [26, 14, 16, 8, 8, 9, 8, 13, 13, 15, 15], merges: [{ s: { r: 0, c: 0 }, e: { r: 0, c: 10 } }] });
    sheets.forEach(s => addSheet(XLSX, wb, used, s.name, s.aoa, {
      cols: [4, 28].concat(Array(s.n).fill(3.5)).concat([6, 7, 8, 7, 6, 15, 15]),
      merges: [{ s: { r: 0, c: 0 }, e: { r: 0, c: Math.min(s.n + 1, 20) } }],
    }));
    const ls = (lessons.lessons || []).filter(l => gids.includes(l.groupId)).sort((a, b) => a.date.localeCompare(b.date));
    if (ls.length) {
      addSheet(XLSX, wb, used, 'Занятия', [['Дата', 'Группа', 'Занятие', 'Педагог', 'Минут', 'Статус', 'Детей присутствовало', 'Комментарий']]
        .concat(ls.map(l => [fmtDate(l.date), groupName(l.groupId), l.title, l.teacher, l.minutes ?? '', LESSON_STATUS[l.status] || l.status, presentCount(att, l.groupId, l.date) ?? '', l.note || ''])),
      { cols: [11, 22, 30, 22, 7, 14, 12, 30] });
    }
    const fname = `Табель_${ym}${gids.length === 1 ? '_' + groupName(gids[0]).replace(/[\\/:*?"<>|]/g, '') : ''}.xlsx`;
    downloadWorkbook(XLSX, wb, fname);
    S.gh.commit(S.dataRepo, CONFIG.dataBranch, `${S.me.name}: выгрузка Excel`, [logChange('export', `Выгрузка табеля в Excel: ${monthTitle(ym)}, ${gids.map(groupName).join(', ')}`)]).catch(e => console.warn(e));
    toast('Файл Excel скачан');
  } catch (e) {
    console.error(e); toast(humanError(e), true);
  } finally { hideBusy(); }
}
function presentCount(att, gid, date) {
  const day = att[date];
  if (!day) return null;
  let c = 0, any = false;
  for (const [cid, m] of Object.entries(day)) {
    const child = childById(cid);
    if ((m.g || (child && child.groupId)) !== gid) continue;
    any = true;
    if (m.s === 'p') c++;
  }
  return any ? c : null;
}

/* ================= Занятия ================= */

async function renderLessons() {
  if (!myGroups(true).length) { setView('<div class="panel"><div class="empty">Нет доступных групп.</div></div>'); return; }
  const tb = monthGroupToolbar(true);
  const ym = S.filters.month;
  const [data, att] = await Promise.all([loadMonth('lessons', ym), loadMonth('attendance', ym)]);
  const allowed = new Set(myGroups(true).map(g => g.id));
  const list = (data.lessons || []).filter(l => allowed.has(l.groupId) && (!S.filters.groupId || l.groupId === S.filters.groupId))
    .sort((a, b) => b.date.localeCompare(a.date) || (b.at || '').localeCompare(a.at || ''));
  const badge = s => `<span class="badge ${s === 'done' ? 'green' : s === 'cancelled' ? 'red' : 'amber'}">${LESSON_STATUS[s] || esc(s)}</span>`;
  const rows = list.map(l => `<tr>
    <td class="nowrap">${fmtDate(l.date)}</td>
    <td><b>${esc(l.title)}</b>${l.note ? `<br><span class="muted">${esc(l.note)}</span>` : ''}</td>
    <td>${esc(groupName(l.groupId))}</td>
    <td>${esc(l.teacher || '—')}</td>
    <td class="num">${l.minutes ? l.minutes + ' мин' : '—'}</td>
    <td class="num">${presentCount(att, l.groupId, l.date) ?? '—'}</td>
    <td>${badge(l.status)}</td>
    <td class="nowrap"><button class="btn small" data-act="editLesson" data-id="${esc(l.id)}">Изменить</button> <button class="btn small danger" data-act="delLesson" data-id="${esc(l.id)}">Удалить</button></td></tr>`);
  setView(`<div class="panel">
    <div class="panel-head"><div><h2>Журнал занятий</h2><p class="hint">${monthTitle(ym)}. «Детей» — сколько было в этот день по отметкам посещаемости.</p></div>
      <button class="btn primary" data-act="addLesson">＋ Занятие</button></div>
    ${tb}
    ${table([th('Дата'), th('Занятие'), th('Группа'), th('Педагог'), th('Длит.', 'num'), th('Детей', 'num'), th('Статус'), th('')], rows, 'Занятий за этот месяц нет')}
  </div>`);
  bindMonthGroup();
}
Object.assign(ACTIONS, {
  addLesson: () => lessonModal(null),
  editLesson: d => lessonModal(d.id),
  delLesson: async d => {
    const ym = S.filters.month;
    const l = ((await loadMonth('lessons', ym)).lessons || []).find(x => x.id === d.id);
    if (!l || !(await confirmModal('Удалить занятие?', `«${esc(l.title)}», ${fmtDate(l.date)}, ${esc(groupName(l.groupId))}`, 'Удалить'))) return;
    try {
      await saveData('lesson', [{ path: monthPath('lessons', ym), update: x => { x = x || { lessons: [] }; x.lessons = x.lessons.filter(y => y.id !== l.id); return x; } }],
        `Удалено занятие «${l.title}», ${fmtDate(l.date)}, «${groupName(l.groupId)}»`);
      toast('Занятие удалено'); render();
    } catch (e) { toast(humanError(e), true); }
  },
});

async function lessonModal(id) {
  const ym = S.filters.month;
  const data = await loadMonth('lessons', ym);
  const old = id ? (data.lessons || []).find(l => l.id === id) : null;
  if (id && !old) return;
  const groups = myGroups();
  if (!groups.length) { toast('Нет доступных групп', true); return; }
  const l = old || { date: ym === thisMonth() ? today() : ym + '-01', groupId: S.filters.groupId || groups[0].id, title: '', teacher: S.me.name, minutes: 20, status: 'done', note: '' };
  const gsel = old && !groups.some(g => g.id === old.groupId) ? groups.concat([groupById(old.groupId)].filter(Boolean)) : groups;
  openModal({
    title: old ? 'Изменить занятие' : 'Новое занятие',
    body: `<div class="form-grid">
      <div class="field"><label>Дата</label><input name="date" type="date" required value="${esc(l.date)}"></div>
      <div class="field"><label>Группа</label><select name="groupId" required>${groupOptions(l.groupId, gsel)}</select></div>
      <div class="field wide"><label>Занятие / тема</label><input name="title" required maxlength="150" value="${esc(l.title)}" placeholder="Например, развитие речи"></div>
      <div class="field"><label>Педагог</label><input name="teacher" maxlength="100" value="${esc(l.teacher)}"></div>
      <div class="field"><label>Длительность, минут</label><input name="minutes" type="number" min="0" max="600" value="${esc(l.minutes ?? '')}"></div>
      <div class="field wide"><label>Статус</label><select name="status">${Object.entries(LESSON_STATUS).map(([k, v]) => `<option value="${k}" ${l.status === k ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
      <div class="field wide"><label>Комментарий</label><textarea name="note" maxlength="500">${esc(l.note || '')}</textarea></div>
    </div>`,
    onOk: async f => {
      const v = {
        date: fval(f, 'date'), groupId: fval(f, 'groupId'), title: fval(f, 'title'), teacher: fval(f, 'teacher'),
        minutes: fval(f, 'minutes') === '' ? null : Number(fval(f, 'minutes')), status: fval(f, 'status'), note: fval(f, 'note'),
      };
      if (!v.date || !v.title) throw new Error('Заполните дату и название.');
      const newYm = v.date.slice(0, 7);
      const lid = old ? old.id : uid();
      const rec = Object.assign({}, old || {}, v, { id: lid, by: S.me.id, at: nowIso() });
      const changes = [];
      if (old && old.date.slice(0, 7) !== newYm) {
        changes.push({ path: monthPath('lessons', old.date.slice(0, 7)), update: x => { x = x || { lessons: [] }; x.lessons = x.lessons.filter(y => y.id !== lid); return x; } });
      }
      changes.push({ path: monthPath('lessons', newYm), update: x => {
        x = x || { lessons: [] };
        const i = x.lessons.findIndex(y => y.id === lid);
        if (i >= 0) x.lessons[i] = rec; else x.lessons.push(rec);
        return x;
      } });
      await saveData('lesson', changes, `${old ? 'Изменено' : 'Добавлено'} занятие «${v.title}», ${fmtDate(v.date)}, «${groupName(v.groupId)}», ${LESSON_STATUS[v.status].toLowerCase()}`);
      S.filters.month = newYm;
      toast('Занятие сохранено');
      render();
    },
  });
}

/* ================= Статистика ================= */

async function renderStats() {
  if (!myGroups(true).length) { setView('<div class="panel"><div class="empty">Нет доступных групп.</div></div>'); return; }
  const tb = monthGroupToolbar(true);
  const ym = S.filters.month;
  const att = await loadMonth('attendance', ym);
  const gids = S.filters.groupId ? [S.filters.groupId] : myGroups().map(g => g.id);
  const all = { p: 0, marked: 0, s: 0 };
  const groupRows = gids.map(gid => {
    const st = groupStats(att, gid);
    all.p += st.total.p; all.marked += st.total.marked; all.s += st.total.s;
    return `<tr><td>${esc(groupName(gid))}</td><td class="num">${st.total.kids}</td><td class="num">${st.total.days}</td><td class="num">${st.total.avg ?? '—'}</td>
      <td class="num">${st.total.s}</td><td class="num">${st.total.a}</td><td style="min-width:120px">${pctText(st.total.pct)}<div class="bar"><span style="width:${st.total.pct || 0}%"></span></div></td></tr>`;
  });
  let childPart = '';
  if (S.filters.groupId) {
    const { rows } = groupStats(att, S.filters.groupId);
    const sorted = rows.slice().sort((a, b) => (a.c.pct ?? 101) - (b.c.pct ?? 101));
    childPart = `<div class="panel"><div class="panel-head"><div><h2>По детям</h2><p class="hint">Сначала — с наименьшей посещаемостью</p></div></div>` +
      table([th('Ребёнок'), th('Был', 'num'), th('Не был', 'num'), th('Болезнь', 'num'), th('Отпуск', 'num'), th('Уваж.', 'num'), th('Посещаемость')],
        sorted.map(r => `<tr><td>${esc(r.child.name)}</td><td class="num">${r.c.p}</td><td class="num">${r.c.a}</td><td class="num">${r.c.s}</td><td class="num">${r.c.v}</td><td class="num">${r.c.o}</td>
          <td style="min-width:120px">${pctText(r.c.pct)}<div class="bar"><span style="width:${r.c.pct || 0}%"></span></div></td></tr>`), 'Нет данных') + '</div>';
  }
  setView(`<div class="panel">
    <div class="panel-head"><div><h2>Статистика посещаемости</h2><p class="hint">${monthTitle(ym)}. Посещаемость = «был» / все отметки.</p></div>
      <button class="btn" data-act="${S.filters.groupId ? 'exportTabel' : 'exportTabelAll'}">⇩ Excel</button></div>
    ${tb}
    <div class="stats">
      <div class="stat"><div class="label">Посещаемость</div><div class="value">${pctText(pct(all.p, all.marked))}</div></div>
      <div class="stat"><div class="label">Всего посещений</div><div class="value">${all.p}</div></div>
      <div class="stat"><div class="label">Пропуски по болезни</div><div class="value">${all.s}</div></div>
    </div>
    ${table([th('Группа'), th('Детей', 'num'), th('Дней', 'num'), th('В среднем в день', 'num'), th('Болезнь', 'num'), th('Не был', 'num'), th('Посещаемость')], groupRows, 'Нет групп')}
  </div>${childPart}`);
  bindMonthGroup();
}

/* ================= Журнал действий ================= */

async function renderLog() {
  const ym = S.filters.month;
  const data = await loadMonth('log', ym, true);
  const q = S.filters.q.toLowerCase();
  const list = (data.entries || []).filter(e => (!S.filters.user || e.by === S.filters.user) && (!q || (e.text || '').toLowerCase().includes(q)))
    .slice().sort((a, b) => b.at.localeCompare(a.at));
  const users = S.users.slice().sort(byName);
  setView(`<div class="panel">
    <div class="panel-head"><div><h2>Журнал действий</h2><p class="hint">Кто, когда и что сделал. Полная история изменений также хранится в репозитории данных на GitHub.</p></div>
      <button class="btn" data-act="exportLog">⇩ Excel</button></div>
    <div class="toolbar">
      <div class="field"><label>Месяц</label><input type="month" id="fMonth" value="${ym}"></div>
      <div class="field"><label>Сотрудник</label><select id="fUser"><option value="">Все</option>${users.map(u => `<option value="${esc(u.id)}" ${u.id === S.filters.user ? 'selected' : ''}>${esc(u.name)}</option>`).join('')}</select></div>
      <div class="field grow"><label>Поиск</label><input id="fQ" value="${esc(S.filters.q)}" placeholder="Например, фамилия ребёнка"></div>
    </div>
    ${list.length ? `<div class="log-list">${list.map(e => `<div class="log-item"><div class="log-meta">${fmtDateTime(e.at)} · <b>${esc(e.name)}</b></div><div>${esc(e.text)}</div></div>`).join('')}</div>` : '<div class="empty">Записей нет</div>'}
  </div>`);
  $('#fMonth').onchange = e => { if (e.target.value) { S.filters.month = e.target.value; render(); } };
  $('#fUser').onchange = e => { S.filters.user = e.target.value; render(); };
  let t;
  $('#fQ').oninput = e => { clearTimeout(t); t = setTimeout(() => { S.filters.q = e.target.value; render().then(() => { const i = $('#fQ'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 400); };
}
ACTIONS.exportLog = async () => {
  showBusy('Готовлю Excel…');
  try {
    const XLSX = await loadXLSX();
    const ym = S.filters.month;
    const data = await loadMonth('log', ym);
    const list = (data.entries || []).filter(e => !S.filters.user || e.by === S.filters.user).slice().sort((a, b) => a.at.localeCompare(b.at));
    const wb = XLSX.utils.book_new();
    addSheet(XLSX, wb, new Set(), 'Журнал действий', [['Дата и время', 'Сотрудник', 'Действие']].concat(list.map(e => [fmtDateTime(e.at), e.name, e.text])), { cols: [17, 26, 100] });
    downloadWorkbook(XLSX, wb, `Журнал_действий_${ym}.xlsx`);
    toast('Файл Excel скачан');
  } catch (e) { toast(humanError(e), true); } finally { hideBusy(); }
};

/* ================= Управление ================= */

function renderAdmin() {
  const tabs = [['children', 'Дети'], ['groups', 'Группы'], ['users', 'Сотрудники'], ['key', 'Ключ GitHub']];
  let html = `<div class="subtabs">${tabs.map(([k, t]) => `<button type="button" data-act="adminTab" data-tab="${k}" class="${S.adminTab === k ? 'active' : ''}">${t}</button>`).join('')}</div>`;
  if (S.adminTab === 'children') html += adminChildren();
  else if (S.adminTab === 'groups') html += adminGroups();
  else if (S.adminTab === 'users') html += adminUsers();
  else html += adminKey();
  setView(html);
  const fg = $('#acGroup');
  if (fg) fg.onchange = e => { S.filters.groupId = e.target.value; render(); };
}
ACTIONS.adminTab = d => { S.adminTab = d.tab; render(); };

function adminChildren() {
  const groups = S.groups.slice().sort(byName);
  const gid = S.filters.groupId;
  const list = S.children.filter(c => !gid || c.groupId === gid).sort((a, b) => (a.archived ? 1 : 0) - (b.archived ? 1 : 0) || byName(a, b));
  return `<div class="panel">
    <div class="panel-head"><div><h2>Дети</h2><p class="hint">Совет: можно вносить «Иванов М.» вместо полного ФИО.</p></div>
      <div class="actions"><button class="btn" data-act="bulkChildren">＋ Списком</button><button class="btn primary" data-act="addChild">＋ Ребёнок</button></div></div>
    ${groups.length ? '' : '<div class="notice">Сначала создайте группу на вкладке «Группы».</div>'}
    <div class="toolbar"><div class="field grow"><label>Группа</label><select id="acGroup">${groupOptions(gid, groups, 'Все группы')}</select></div></div>
    ${table([th('Ребёнок'), th('Группа'), th('Дата рождения'), th('Статус'), th('')], list.map(c => `<tr>
      <td>${esc(c.name)}${c.note ? `<br><span class="muted">${esc(c.note)}</span>` : ''}</td><td>${esc(groupName(c.groupId))}</td><td class="nowrap">${c.birth ? fmtDate(c.birth) : '—'}</td>
      <td>${c.archived ? '<span class="badge">Выбыл</span>' : '<span class="badge green">Посещает</span>'}</td>
      <td class="nowrap"><button class="btn small" data-act="editChild" data-id="${esc(c.id)}">Изменить</button></td></tr>`), 'Детей пока нет')}
  </div>`;
}
Object.assign(ACTIONS, {
  addChild: () => childModal(null),
  editChild: d => childModal(d.id),
  bulkChildren: () => {
    const groups = S.groups.filter(g => !g.archived).sort(byName);
    if (!groups.length) { toast('Сначала создайте группу', true); return; }
    openModal({
      title: 'Добавить детей списком',
      body: `<div class="form-grid">
        <div class="field wide"><label>Группа</label><select name="groupId">${groupOptions(S.filters.groupId || groups[0].id, groups)}</select></div>
        <div class="field wide"><label>Каждый ребёнок с новой строки</label><textarea name="names" rows="10" required placeholder="Иванов М.&#10;Петрова А.&#10;…"></textarea></div></div>`,
      onOk: async f => {
        const gid = fval(f, 'groupId');
        const names = f.elements.names.value.split('\n').map(s => s.trim()).filter(Boolean);
        if (!names.length) throw new Error('Список пуст.');
        const recs = names.map(n => ({ id: uid() + Math.random().toString(36).slice(2, 5), name: n.slice(0, 160), groupId: gid, archived: false, createdAt: nowIso() }));
        await saveData('children', [{ path: 'data/children.json', update: d => { d = d || { children: [] }; d.children.push(...recs); return d; } }],
          `Добавлено детей в «${groupName(gid)}»: ${recs.length} (${names.join(', ')})`);
        toast('Добавлено: ' + recs.length); render();
      },
    });
  },
});

function childModal(id) {
  const old = id ? childById(id) : null;
  const groups = S.groups.filter(g => !g.archived || (old && g.id === old.groupId)).sort(byName);
  if (!groups.length) { toast('Сначала создайте группу', true); return; }
  const c = old || { name: '', groupId: S.filters.groupId || groups[0].id, birth: '', note: '', archived: false };
  openModal({
    title: old ? 'Изменить данные ребёнка' : 'Добавить ребёнка',
    body: `<div class="form-grid">
      <div class="field wide"><label>Имя / ФИО</label><input name="name" required maxlength="160" value="${esc(c.name)}"></div>
      <div class="field"><label>Группа</label><select name="groupId">${groupOptions(c.groupId, groups)}</select></div>
      <div class="field"><label>Дата рождения (необязательно)</label><input name="birth" type="date" value="${esc(c.birth || '')}"></div>
      <div class="field wide"><label>Примечание</label><input name="note" maxlength="300" value="${esc(c.note || '')}"></div>
      ${old ? `<label class="check wide"><input type="checkbox" name="archived" ${c.archived ? 'checked' : ''}> Выбыл (не показывать в отметках; история сохранится)</label>` : ''}
    </div>`,
    onOk: async f => {
      const v = { name: fval(f, 'name'), groupId: fval(f, 'groupId'), birth: fval(f, 'birth'), note: fval(f, 'note'), archived: !!(f.elements.archived && f.elements.archived.checked) };
      if (!v.name) throw new Error('Укажите имя.');
      const cid = old ? old.id : uid();
      const notes = [];
      if (old) {
        if (old.name !== v.name) notes.push(`имя: ${old.name} → ${v.name}`);
        if (old.groupId !== v.groupId) notes.push(`группа: ${groupName(old.groupId)} → ${groupName(v.groupId)}`);
        if (!!old.archived !== v.archived) notes.push(v.archived ? 'отмечен как выбывший' : 'снова посещает');
        if ((old.birth || '') !== v.birth) notes.push('дата рождения');
        if ((old.note || '') !== v.note) notes.push('примечание');
        if (!notes.length) return;
      }
      await saveData('children', [{ path: 'data/children.json', update: d => {
        d = d || { children: [] };
        const i = d.children.findIndex(x => x.id === cid);
        if (i >= 0) Object.assign(d.children[i], v); else d.children.push(Object.assign({ id: cid, createdAt: nowIso() }, v));
        return d;
      } }], old ? `Изменён ребёнок ${old.name}: ${notes.join(', ')}` : `Добавлен ребёнок ${v.name} в «${groupName(v.groupId)}»`);
      toast('Сохранено'); render();
    },
  });
}

function adminGroups() {
  const list = S.groups.slice().sort((a, b) => (a.archived ? 1 : 0) - (b.archived ? 1 : 0) || byName(a, b));
  return `<div class="panel">
    <div class="panel-head"><div><h2>Группы</h2></div><button class="btn primary" data-act="addGroup">＋ Группа</button></div>
    ${table([th('Группа'), th('Детей', 'num'), th('Воспитатели'), th('Статус'), th('')], list.map(g => `<tr>
      <td><b>${esc(g.name)}</b></td><td class="num">${groupKids(g.id).length}</td>
      <td>${esc(S.users.filter(u => u.active !== false && u.role === 'teacher' && (u.groups || []).includes(g.id)).map(u => u.name).join(', ') || '—')}</td>
      <td>${g.archived ? '<span class="badge">Архив</span>' : '<span class="badge green">Активна</span>'}</td>
      <td><button class="btn small" data-act="editGroup" data-id="${esc(g.id)}">Изменить</button></td></tr>`), 'Групп пока нет')}
  </div>`;
}
Object.assign(ACTIONS, {
  addGroup: () => groupModal(null),
  editGroup: d => groupModal(d.id),
});
function groupModal(id) {
  const old = id ? groupById(id) : null;
  openModal({
    title: old ? 'Изменить группу' : 'Новая группа',
    body: `<div class="form-grid"><div class="field wide"><label>Название</label><input name="name" required maxlength="80" value="${esc(old ? old.name : '')}" placeholder="Например, «Солнышко» (младшая)"></div>
      ${old ? `<label class="check wide"><input type="checkbox" name="archived" ${old.archived ? 'checked' : ''}> В архиве (скрыть из отметок)</label>` : ''}</div>`,
    onOk: async f => {
      const name = fval(f, 'name');
      const archived = !!(f.elements.archived && f.elements.archived.checked);
      if (!name) throw new Error('Укажите название.');
      if (S.groups.some(g => g.id !== id && g.name.toLowerCase() === name.toLowerCase())) throw new Error('Группа с таким названием уже есть.');
      const gid = old ? old.id : uid();
      if (old && old.name === name && !!old.archived === archived) return;
      await saveData('groups', [{ path: 'data/groups.json', update: d => {
        d = d || { groups: [] };
        const i = d.groups.findIndex(x => x.id === gid);
        if (i >= 0) Object.assign(d.groups[i], { name, archived }); else d.groups.push({ id: gid, name, archived: false, createdAt: nowIso() });
        return d;
      } }], old ? `Изменена группа «${old.name}»${old.name !== name ? ' → «' + name + '»' : ''}${!!old.archived !== archived ? (archived ? ', перенесена в архив' : ', восстановлена из архива') : ''}` : `Создана группа «${name}»`);
      toast('Сохранено'); render();
    },
  });
}

function adminUsers() {
  const list = S.users.slice().sort((a, b) => (a.active === false ? 1 : 0) - (b.active === false ? 1 : 0) || byName(a, b));
  return `<div class="panel">
    <div class="panel-head"><div><h2>Сотрудники</h2><p class="hint">У каждого свой логин и пароль. Все действия видны в журнале.</p></div>
      <button class="btn primary" data-act="addUser">＋ Сотрудник</button></div>
    ${table([th('Имя'), th('Логин'), th('Роль'), th('Группы'), th('Статус'), th('')], list.map(u => `<tr>
      <td><b>${esc(u.name)}</b>${u.id === S.me.id ? ' <span class="muted">(вы)</span>' : ''}</td><td>${esc(u.login)}</td><td>${ROLE[u.role] || u.role}</td>
      <td>${u.role === 'admin' ? 'все' : esc((u.groups || []).map(groupName).join(', ') || '—')}</td>
      <td>${u.active === false ? '<span class="badge red">Отключён</span>' : '<span class="badge green">Активен</span>'}</td>
      <td class="nowrap"><button class="btn small" data-act="editUser" data-id="${esc(u.id)}">Изменить</button>
        ${u.active !== false && u.id !== S.me.id ? `<button class="btn small" data-act="resetPass" data-id="${esc(u.id)}">Новый пароль</button>` : ''}</td></tr>`), 'Сотрудников нет')}
  </div>`;
}
Object.assign(ACTIONS, {
  addUser: () => userModal(null),
  editUser: d => userModal(d.id),
  resetPass: async d => {
    const u = S.users.find(x => x.id === d.id);
    if (!u || !(await confirmModal('Выдать новый пароль?', `Старый пароль сотрудника <b>${esc(u.name)}</b> перестанет работать.`, 'Выдать'))) return;
    try {
      const password = genPassword();
      await setUserPassword(u, password);
      await S.gh.commit(S.dataRepo, CONFIG.dataBranch, `${S.me.name}: новый пароль`, [logChange('users', `Выдан новый пароль сотруднику ${u.name}`)]);
      openModal({ title: 'Новый пароль', body: credentialsHtml([{ name: u.name, login: u.login, password }]), cancelText: 'Готово' });
    } catch (e) { toast(humanError(e), true); }
  },
});

async function setUserPassword(u, password) {
  showBusy('Шифрую и сохраняю…');
  try {
    const sealed = await seal({ t: S.token, r: S.dataRepo, u: u.id }, password);
    const h = await loginHash(u.login);
    await saveAuth(d => { d.users[h] = sealed; });
  } finally { hideBusy(); }
}

function userModal(id) {
  const old = id ? S.users.find(u => u.id === id) : null;
  const u = old || { name: '', login: '', role: 'teacher', groups: [], active: true };
  const groups = S.groups.filter(g => !g.archived || (u.groups || []).includes(g.id)).sort(byName);
  const self = old && old.id === S.me.id;
  const m = openModal({
    title: old ? 'Изменить сотрудника' : 'Новый сотрудник',
    body: `<div class="form-grid">
      <div class="field wide"><label>Имя (как в журнале)</label><input name="name" required maxlength="100" value="${esc(u.name)}" placeholder="Например, Анна Петровна"></div>
      <div class="field"><label>Логин${old ? ' (не меняется)' : ''}</label><input name="login" required maxlength="40" autocapitalize="none" spellcheck="false" value="${esc(u.login)}" ${old ? 'disabled' : ''} placeholder="например, anna"></div>
      <div class="field"><label>Роль</label><select name="role" ${self ? 'disabled' : ''}>${Object.entries(ROLE).map(([k, v]) => `<option value="${k}" ${u.role === k ? 'selected' : ''}>${v}</option>`).join('')}</select></div>
      <div class="field wide" id="uGroupsField"><label>Группы воспитателя</label><div class="checks">${groups.length ? groups.map(g => `<label class="check"><input type="checkbox" name="g" value="${esc(g.id)}" ${(u.groups || []).includes(g.id) ? 'checked' : ''}> ${esc(g.name)}</label>`).join('') : '<span class="muted">Групп пока нет</span>'}</div></div>
      ${old ? (self ? '' : `<label class="check wide"><input type="checkbox" name="active" ${u.active !== false ? 'checked' : ''}> Доступ разрешён (снимите галочку при увольнении)</label>`)
        : `<div class="field wide"><label>Пароль (можно изменить)</label><input name="password" required minlength="10" value="${genPassword()}" spellcheck="false"></div>`}
    </div>`,
    onOk: async f => {
      const name = fval(f, 'name');
      const role = self ? 'admin' : fval(f, 'role');
      const gs = Array.from(f.querySelectorAll('input[name=g]:checked')).map(x => x.value);
      if (!name) throw new Error('Укажите имя.');
      if (!old) {
        const login = normLogin(fval(f, 'login'));
        const password = f.elements.password.value;
        if (!/^[a-zа-яё0-9._-]{2,40}$/i.test(login)) throw new Error('Логин: 2–40 символов, буквы, цифры, точка, дефис.');
        if (S.users.some(x => normLogin(x.login) === login)) throw new Error('Такой логин уже есть.');
        if (password.length < 10) throw new Error('Пароль должен быть не короче 10 символов.');
        const rec = { id: uid(), login, name, role, groups: role === 'teacher' ? gs : [], active: true, createdAt: nowIso() };
        await saveData('users', [{ path: 'data/users.json', update: d => {
          d = d || { users: [] };
          if (d.users.some(x => normLogin(x.login) === login)) throw new Error('Такой логин уже есть.');
          d.users.push(rec); return d;
        } }], `Добавлен сотрудник ${name} (${ROLE[role]}, логин ${login})`);
        await setUserPassword(rec, password);
        openModal({ title: 'Сотрудник добавлен', body: credentialsHtml([{ name, login, password }]), cancelText: 'Готово' });
        render();
        return false;
      }
      const active = self ? true : !!(f.elements.active && f.elements.active.checked);
      if (!active && old.role === 'admin' && S.users.filter(x => x.role === 'admin' && x.active !== false).length < 2) throw new Error('Нельзя отключить единственную заведующую.');
      if (role !== 'admin' && old.role === 'admin' && S.users.filter(x => x.role === 'admin' && x.active !== false).length < 2) throw new Error('Должна остаться хотя бы одна заведующая.');
      const patch = { name, role, groups: role === 'teacher' ? gs : [], active };
      const notes = [];
      if (old.name !== name) notes.push(`имя → ${name}`);
      if (old.role !== role) notes.push(`роль → ${ROLE[role]}`);
      if ((old.groups || []).join() !== patch.groups.join()) notes.push(`группы → ${patch.groups.map(groupName).join(', ') || 'нет'}`);
      if ((old.active !== false) !== active) notes.push(active ? 'доступ восстановлен' : 'доступ отключён');
      if (!notes.length) return;
      await saveData('users', [{ path: 'data/users.json', update: d => {
        d = d || { users: [] };
        const i = d.users.findIndex(x => x.id === old.id);
        if (i >= 0) Object.assign(d.users[i], patch);
        return d;
      } }], `Изменён сотрудник ${old.name}: ${notes.join(', ')}`);
      if (!active && old.active !== false) {
        const h = await loginHash(old.login);
        showBusy('Отключаю доступ…');
        try { await saveAuth(d => { delete d.users[h]; }); } finally { hideBusy(); }
      }
      if (self) { S.me = S.users.find(x => x.id === S.me.id); $('#userBtn').textContent = S.me.name + ' ▾'; }
      toast(active && old.active === false ? 'Доступ восстановлен. Выдайте сотруднику новый пароль.' : 'Сохранено');
      render();
    },
  });
  const roleSel = m.form.elements.role;
  const sync = () => { $('#uGroupsField').classList.toggle('hidden', roleSel.value !== 'teacher'); };
  roleSel.onchange = sync; sync();
}

function adminKey() {
  return `<div class="panel">
    <h2>Ключ доступа GitHub</h2>
    <p class="hint">Ключ хранится только в зашифрованном виде — отдельно для каждого сотрудника под его паролем.</p>
    <div class="notice info" style="margin-top:12px">Когда менять ключ:<br>• истёк срок действия ключа (GitHub пришлёт письмо заранее);<br>• уволился сотрудник и нужно гарантированно закрыть ему доступ;<br>• есть подозрение, что пароль или ключ узнал посторонний.</div>
    <p>При замене ключа ваш пароль останется прежним, а <b>всем остальным сотрудникам будут выданы новые пароли</b> — их покажут на экране.</p>
    <p class="hint">Порядок: создайте новый ключ на GitHub → замените его здесь → удалите старый ключ на GitHub.</p>
    <button class="btn primary" data-act="rotateKey">Заменить ключ</button>
  </div>`;
}
ACTIONS.rotateKey = () => {
  openModal({
    title: 'Замена ключа GitHub',
    body: `<div class="form-grid">
      <div class="field wide"><label>Новый ключ доступа (токен)</label><input name="token" type="password" required spellcheck="false" placeholder="github_pat_…"></div>
      <div class="field wide"><label>Ваш текущий пароль</label><input name="pass" type="password" required autocomplete="current-password"></div></div>`,
    okText: 'Заменить',
    onOk: async f => {
      const token = fval(f, 'token'), pass = f.elements.pass.value;
      AUTH = (await fetchAuth()).data || AUTH;
      const myEntry = AUTH && AUTH.users && AUTH.users[await loginHash(S.me.login)];
      let ok = false;
      if (myEntry) { try { await unseal(myEntry, pass); ok = true; } catch (x) { ok = false; } }
      if (!ok) throw new Error('Текущий пароль неверный.');
      const gh = new GitHub(token);
      showBusy('Проверяю новый ключ…');
      let creds = [];
      try {
        try { await gh.api('GET', `/repos/${S.dataRepo}`); } catch (x) { throw new Error('Новый ключ не даёт доступа к репозиторию данных ' + S.dataRepo); }
        try { await gh.api('GET', `/repos/${CONFIG.siteRepo}`); } catch (x) { throw new Error('Новый ключ не даёт доступа к репозиторию сайта ' + CONFIG.siteRepo); }
        showBusy('Шифрую ключ для всех сотрудников…');
        const entries = {};
        entries[await loginHash(S.me.login)] = await seal({ t: token, r: S.dataRepo, u: S.me.id }, pass);
        for (const u of S.users.filter(x => x.active !== false && x.id !== S.me.id)) {
          const password = genPassword();
          entries[await loginHash(u.login)] = await seal({ t: token, r: S.dataRepo, u: u.id }, password);
          creds.push({ name: u.name, login: u.login, password });
        }
        await saveAuth(d => { d.users = entries; }, gh);
        S.gh = gh; S.token = token;
        const sess = store.get('kj-session');
        if (sess) { let persistent = false; try { persistent = !!localStorage.getItem('kj-session'); } catch (x) { /* ignore */ } store.set('kj-session', { t: token, r: S.dataRepo, u: S.me.id }, persistent); }
        await gh.commit(S.dataRepo, CONFIG.dataBranch, `${S.me.name}: замена ключа`, [logChange('auth', 'Заменён ключ доступа GitHub, сотрудникам выданы новые пароли')]);
      } finally { hideBusy(); }
      openModal({ title: 'Ключ заменён', wide: true, body: (creds.length ? credentialsHtml(creds) : '<p>Других сотрудников нет.</p>') + '<p class="hint">Теперь удалите старый ключ на GitHub: Settings → Developer settings → Personal access tokens.</p>', cancelText: 'Готово' });
      return false;
    },
  });
};

/* ================= Старт ================= */

if (!window.crypto || !crypto.subtle) {
  document.body.innerHTML = '<div class="center-screen"><p>Браузер не поддерживает шифрование. Откройте сайт по адресу https:// в современном браузере.</p></div>';
} else {
  boot();
}
