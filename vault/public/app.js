"use strict";

(() => {
  const VC = window.VaultCrypto;
  const $ = (id) => document.getElementById(id);

  /* ------------------------------------------------------------------ *
   *  Icons (static, trusted markup only)
   * ------------------------------------------------------------------ */
  const svg = (inner, extra = "") =>
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" ${extra}>${inner}</svg>`;
  const ICONS = {
    key: svg('<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>'),
    lock: svg('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'),
    note: svg('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>'),
    star: svg('<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>'),
    starFill: svg('<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>', 'fill="currentColor"'),
    folder: svg('<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>'),
    shield: svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'),
    refresh: svg('<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>'),
    copy: svg('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>'),
    user: svg('<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>'),
    ext: svg('<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"/>'),
    edit: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4z"/>'),
    eye: svg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>'),
    eyeOff: svg('<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><path d="M1 1l22 22"/>'),
    x: svg('<path d="M18 6L6 18M6 6l12 12"/>'),
    search: svg('<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>'),
    menu: svg('<path d="M3 12h18M3 6h18M3 18h18"/>'),
    grid: svg('<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>'),
    list: svg('<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>'),
    download: svg('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>'),
    all: svg('<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M3 9h18M9 21V9"/>'),
  };
  const setIcon = (node, name) => { node.innerHTML = ICONS[name]; };

  /* ------------------------------------------------------------------ *
   *  Small helpers
   * ------------------------------------------------------------------ */
  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "html") n.innerHTML = v; // only ever called with static ICONS markup
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids) if (kid !== null && kid !== undefined) n.append(kid);
    return n;
  }

  const store = {
    get(k, d) { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* storage may be blocked */ } },
  };

  function toast(msg, isErr) {
    const t = el("div", { class: "toast" + (isErr ? " err" : ""), text: msg });
    $("toasts").textContent = ""; // one at a time, newest wins
    $("toasts").append(t);
    setTimeout(() => t.remove(), isErr ? 4200 : 2600);
  }

  let clipTimer = null;
  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`${what} copied. Clipboard clears in 30 seconds.`);
      clearTimeout(clipTimer);
      clipTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
    } catch {
      toast("Could not access the clipboard.", true);
    }
  }

  function confirmBox(title, text, okLabel = "Confirm") {
    const dlg = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = okLabel;
    return new Promise((resolve) => {
      dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
      dlg.returnValue = "";
      dlg.showModal();
    });
  }

  function normalizeUrl(raw) {
    const s = (raw || "").trim();
    if (!s) return null;
    try {
      const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "https://" + s);
      return u.protocol === "http:" || u.protocol === "https:" ? u : null;
    } catch { return null; }
  }
  const hostOf = (raw) => { const u = normalizeUrl(raw); return u ? u.hostname.replace(/^www\./, "") : ""; };

  const PALETTE = ["#d32d27", "#e0602a", "#c77700", "#2f855a", "#0e7490", "#2563eb", "#6d4ccb", "#a8359c", "#475569", "#b4474f"];
  function colorFor(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
    return PALETTE[h % PALETTE.length];
  }

  function updateMeter(root, pw) {
    const s = VC.passwordStrength(pw);
    root.dataset.score = String(s.score);
    root.dataset.empty = pw ? "0" : "1";
    root.querySelector(".meter-label").textContent = pw ? `${s.label}` : "";
  }

  /* ------------------------------------------------------------------ *
   *  State
   * ------------------------------------------------------------------ */
  const S = {
    token: null,
    email: "",
    aesKey: null,
    items: [],            // { id, createdAt, updatedAt, data }
    nav: "all",
    q: "",
    layout: store.get("layout", "grid"),
    editingId: null,
    drawerSnapshot: "",
    mode: "login",
    gen: { length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: false },
  };

  /* ------------------------------------------------------------------ *
   *  API
   * ------------------------------------------------------------------ */
  async function api(method, path, body) {
    const headers = {};
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (S.token) headers.Authorization = "Bearer " + S.token;
    let res;
    try {
      res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    } catch {
      throw Object.assign(new Error("Can't reach the server. Check your connection."), { status: 0 });
    }
    let data = {};
    try { data = await res.json(); } catch { /* empty body */ }
    if (!res.ok) throw Object.assign(new Error(data.error || "Request failed"), { status: res.status });
    return data;
  }

  // For calls that need a session: a 401 means the session is gone, so lock.
  async function authed(method, path, body) {
    try { return await api(method, path, body); }
    catch (e) { if (e.status === 401) lock("Your session expired. Log in again."); throw e; }
  }

  /* ------------------------------------------------------------------ *
   *  Auth screen
   * ------------------------------------------------------------------ */
  function setMode(mode) {
    S.mode = mode;
    const signup = mode === "signup";
    $("auth-title").textContent = signup ? "Create your vault" : "Log in to your vault";
    $("auth-submit").textContent = signup ? "Create account" : "Log in";
    $("auth-switch-text").textContent = signup ? "Already have an account?" : "New here?";
    $("auth-switch").textContent = signup ? "Log in" : "Create an account";
    $("signup-extra").hidden = !signup;
    $("a-pass").autocomplete = signup ? "new-password" : "current-password";
    $("auth-lock-note").hidden = true;
    showAuthError("");
  }

  function showAuthError(msg) {
    $("auth-error").textContent = msg;
    $("auth-error").hidden = !msg;
  }

  async function submitAuth(e) {
    e.preventDefault();
    showAuthError("");
    const email = $("a-email").value.trim().toLowerCase();
    const pass = $("a-pass").value;
    const signup = S.mode === "signup";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return showAuthError("Enter a valid email address.");
    if (!pass) return showAuthError("Enter your master password.");
    if (signup) {
      if (pass.length < 12) return showAuthError("Your master password needs at least 12 characters.");
      if (pass !== $("a-pass2").value) return showAuthError("The two passwords don't match.");
      if (!$("a-ack").checked) return showAuthError("Please confirm you understand the password can't be recovered.");
    }

    const btn = $("auth-submit");
    const label = btn.textContent;
    btn.disabled = true;
    btn.textContent = "Securing…";
    try {
      let token, aesKey;
      if (signup) {
        const salt = VC.newSalt();
        const iterations = VC.DEFAULT_ITERATIONS;
        const keys = await VC.deriveKeys(pass, email, salt, iterations);
        ({ token } = await api("POST", "/api/register", { email, salt, iterations, authKey: keys.authKey }));
        aesKey = keys.aesKey;
      } else {
        const pre = await api("GET", "/api/prelogin?email=" + encodeURIComponent(email));
        const keys = await VC.deriveKeys(pass, email, pre.salt, pre.iterations);
        ({ token } = await api("POST", "/api/login", { email, authKey: keys.authKey }));
        aesKey = keys.aesKey;
      }
      S.token = token; S.email = email; S.aesKey = aesKey;
      btn.textContent = "Opening vault…";
      await loadItems();
      $("a-pass").value = ""; $("a-pass2").value = ""; $("a-ack").checked = false;
      showApp();
    } catch (err) {
      S.token = null; S.aesKey = null;
      showAuthError(err.message || "Something went wrong.");
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  async function loadItems() {
    const { items } = await api("GET", "/api/items");
    const out = [];
    let failed = 0;
    for (const row of items) {
      try {
        out.push({ id: row.id, createdAt: row.created_at, updatedAt: row.updated_at, data: await VC.decryptItem(S.aesKey, row.id, row.blob) });
      } catch { failed++; }
    }
    S.items = out;
    if (failed) setTimeout(() => toast(`${failed} item${failed > 1 ? "s" : ""} couldn't be decrypted and ${failed > 1 ? "were" : "was"} skipped.`, true), 400);
  }

  function lock(message, { keepEmail = true } = {}) {
    if (S.token) api("POST", "/api/logout").catch(() => {});
    S.token = null; S.aesKey = null; S.items = []; S.q = ""; S.nav = "all"; S.editingId = null;
    closeDrawer(true);
    $("search").value = "";
    $("app").hidden = true;
    $("auth").hidden = false;
    $("a-pass").value = "";
    if (!keepEmail) $("a-email").value = "";
    setMode("login");
    if (message) { $("auth-lock-note").textContent = message; $("auth-lock-note").hidden = false; }
    (($("a-email").value) ? $("a-pass") : $("a-email")).focus();
    stopIdleTimer();
  }

  function showApp() {
    $("auth").hidden = true;
    $("app").hidden = false;
    $("me-email").textContent = S.email;
    $("me-email").title = S.email;
    renderAll();
    startIdleTimer();
  }

  /* ------------------------------------------------------------------ *
   *  Idle auto-lock
   * ------------------------------------------------------------------ */
  const IDLE_MS = 15 * 60 * 1000;
  let idleTimer = null, lastBump = 0;
  function bumpIdle() {
    const now = Date.now();
    if (!S.aesKey || now - lastBump < 5000) return;
    lastBump = now;
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => lock("Your vault was locked after 15 minutes of inactivity."), IDLE_MS);
  }
  function startIdleTimer() { lastBump = 0; bumpIdle(); }
  function stopIdleTimer() { clearTimeout(idleTimer); }
  ["pointerdown", "keydown", "scroll"].forEach((ev) => window.addEventListener(ev, bumpIdle, { passive: true }));

  /* ------------------------------------------------------------------ *
   *  Navigation
   * ------------------------------------------------------------------ */
  const sorted = (arr) => [...arr].sort((a, b) => a.data.name.localeCompare(b.data.name, undefined, { sensitivity: "base" }));
  const passwordItems = () => S.items.filter((i) => i.data.type !== "note");
  const folderNames = () => [...new Set(S.items.map((i) => i.data.folder).filter(Boolean))].sort((a, b) => a.localeCompare(b));

  function renderNav() {
    const nav = $("nav");
    nav.textContent = "";
    const entry = (key, icon, label, count, onClick) => {
      const b = el("button", { class: "nav-item", type: "button", "aria-current": S.nav === key ? "page" : null },
        el("span", { class: "ico", html: ICONS[icon] }),
        el("span", { class: "label", text: label }),
        count !== undefined ? el("span", { class: "count", text: String(count) }) : null);
      b.addEventListener("click", onClick || (() => setNav(key)));
      nav.append(b);
    };
    entry("all", "all", "All items", S.items.length);
    entry("passwords", "key", "Passwords", passwordItems().length);
    entry("notes", "note", "Secure notes", S.items.filter((i) => i.data.type === "note").length);
    entry("favorites", "star", "Favorites", S.items.filter((i) => i.data.favorite).length);

    const folders = folderNames();
    if (folders.length) {
      nav.append(el("div", { class: "nav-sec", text: "Folders" }));
      for (const f of folders) entry("folder:" + f, "folder", f, S.items.filter((i) => i.data.folder === f).length);
    }
    nav.append(el("div", { class: "nav-sec", text: "Tools" }));
    entry("security", "shield", "Security challenge");
    entry("generator", "refresh", "Password generator");
    entry("export", "download", "Export vault", undefined, exportCsv);
  }

  function setNav(key) {
    S.nav = key;
    if (key !== "all" && key !== "passwords" && key !== "notes" && key !== "favorites" && !key.startsWith("folder:")) {
      S.q = ""; $("search").value = "";
    }
    closeSidebar();
    renderAll();
    $("view").scrollTop = 0;
  }

  function closeSidebar() { $("sidebar").classList.remove("open"); $("scrim").hidden = true; }
  function openSidebar() { $("sidebar").classList.add("open"); $("scrim").hidden = false; }

  function renderAll() { renderNav(); renderView(); }

  /* ------------------------------------------------------------------ *
   *  Item list
   * ------------------------------------------------------------------ */
  function visibleItems() {
    let list = S.items;
    if (S.nav === "passwords") list = list.filter((i) => i.data.type !== "note");
    else if (S.nav === "notes") list = list.filter((i) => i.data.type === "note");
    else if (S.nav === "favorites") list = list.filter((i) => i.data.favorite);
    else if (S.nav.startsWith("folder:")) list = list.filter((i) => i.data.folder === S.nav.slice(7));

    const terms = S.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (terms.length) {
      list = list.filter((i) => {
        const d = i.data;
        const hay = [d.name, d.url, d.username, d.folder, d.type === "note" ? d.notes : ""].join(" ").toLowerCase();
        return terms.every((t) => hay.includes(t));
      });
    }
    return sorted(list);
  }

  function titleFor() {
    if (S.q.trim()) return "Search results";
    if (S.nav === "passwords") return "Passwords";
    if (S.nav === "notes") return "Secure notes";
    if (S.nav === "favorites") return "Favorites";
    if (S.nav.startsWith("folder:")) return S.nav.slice(7);
    return "All items";
  }

  function avatar(d) {
    if (d.type === "note") return el("span", { class: "avatar note", html: ICONS.note });
    const seed = hostOf(d.url) || d.name;
    const a = el("span", { class: "avatar", text: (d.name || "?").trim().charAt(0) || "?" });
    a.style.background = colorFor(seed);
    return a;
  }

  function itemCard(item) {
    const d = item.data;
    const sub = d.type === "note" ? "Secure note" : (d.username || hostOf(d.url) || "No username");
    const main = el("button", { class: "card-main", type: "button", "aria-label": `Edit ${d.name}` },
      avatar(d),
      el("span", { class: "card-text" },
        el("span", { class: "card-name" },
          el("span", { text: d.name, style: "overflow:hidden;text-overflow:ellipsis" }),
          d.favorite ? el("span", { class: "star", html: ICONS.starFill, title: "Favorite" }) : null),
        el("span", { class: "card-sub", text: sub })));
    main.addEventListener("click", () => openDrawer(item.id));

    const actions = el("span", { class: "card-actions" });
    if (d.type !== "note") {
      if (d.username) actions.append(iconAction("user", "Copy username", () => copy(d.username, "Username")));
      if (d.password) actions.append(iconAction("copy", "Copy password", () => copy(d.password, "Password")));
      const u = normalizeUrl(d.url);
      if (u) actions.append(el("a", { class: "icon-btn", href: u.href, target: "_blank", rel: "noopener noreferrer", title: "Open website", "aria-label": "Open website", html: ICONS.ext }));
    }
    actions.append(iconAction("edit", "Edit", () => openDrawer(item.id)));
    return el("div", { class: "card" }, main, actions);
  }

  function iconAction(icon, label, onClick) {
    const b = el("button", { class: "icon-btn", type: "button", title: label, "aria-label": label, html: ICONS[icon] });
    b.addEventListener("click", onClick);
    return b;
  }

  function renderView() {
    const view = $("view");
    view.textContent = "";
    if (S.nav === "security") return renderSecurity(view);
    if (S.nav === "generator") return renderGeneratorPage(view);

    const list = visibleItems();
    const toggle = el("div", { class: "layout-toggle", role: "group", "aria-label": "Layout" });
    for (const [mode, icon, label] of [["grid", "grid", "Grid view"], ["list", "list", "List view"]]) {
      const b = el("button", { type: "button", "aria-pressed": String(S.layout === mode), title: label, "aria-label": label, html: ICONS[icon] });
      b.addEventListener("click", () => { S.layout = mode; store.set("layout", mode); renderView(); });
      toggle.append(b);
    }
    view.append(el("div", { class: "view-head" },
      el("h1", { text: titleFor() }),
      el("span", { class: "sub", text: `${list.length} item${list.length === 1 ? "" : "s"}` }),
      el("span", { class: "spacer" }),
      toggle));

    if (!list.length) return view.append(emptyState());

    const grid = (items) => el("div", { class: "grid" + (S.layout === "list" ? " list" : "") }, ...items.map(itemCard));
    const grouped = S.nav === "all" && !S.q.trim() && folderNames().length > 0;
    if (!grouped) return view.append(grid(list));

    const byFolder = new Map();
    for (const i of list) {
      const k = i.data.folder || "";
      if (!byFolder.has(k)) byFolder.set(k, []);
      byFolder.get(k).push(i);
    }
    const keys = [...byFolder.keys()].filter(Boolean).sort((a, b) => a.localeCompare(b));
    if (byFolder.has("")) keys.push("");
    for (const k of keys) {
      view.append(el("div", { class: "folder-group" }, el("h2", { text: k || "No folder" }), grid(byFolder.get(k))));
    }
  }

  function emptyState() {
    const searching = !!S.q.trim();
    const empty = S.items.length === 0;
    const wrap = el("div", { class: "empty" },
      el("div", { class: "empty-ico", html: searching ? ICONS.search : ICONS.lock }),
      el("h2", { text: searching ? "No matches" : empty ? "Your vault is empty" : "Nothing here yet" }),
      el("p", { text: searching ? "Try a different search term."
        : empty ? "Add your first password or secure note. Everything is encrypted in your browser before it is saved."
        : "Items you add or mark here will show up in this list." }));
    if (!searching) {
      const b = el("button", { class: "btn btn-primary", type: "button", text: "Add item" });
      b.addEventListener("click", () => openDrawer(null));
      wrap.append(b);
    }
    return wrap;
  }

  /* ------------------------------------------------------------------ *
   *  Password generator (shared by page and drawer)
   * ------------------------------------------------------------------ */
  function genPanel({ onUse } = {}) {
    const root = el("div", { class: "gen" });
    const out = el("code");
    const meter = el("div", { class: "meter" }, el("div", { class: "meter-bar" }, el("span"), el("span"), el("span"), el("span")), el("div", { class: "meter-label" }));

    const regen = () => {
      const pw = VC.generatePassword(S.gen);
      out.textContent = pw;
      updateMeter(meter, pw);
    };

    const copyBtn = iconAction("copy", "Copy password", () => copy(out.textContent, "Password"));
    const newBtn = iconAction("refresh", "Generate another", regen);
    root.append(el("div", { class: "gen-out" }, out, copyBtn, newBtn), meter);

    const len = el("input", { type: "range", min: "8", max: "64", value: String(S.gen.length), id: "gen-len-" + Math.random().toString(36).slice(2, 7), "aria-label": "Password length" });
    const lenOut = el("output", { text: String(S.gen.length) });
    len.addEventListener("input", () => { S.gen.length = Number(len.value); lenOut.textContent = len.value; regen(); });
    root.append(el("div", { class: "gen-row" }, el("span", { class: "t gen-row-label", text: "Length", style: "font-size:13px;font-weight:600;min-width:64px" }), len, lenOut));

    const opts = el("div", { class: "gen-opts" });
    const boxes = [];
    for (const [key, label] of [["upper", "Uppercase (A-Z)"], ["lower", "Lowercase (a-z)"], ["digits", "Numbers (0-9)"], ["symbols", "Symbols (!@#$)"], ["avoidAmbiguous", "Avoid look-alikes (O, 0, l, 1)"]]) {
      const cb = el("input", { type: "checkbox" });
      cb.checked = !!S.gen[key];
      cb.addEventListener("change", () => {
        S.gen[key] = cb.checked;
        if (!S.gen.upper && !S.gen.lower && !S.gen.digits && !S.gen.symbols) { S.gen[key] = true; cb.checked = true; }
        regen();
      });
      boxes.push(cb);
      opts.append(el("label", { class: "check" }, cb, el("span", { text: label })));
    }
    root.append(opts);

    if (onUse) {
      const use = el("button", { class: "btn btn-primary", type: "button", text: "Use this password" });
      use.addEventListener("click", () => onUse(out.textContent));
      root.append(el("div", { class: "gen-actions" }, use));
    }
    regen();
    return root;
  }

  function renderGeneratorPage(view) {
    view.append(el("div", { class: "view-head" }, el("h1", { text: "Password generator" })), genPanel());
  }

  /* ------------------------------------------------------------------ *
   *  Security challenge
   * ------------------------------------------------------------------ */
  function renderSecurity(view) {
    const pw = passwordItems().filter((i) => i.data.password);
    view.append(el("div", { class: "view-head" }, el("h1", { text: "Security challenge" })));

    if (!pw.length) {
      return view.append(el("div", { class: "empty" },
        el("div", { class: "empty-ico", html: ICONS.shield }),
        el("h2", { text: "Nothing to check yet" }),
        el("p", { text: "Add some passwords and this page will flag weak and reused ones. The check runs in your browser." })));
    }

    const weak = pw.filter((i) => VC.passwordStrength(i.data.password).score <= 1);
    const groups = new Map();
    for (const i of pw) {
      if (!groups.has(i.data.password)) groups.set(i.data.password, []);
      groups.get(i.data.password).push(i);
    }
    const reusedGroups = [...groups.values()].filter((g) => g.length > 1);
    const flagged = new Set([...weak.map((i) => i.id), ...reusedGroups.flat().map((i) => i.id)]);
    const score = Math.round(100 * (1 - flagged.size / pw.length));

    const ring = el("div", { class: "ring" }, el("span", { text: String(score) }));
    ring.style.setProperty("--p", String(score));
    ring.style.setProperty("--c", score >= 80 ? "#1f8a4c" : score >= 50 ? "#d89a00" : "#d32d27");
    view.append(el("div", { class: "sec-top" }, ring,
      el("div", {},
        el("h2", { text: score === 100 ? "Looking good" : score >= 80 ? "Almost there" : "Needs attention" }),
        el("p", { text: `${flagged.size} of ${pw.length} password${pw.length === 1 ? "" : "s"} ${flagged.size === 1 ? "is" : "are"} weak or reused. Fix these first. Reusing a password means one breach can open several accounts.` }))));

    const cards = el("div", { class: "sec-cards" });
    cards.append(secCard("Weak passwords", weak.length, weak.length ? sorted(weak).map(itemCard) : null, "No weak passwords."));
    const reusedKids = [];
    for (const g of reusedGroups) {
      reusedKids.push(el("div", { class: "none", style: "padding:10px 16px 0;font-size:12px;border-top:1px solid var(--line)", text: `Same password on ${g.length} items` }));
      sorted(g).forEach((i) => reusedKids.push(itemCard(i)));
    }
    cards.append(secCard("Reused passwords", reusedGroups.flat().length, reusedKids.length ? reusedKids : null, "No reused passwords."));
    view.append(cards);
  }

  function secCard(title, count, kids, noneText) {
    const card = el("section", { class: "sec-card" },
      el("h3", {}, el("span", { text: title }), el("span", { class: "pill " + (count ? "bad" : "good"), text: String(count) })));
    if (kids) kids.forEach((k) => card.append(k)); else card.append(el("div", { class: "none", text: noneText }));
    return card;
  }

  /* ------------------------------------------------------------------ *
   *  Drawer (add / edit)
   * ------------------------------------------------------------------ */
  const F = {
    name: () => $("f-name"), url: () => $("f-url"), user: () => $("f-user"), pass: () => $("f-pass"),
    notes: () => $("f-notes"), folder: () => $("f-folder"), fav: () => $("f-fav"),
  };

  function currentType() { return $("drawer").dataset.type || "password"; }
  function setType(type) {
    $("drawer").dataset.type = type;
    for (const b of $("type-seg").querySelectorAll("button")) b.setAttribute("aria-selected", String(b.dataset.type === type));
    $("f-notes").rows = type === "note" ? 12 : 3;
  }

  function formState() {
    return JSON.stringify([currentType(), F.name().value, F.url().value, F.user().value, F.pass().value, F.notes().value, F.folder().value, F.fav().checked]);
  }

  function openDrawer(id) {
    const item = id ? S.items.find((i) => i.id === id) : null;
    S.editingId = item ? item.id : null;
    const d = item ? item.data : { type: "password", name: "", url: "", username: "", password: "", notes: "", folder: S.nav.startsWith("folder:") ? S.nav.slice(7) : "", favorite: S.nav === "favorites" };

    setType(d.type === "note" ? "note" : "password");
    $("type-seg").classList.toggle("locked", !!item);
    $("drawer-title").textContent = item ? "Edit item" : "Add item";
    F.name().value = d.name; F.url().value = d.url || ""; F.user().value = d.username || "";
    F.pass().value = d.password || ""; F.notes().value = d.notes || ""; F.folder().value = d.folder || ""; F.fav().checked = !!d.favorite;
    $("btn-delete").hidden = !item;
    $("item-error").hidden = true;

    $("f-pass").type = "password";
    const tgl = document.querySelector('[data-toggle-for="f-pass"]');
    setIcon(tgl, "eye"); tgl.setAttribute("aria-pressed", "false"); tgl.setAttribute("aria-label", "Show password");
    $("f-gen").hidden = true; $("f-gen").textContent = "";
    $("f-gen-toggle").setAttribute("aria-expanded", "false");
    $("f-gen-toggle").textContent = "Generate a password";
    updateMeter($("f-meter"), F.pass().value);
    refreshUrlLink();

    $("folder-list").textContent = "";
    folderNames().forEach((f) => $("folder-list").append(el("option", { value: f })));

    $("drawer").classList.add("open");
    $("drawer").setAttribute("aria-hidden", "false");
    $("drawer-scrim").hidden = false;
    S.drawerSnapshot = formState();
    setTimeout(() => F.name().focus(), 60);
  }

  async function closeDrawer(force) {
    if (!$("drawer").classList.contains("open")) return;
    if (!force && formState() !== S.drawerSnapshot) {
      const ok = await confirmBox("Discard changes?", "You have unsaved changes to this item.", "Discard");
      if (!ok) return;
    }
    $("drawer").classList.remove("open");
    $("drawer").setAttribute("aria-hidden", "true");
    $("drawer-scrim").hidden = true;
    F.pass().value = ""; // don't leave the secret sitting in the form
    S.editingId = null;
  }

  function refreshUrlLink() {
    const a = $("f-url-open");
    const u = normalizeUrl(F.url().value);
    a.hidden = !u;
    if (u) a.href = u.href;
  }

  async function saveItem(e) {
    e.preventDefault();
    const type = currentType();
    const name = F.name().value.trim();
    const err = (m) => { $("item-error").textContent = m; $("item-error").hidden = false; };
    if (!name) { err("Give this item a name."); F.name().focus(); return; }
    if (type === "password" && F.url().value.trim() && !normalizeUrl(F.url().value)) { err("That website address doesn't look right. Use a web address like https://example.com."); return; }

    const data = {
      type, name,
      url: type === "password" ? F.url().value.trim() : "",
      username: type === "password" ? F.user().value : "",
      password: type === "password" ? F.pass().value : "",
      notes: F.notes().value,
      folder: F.folder().value.trim(),
      favorite: F.fav().checked,
    };

    const id = S.editingId || VC.uuid();
    const btn = $("btn-save");
    btn.disabled = true;
    try {
      const blob = await VC.encryptItem(S.aesKey, id, data);
      const res = await authed("PUT", "/api/items/" + id, { blob });
      const existing = S.items.find((i) => i.id === id);
      if (existing) { existing.data = data; existing.updatedAt = res.updated_at; }
      else S.items.push({ id, createdAt: res.updated_at, updatedAt: res.updated_at, data });
      S.drawerSnapshot = formState();
      await closeDrawer(true);
      renderAll();
      toast(existing ? "Changes saved" : "Item added");
    } catch (ex) {
      if (S.token) err(ex.message || "Could not save this item.");
    } finally {
      btn.disabled = false;
    }
  }

  async function deleteItem() {
    const item = S.items.find((i) => i.id === S.editingId);
    if (!item) return;
    const ok = await confirmBox("Delete this item?", `"${item.data.name}" will be permanently removed. This can't be undone.`, "Delete");
    if (!ok) return;
    try {
      await authed("DELETE", "/api/items/" + item.id);
      S.items = S.items.filter((i) => i.id !== item.id);
      await closeDrawer(true);
      renderAll();
      toast("Item deleted");
    } catch (ex) {
      if (S.token) toast(ex.message || "Could not delete the item.", true);
    }
  }

  /* ------------------------------------------------------------------ *
   *  Export
   * ------------------------------------------------------------------ */
  async function exportCsv() {
    closeSidebar();
    const ok = await confirmBox("Export your vault?",
      "The file will contain every password and note in plain text, with no encryption. Store it somewhere safe and delete it when you are done.", "Export");
    if (!ok) return;
    const cell = (v) => {
      let s = String(v ?? "");
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // stop spreadsheets treating a value as a formula
      return '"' + s.replace(/"/g, '""') + '"';
    };
    const rows = [["type", "name", "url", "username", "password", "notes", "folder", "favorite"]];
    for (const i of sorted(S.items)) {
      const d = i.data;
      rows.push([d.type, d.name, d.url, d.username, d.password, d.notes, d.folder, d.favorite ? "1" : "0"]);
    }
    const blob = new Blob(["﻿" + rows.map((r) => r.map(cell).join(",")).join("\r\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: `vault-export-${new Date().toISOString().slice(0, 10)}.csv` });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast("Export downloaded");
  }

  /* ------------------------------------------------------------------ *
   *  Wire up
   * ------------------------------------------------------------------ */
  function init() {
    // Static icons
    setIcon($("btn-menu"), "menu");
    document.querySelector(".search-ico").innerHTML = ICONS.search;
    setIcon($("drawer-close"), "x");
    setIcon($("f-user-copy"), "copy");
    setIcon($("f-pass-copy"), "copy");
    setIcon($("f-url-open"), "ext");
    document.querySelectorAll(".pw-toggle").forEach((b) => setIcon(b, "eye"));

    // Show / hide password buttons
    document.querySelectorAll(".pw-toggle").forEach((b) => b.addEventListener("click", () => {
      const input = $(b.dataset.toggleFor);
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      setIcon(b, show ? "eyeOff" : "eye");
      b.setAttribute("aria-pressed", String(show));
      b.setAttribute("aria-label", show ? "Hide password" : "Show password");
    }));

    // Auth
    $("auth-form").addEventListener("submit", submitAuth);
    $("auth-switch").addEventListener("click", () => { setMode(S.mode === "login" ? "signup" : "login"); $("a-pass").focus(); });
    $("a-pass").addEventListener("input", () => { if (S.mode === "signup") updateMeter($("a-meter"), $("a-pass").value); });
    updateMeter($("a-meter"), "");

    // Shell
    $("btn-lock").addEventListener("click", () => lock("Your vault is locked."));
    $("btn-logout").addEventListener("click", () => lock("", { keepEmail: false }));
    $("btn-add").addEventListener("click", () => openDrawer(null));
    $("btn-menu").addEventListener("click", openSidebar);
    $("scrim").addEventListener("click", closeSidebar);
    $("search").addEventListener("input", (e) => {
      S.q = e.target.value;
      if (S.q.trim() && (S.nav === "security" || S.nav === "generator")) S.nav = "all";
      renderAll();
    });

    // Drawer
    $("item-form").addEventListener("submit", saveItem);
    $("btn-cancel").addEventListener("click", () => closeDrawer(false));
    $("drawer-close").addEventListener("click", () => closeDrawer(false));
    $("drawer-scrim").addEventListener("click", () => closeDrawer(false));
    $("btn-delete").addEventListener("click", deleteItem);
    $("type-seg").addEventListener("click", (e) => { const b = e.target.closest("button[data-type]"); if (b) setType(b.dataset.type); });
    $("f-pass").addEventListener("input", () => updateMeter($("f-meter"), $("f-pass").value));
    $("f-url").addEventListener("input", refreshUrlLink);
    $("f-user-copy").addEventListener("click", () => F.user().value ? copy(F.user().value, "Username") : toast("Nothing to copy yet", true));
    $("f-pass-copy").addEventListener("click", () => F.pass().value ? copy(F.pass().value, "Password") : toast("Nothing to copy yet", true));
    $("f-gen-toggle").addEventListener("click", () => {
      const box = $("f-gen");
      const open = box.hidden;
      box.hidden = !open;
      $("f-gen-toggle").setAttribute("aria-expanded", String(open));
      $("f-gen-toggle").textContent = open ? "Hide generator" : "Generate a password";
      if (open) {
        box.textContent = "";
        box.append(genPanel({
          onUse: (pw) => {
            F.pass().value = pw;
            updateMeter($("f-meter"), pw);
            box.hidden = true; $("f-gen-toggle").setAttribute("aria-expanded", "false"); $("f-gen-toggle").textContent = "Generate a password";
            toast("Password filled in");
          },
        }));
      }
    });

    // Keyboard shortcuts
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("confirm").open) { closeDrawer(false); closeSidebar(); }
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName);
      if (e.key === "/" && !typing && S.aesKey && !$("drawer").classList.contains("open")) { e.preventDefault(); $("search").focus(); }
    });

    setMode("login");
    $("a-email").focus();
  }

  init();
})();
