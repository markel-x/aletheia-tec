// Panel de Aletheia: módulos ES, sin dependencias. Cliente de /v1 con token de sesión.

import { claimsEditor, schemaEditor } from "./editors.js";
import { LANGS, applyLang, chosenLang, fmtDateTime, lang, langSwitch, rememberLang, t, translateStatic } from "./i18n.js";

// Ayudas largas (prosa con HTML): un módulo por idioma con las mismas claves. Se cargan
// cuando ya se conoce el idioma (el de la cuenta se sabe tras /v1/auth/me).
let HELP = { DOCS: [], ERROR_TIPS: {}, FIELD_HELP: {}, SECTION_HELP: {} };
const loadHelp = async () => { HELP = await import(lang === "en" ? "./help-en.js" : "./help.js"); };

const TOKEN_KEY = "aletheia.session";

// Tema del panel: «dark» (predeterminado), «light» o «system» (el del sistema operativo).
// Se guarda en la cuenta; en este navegador se recuerda el último para no parpadear al cargar.
const THEME_KEY = "aletheia.theme";
const prefersLight = matchMedia("(prefers-color-scheme: light)");
let themePref = "dark";
function applyTheme(pref) {
  themePref = ["light", "system"].includes(pref) ? pref : "dark";
  const light = themePref === "light" || (themePref === "system" && prefersLight.matches);
  document.documentElement.dataset.theme = light ? "light" : "dark";
  document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", light ? "light" : "dark");
  try { localStorage.setItem(THEME_KEY, themePref); } catch { /* sólo para esta visita */ }
}
prefersLight.addEventListener("change", () => { if (themePref === "system") applyTheme("system"); });
try { applyTheme(localStorage.getItem(THEME_KEY)); } catch { applyTheme("dark"); }
const app = document.getElementById("app");
const nav = document.getElementById("nav");
const who = document.getElementById("who");
const shell = document.getElementById("shell");
const auth = document.getElementById("auth");
const authCard = document.getElementById("auth-card");
const crumbs = document.getElementById("crumbs");
const topbarRight = document.getElementById("topbar-right");
let me = null;
let org = null;

// Iconos propios (trazos simples; atributos de presentación, sin estilos en línea: CSP).
const ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  badge: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.2"/><path d="M6 16c.6-1.6 1.8-2.4 3-2.4s2.4.8 3 2.4M15 10h3M15 13h3"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  check: '<path d="M12 3 20 6.5v5c0 4.7-3.3 8.3-8 9.5-4.7-1.2-8-4.8-8-9.5v-5z"/><path d="m8.5 12 2.5 2.5 4.5-5"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M3.5 19c.8-3 3-4.5 5.5-4.5s4.7 1.5 5.5 4.5"/><circle cx="17" cy="9" r="2.3"/><path d="M16 14.6c2 .2 3.6 1.5 4.3 4"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8M16 6l2 2M14 8l2 2"/>',
  pen: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
  list: '<path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
  chart: '<path d="M4 20V4M4 20h16"/><path d="m7 15 4-5 3 3 5-7"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.6 2.2c-.8.4-1.1 1-1.1 1.8M12 17h.01"/>',
  code: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
  gear: '<circle cx="12" cy="12" r="3"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7"/>',
};
function decorateNav() {
  document.querySelectorAll("[data-icon]").forEach((a) => {
    if (a.querySelector("svg")) return;
    const label = a.textContent.trim();
    a.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[a.dataset.icon] || ""}</svg><span class="nav-label">${esc(label)}</span>`;
    a.title = label;
  });
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = (iso) => fmtDateTime(iso);
const tag = (v) => `<span class="tag ${esc(v)}">${esc(v)}</span>`;
const short = (id) => `<span class="mono" title="${esc(id)}">${esc(String(id).slice(0, 8))}…</span>`;

function toast(msg, error = false) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast" + (error ? " error" : "");
  el.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => (el.hidden = true), error ? 6000 : 3000);
}

async function api(method, path, body, headers = {}) {
  const token = sessionStorage.getItem(TOKEN_KEY);
  const res = await fetch(path, {
    method,
    headers: {
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && path !== "/v1/auth/login") {
      sessionStorage.removeItem(TOKEN_KEY);
      me = null;
      location.hash = "#/login";
    }
    const e = data.error || {};
    const detail = e.details ? ` (${JSON.stringify(e.details)})` : "";
    const tip = HELP.ERROR_TIPS[e.code] ? ` — ${HELP.ERROR_TIPS[e.code]}` : "";
    throw new Error(`${e.code || res.status}: ${e.message || "error"}${detail}${tip}`);
  }
  return data;
}

const can = (perm) => !!me && me.permissions.includes(perm);

// Ayuda desplegable bajo un campo o al inicio de una sección (contenido de help.js).
const fieldHelp = (key) =>
  key && HELP.FIELD_HELP[key]
    ? `<details class="field-help"><summary>${t("common.how_to_fill")}</summary><div class="help-panel">${HELP.FIELD_HELP[key]}</div></details>`
    : "";
const sectionHelp = (key) =>
  key && HELP.SECTION_HELP[key]
    ? `<details class="section-help"><summary>${t("common.what_is_this")}</summary><div class="help-panel">${HELP.SECTION_HELP[key]}</div></details>`
    : "";

function form(fields, submitLabel, onSubmit) {
  const f = document.createElement("form");
  f.innerHTML =
    fields
      .map((x) => fieldMarkup(x) + fieldHelp(x.help) + (x.after || ""))
      .join("") + `<p><button type="submit">${esc(submitLabel)}</button></p>`;
  f.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const btn = f.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      const data = {};
      for (const x of fields) {
        const el = f.elements[x.name];
        data[x.name] = x.type === "checkbox" ? el.checked : el.value;
      }
      await onSubmit(data, f);
    } catch (e) {
      toast(e.message, true);
    } finally {
      btn.disabled = false;
    }
  });
  return f;
}

function fieldMarkup(x) {
        const id = `f_${x.name}`;
        if (x.type === "select")
          return `<label for="${id}">${esc(x.label)}</label><select id="${id}" name="${x.name}">${x.options
            .map((o) => (typeof o === "string" ? { value: o, label: o } : o))
            .map((o) => `<option value="${esc(o.value)}">${esc(o.label)}</option>`)
            .join("")}</select>`;
        if (x.type === "textarea")
          return `<label for="${id}">${esc(x.label)}</label><textarea id="${id}" name="${x.name}" ${x.required ? "required" : ""}>${esc(x.value || "")}</textarea>`;
        if (x.type === "checkbox")
          return `<label><input type="checkbox" class="inline" name="${x.name}" ${x.checked ? "checked" : ""}> ${esc(x.label)}</label>`;
        return `<label for="${id}">${esc(x.label)}</label><input id="${id}" name="${x.name}" type="${x.type || "text"}" value="${esc(x.value || "")}" ${x.required ? "required" : ""} ${x.placeholder ? `placeholder="${esc(x.placeholder)}"` : ""} autocomplete="${x.autocomplete || "off"}">`;
}

function table(headers, rows, { filter = false } = {}) {
  const bar = filter && rows.length > 5 ? `<div class="filter"><input type="search" placeholder="${t("common.filter_placeholder")}" data-filter aria-label="${t("common.filter_label")}"></div>` : "";
  return `${bar}<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="muted">${t("common.no_data")}</td></tr>`
  }</tbody></table></div>`;
}

// Filtro en el cliente para tablas con barra de filtro.
document.addEventListener("input", (ev) => {
  const input = ev.target.closest?.("[data-filter]");
  if (!input) return;
  const term = input.value.trim().toLowerCase();
  const tbody = input.closest(".filter").nextElementSibling?.querySelector("tbody");
  tbody?.querySelectorAll("tr").forEach((tr) => (tr.hidden = term !== "" && !tr.textContent.toLowerCase().includes(term)));
});

// Gráfico de líneas SVG (sin bibliotecas).
function lineChart(labels, series) {
  const W = 720, H = 220, L = 36, R = 12, T = 12, B = 26;
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const step = Math.max(1, Math.ceil(max / 4));
  const top = step * 4;
  const x = (i) => L + (labels.length <= 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (labels.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / top);
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(series.map((s) => s.name).join(", "))}">`;
  for (let k = 0; k <= 4; k++) {
    const v = step * k;
    svg += `<line class="grid-line" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text class="axis" x="${L - 6}" y="${y(v) + 3}" text-anchor="end">${v}</text>`;
  }
  labels.forEach((lab, i) => { svg += `<text class="axis" x="${x(i)}" y="${H - 8}" text-anchor="middle">${esc(lab)}</text>`; });
  if (labels.length < 3) {
    // Con pocos puntos una línea no dice nada: columnas agrupadas por mes.
    const slot = (W - L - R) / labels.length;
    const bw = Math.min(56, (slot * 0.6) / series.length);
    labels.forEach((_, i) => {
      series.forEach((s, n) => {
        const v = s.values[i];
        const bx = L + slot * i + slot / 2 - (bw * series.length) / 2 + n * bw;
        svg += `<rect class="d${n}" x="${bx}" y="${y(v)}" width="${bw - 4}" height="${Math.max(0, H - B - y(v))}" rx="2"><title>${esc(s.name)} ${esc(labels[i])}: ${v}</title></rect>`;
      });
    });
    labels.forEach((lab, i) => { svg = svg.replace(`<text class="axis" x="${x(i)}" y="${H - 8}"`, `<text class="axis" x="${L + slot * i + slot / 2}" y="${H - 8}"`); });
  } else {
    series.forEach((s, n) => {
      const pts = s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ");
      svg += `<polyline class="s${n}" points="${pts}"/>`;
      s.values.forEach((v, i) => { svg += `<circle class="d${n}" cx="${x(i)}" cy="${y(v)}" r="2.6"><title>${esc(s.name)} ${esc(labels[i])}: ${v}</title></circle>`; });
    });
  }
  svg += "</svg>";
  const legend = `<div class="legend">${series.map((s, n) => `<span><i class="l${n}"></i>${esc(s.name)}</span>`).join("")}</div>`;
  return svg + legend;
}

function section(title, html, helpKey) {
  const el = document.createElement("section");
  el.className = "card";
  el.innerHTML = (title ? `<h2>${esc(title)}</h2>` : "") + sectionHelp(helpKey) + (html || "");
  return el;
}

function bind(root, selector, event, handler) {
  root.querySelectorAll(selector).forEach((el) =>
    el.addEventListener(event, async (ev) => {
      ev.preventDefault();
      el.disabled = true;
      try {
        await handler(el, ev);
      } catch (e) {
        toast(e.message, true);
      } finally {
        el.disabled = false;
      }
    }),
  );
}

// ---------------------------------------------------------------------------
// Vistas
// ---------------------------------------------------------------------------
const views = {};

views.login = () => {
  authCard.innerHTML = `
    <div class="brand"><svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 28 8v8c0 7.2-5 12.6-12 14C9 28.6 4 23.2 4 16V8z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/><path d="m10.5 16.2 3.8 3.8 7.4-8" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>CredoSeal</span></div>
    <h1>${t("login.title")}</h1>`;
  const f = form(
    [
      { name: "email", label: t("login.email"), type: "email", required: true, autocomplete: "username", help: "login.email" },
      { name: "password", label: t("login.password"), type: "password", required: true, autocomplete: "current-password", help: "login.password" },
    ],
    t("login.submit"),
    async (d, el) => {
      const body = { email: d.email, password: d.password };
      const orgInput = el.querySelector("[name=organization]");
      if (orgInput && orgInput.value.trim()) body.organization = orgInput.value.trim();
      try {
        const r = await api("POST", "/v1/auth/login", body);
        sessionStorage.setItem(TOKEN_KEY, r.token);
      } catch (e) {
        // Varias organizaciones: se pide elegir sin perder lo escrito.
        if (String(e.message).startsWith("organization_required")) {
          el.querySelector("details").open = true;
          throw new Error(t("login.choose_org"));
        }
        throw new Error(String(e.message).startsWith("invalid_credentials") ? t("login.invalid") : e.message);
      }
      const before = lang;
      await loadMe();
      location.hash = "#/overview";
      if (lang !== before) { location.reload(); return; }
      route();
    },
  );
  f.querySelector("p").insertAdjacentHTML(
    "beforebegin",
    `<details class="more"><summary>${t("login.many_orgs")}</summary>
       <label for="f_organization">${t("login.organization")}</label>
       <input id="f_organization" name="organization" autocomplete="off" placeholder="org_…">${fieldHelp("login.organization")}</details>`,
  );
  authCard.appendChild(f);
  authCard.insertAdjacentHTML("beforeend", `<p class="note">${t("login.note_html")}</p>`);
  authCard.querySelector("input")?.focus();
};

// ---------------------------------------------------------------------------
// Resumen (tablero)
// ---------------------------------------------------------------------------
views.overview = async () => {
  app.innerHTML = `<h1>${t("nav.overview")}</h1>`;
  const [creds, usage, verifs] = await Promise.all([
    can("credentials:read") ? api("GET", "/v1/credentials?limit=500").catch(() => []) : [],
    can("usage:read") ? api("GET", "/v1/usage?months=6").catch(() => ({ months: [] })) : { months: [] },
    can("verifications:create") ? api("GET", "/v1/verifications?limit=200").catch(() => []) : [],
  ]);
  const count = (arr, key, val) => arr.filter((x) => x[key] === val).length;
  const tiles = [];
  if (can("credentials:read")) {
    tiles.push(
      { v: count(creds, "state", "issued"), label: t("overview.issued"), hint: t("overview.issued_hint"), cls: "ok" },
      { v: count(creds, "state", "offered"), label: t("overview.offered"), hint: t("overview.offered_hint"), cls: count(creds, "state", "offered") ? "warn" : "" },
      { v: count(creds, "state", "revoked"), label: t("overview.revoked"), hint: t("overview.revoked_hint"), cls: count(creds, "state", "revoked") ? "bad" : "" },
    );
  }
  if (can("verifications:create")) {
    tiles.push(
      { v: count(verifs, "result", "valid"), label: t("overview.valid"), hint: t("overview.last_200"), cls: "ok" },
      { v: count(verifs, "result", "invalid"), label: t("overview.invalid"), hint: t("overview.last_200"), cls: count(verifs, "result", "invalid") ? "bad" : "" },
      { v: count(verifs, "result", "indeterminate"), label: t("overview.indeterminate"), hint: t("overview.indeterminate_hint"), cls: count(verifs, "result", "indeterminate") ? "warn" : "" },
    );
  }
  if (tiles.length) {
    app.insertAdjacentHTML("beforeend", `<div class="billboards n${tiles.length}">${tiles.map((tile) => `<div class="billboard ${tile.cls}"><div class="value">${tile.v}</div><div><div class="label">${esc(tile.label)}</div><div class="hint">${esc(tile.hint)}</div></div></div>`).join("")}</div>`);
  }
  const grid = document.createElement("div");
  grid.className = "grid";
  app.appendChild(grid);
  if (can("usage:read")) {
    const months = [...usage.months].reverse();
    const c = section(t("overview.activity"));
    c.classList.add("span-8");
    c.innerHTML += months.length
      ? lineChart(months.map((m) => m.month), [
          { name: t("overview.issued"), values: months.map((m) => m.totals["credential.issued"] || 0) },
          { name: t("overview.verifications"), values: months.map((m) => m.totals["verification.performed"] || 0) },
        ])
      : `<div class="empty">${t("overview.no_activity")}</div>`;
    grid.appendChild(c);
  }
  const quick = section(t("overview.quick_actions"));
  quick.classList.add(can("usage:read") ? "span-4" : "span-12");
  quick.innerHTML += `<div class="actions">
      ${can("credentials:issue") ? `<a href="#/credentials/new"><button type="button">${t("cred.new_offer")}</button></a>` : ""}
      ${can("verifications:create") ? `<a href="#/verify"><button type="button" class="secondary">${t("overview.request_wallet")}</button></a>` : ""}
      ${can("templates:write") ? `<a href="#/templates"><button type="button" class="secondary">${t("nav.templates")}</button></a>` : ""}
    </div>
    <p class="muted">${t("overview.issuer")} <code>${esc(org?.issuer || "")}</code></p>`;
  grid.appendChild(quick);
  if (can("verifications:create")) {
    const c = section(t("verify.latest"));
    c.classList.add("span-12");
    c.innerHTML += table([t("col.date"), t("col.result"), t("col.issuer"), t("col.type"), t("col.credential")], verifs.slice(0, 8).map((r) => [
      `<span class="mono">${fmt(r.created_at)}</span>`, tag(r.result), esc(r.issuer || "—"),
      esc((r.vct || "").split("/types/")[1] || r.vct || "—"), r.credential_id ? short(r.credential_id) : t("common.external"),
    ]));
    grid.appendChild(c);
  }
};

// Credenciales: listado (#/credentials) y nueva oferta (#/credentials/new).
views.credentials = async (sub) => (sub === "new" ? newOffer() : credentialList());

function pageHead(title, actions = "") {
  app.innerHTML = `<div class="page-head"><h1>${esc(title)}</h1><div class="actions">${actions}</div></div>`;
}

async function credentialList() {
  pageHead(t("cred.list"), can("credentials:issue") ? `<a class="button-link" href="#/credentials/new">+ ${t("cred.new_offer")}</a>` : "");
  const list = section("", "");
  app.appendChild(list);
  async function refreshList() {
    const items = await api("GET", "/v1/credentials?limit=100");
    list.innerHTML = table(
      ["Id", t("col.state"), t("col.delivery"), t("col.holder_ref"), t("col.template_vct"), t("col.created"), t("col.expires"), t("col.actions")],
      items.map((c) => [
        `<span class="mono">${esc(c.public_id)}</span>`,
        tag(c.state),
        c.state === "issued" || c.state === "revoked" ? ({ apple_pass: "Apple Wallet", google_pass: "Google Wallet" }[c.delivery] || t("cred.delivery_oid4vci")) : "—",
        esc(c.holder_reference || "—"),
        `<span class="mono">${esc(c.vct.split("/types/")[1] || c.vct)}</span>`,
        fmt(c.created_at),
        c.state === "offered" ? t("cred.offer_expires", { date: fmt(c.offer_expires_at) }) : fmt(c.expires_at),
        `<div class="actions">${
          c.state === "offered" && can("credentials:issue") ? `<button class="secondary" data-reset="${c.id}">${t("cred.new_link")}</button>` : ""
        }${
          (c.state === "offered" || c.state === "issued") && can("credentials:revoke")
            ? `<button class="danger" data-revoke="${c.id}">${c.state === "offered" ? t("cred.cancel") : t("common.revoke")}</button>`
            : ""
        }</div>`,
      ]),
      { filter: true },
    );
    bind(list, "[data-reset]", "click", async (el) => showOffer(await api("POST", `/v1/credentials/${el.dataset.reset}/offer:reset`)));
    bind(list, "[data-revoke]", "click", async (el) => {
      const reason = prompt(t("cred.revoke_prompt"), "holder_request");
      if (!reason) return;
      await api("POST", `/v1/credentials/${el.dataset.revoke}/revoke`, { reason });
      toast(t("cred.revoked"));
      await refreshList();
    });
  }
  await refreshList();
}

async function newOffer() {
  pageHead(t("cred.new_offer"), `<a class="button-link secondary" href="#/credentials">${t("cred.list")}</a>`);
  if (!can("credentials:issue")) { app.insertAdjacentHTML("beforeend", `<div class="card muted">${t("common.no_permission")}</div>`); return; }
  const templates = await api("GET", "/v1/templates").catch(() => []);
  const issue = section("", "", "offer");
  issue.appendChild(
    form(
      [
        { name: "template", label: t("cred.template"), type: "select", options: templates.map((x) => x.slug), help: "offer.template", after: `<div class="claims-guide" data-claims-guide></div>` },
        { name: "holder_reference", label: t("cred.holder_reference"), placeholder: "LEG-2026-00412", help: "offer.holder_reference" },
        { name: "claims", label: t("cred.claims"), type: "textarea", required: true, value: "{}", help: "offer.claims" },
      ],
      t("cred.create_offer"),
      async (d) => {
        const body = { template: d.template, claims: JSON.parse(d.claims) };
        if (d.holder_reference) body.holder_reference = d.holder_reference;
        showOffer(await api("POST", "/v1/credentials", body, { "Idempotency-Key": crypto.randomUUID() }));
      },
    ),
  );
  app.appendChild(issue);
  const editor = claimsEditor(issue.querySelector("[name=claims]"), (m) => toast(m, true));
  wireClaimsGuide(issue, templates, editor);
}

// Lista los campos de la versión publicada de la plantilla elegida y ofrece un ejemplo válido.
function walkSchema(node, prefix = "", required = []) {
  return Object.entries(node.properties || {}).flatMap(([name, sub]) => {
    const path = prefix + name;
    const own = { path, type: sub.type, required: required.includes(name), enum: sub.enum, max: sub.maxLength, min: sub.minimum };
    return sub.type === "object" ? [own, ...walkSchema(sub, path + ".", sub.required || [])] : [own];
  });
}
function exampleFor(node) {
  switch (node.type) {
    case "object": return Object.fromEntries(Object.entries(node.properties || {}).map(([k, v]) => [k, exampleFor(v)]));
    case "string": return node.enum ? node.enum[0] : "";
    case "integer": case "number": return node.enum ? node.enum[0] : node.minimum ?? 0;
    case "boolean": return false;
    case "date": return new Date().toISOString().slice(0, 10);
    default: return null;
  }
}
const typeLabel = (type) => t(`type.${type}`);
function wireClaimsGuide(card, templates, editor) {
  const select = card.querySelector("[name=template]");
  const guide = card.querySelector("[data-claims-guide]");
  const textarea = card.querySelector("[name=claims]");
  if (!select || !guide) return;
  const render = async () => {
    const tpl = templates.find((x) => x.slug === select.value);
    if (!tpl) { guide.innerHTML = `<p class="muted">${t("guide.no_templates_html")}</p>`; editor.setSchema(null); return; }
    const versions = await api("GET", `/v1/templates/${tpl.id}/versions`).catch(() => []);
    const v = [...versions].reverse().find((x) => x.state === "published");
    if (!v) {
      guide.innerHTML = `<p class="muted">${t("guide.no_version_html")}</p>`;
      editor.setSchema(null);
      return;
    }
    const sd = new Set(v.selective_disclosure);
    const fields = walkSchema(v.claims_schema, "", v.claims_schema.required || []);
    guide.innerHTML = `<div class="guide-head"><b>${t("guide.fields_of", { name: esc(tpl.name), version: v.version })}</b>
        <button type="button" class="secondary" data-insert>${t("guide.insert_example")}</button></div>` +
      table([t("col.field"), t("col.type"), t("col.required"), t("col.holder_can_hide")], fields.map((f) => [
        `<code>${esc(f.path)}</code>`,
        esc(typeLabel(f.type)) + (f.enum ? ` <span class="muted">(${esc(f.enum.join(" / "))})</span>` : ""),
        f.required ? `${t("common.yes")} *` : t("common.no"),
        sd.has(f.path) ? t("common.yes") : t("common.no"),
      ])) + `<p class="muted">${t("guide.validity", { days: v.validity_days })}</p>`;
    guide.querySelector("[data-insert]").addEventListener("click", () => {
      textarea.value = JSON.stringify(exampleFor(v.claims_schema), null, 2);
      editor.refresh();
    });
    if (!textarea.value.trim() || textarea.value.trim() === "{}") textarea.value = JSON.stringify(exampleFor(v.claims_schema), null, 2);
    editor.setSchema(v.claims_schema);
  };
  select.addEventListener("change", render);
  render();
}

function showOffer(r) {
  const el = section(t("offer.created"));
  el.innerHTML += `
    <div class="row">
      <div class="qr"><img alt="${t("offer.qr_alt")}" src="${r.qr_svg}"></div>
      <div>
        <p><b>${t("offer.link")}</b><br><a href="${esc(r.claim_url)}" target="_blank" rel="noopener"><code>${esc(r.claim_url)}</code></a></p>
        <p class="muted">${t("offer.choose", { channels: `<span data-channels>${t("offer.channel_oid4vci")}</span>` })}
          ${t("offer.direct_link")} <code>${esc(r.offer_uri)}</code></p>
        <div class="secret"><b>${t("offer.code")}</b> <span class="mono big">${esc(r.tx_code)}</span><br>
        <span class="muted">${t("offer.code_once", { date: fmt(r.offer_expires_at) })}</span></div>
        <p class="muted">Id: <span class="mono">${esc(r.public_id)}</span></p>
      </div>
    </div>`;
  app.querySelector(":scope > [data-offer]")?.remove();
  el.dataset.offer = "";
  app.insertBefore(el, app.children[1]);
  el.scrollIntoView({ behavior: "smooth" });
  // Los canales de pase dependen de la configuración del servidor: los mismos que verá el titular.
  fetch(new URL(r.claim_url).pathname.replace("/claim/", "/claim-info/"))
    .then((res) => (res.ok ? res.json() : null))
    .then((info) => {
      if (!info) return;
      const passes = [info.apple_pass && "Apple Wallet", info.google_pass && "Google Wallet"].filter(Boolean);
      el.querySelector("[data-channels]").innerHTML =
        passes.map((p) => `<b>${p}</b>`).join(", ") + (passes.length ? ` ${t("offer.or")} ` : "") + t("offer.channel_oid4vci");
    })
    .catch(() => {});
}

// Plantillas: listado (#/templates), alta (#/templates/new) y detalle con versiones (#/templates/{id}).
views.templates = async (sub) => (sub === "new" ? newTemplate() : sub ? templateDetail(sub) : templateList());

async function templateList() {
  pageHead(t("tpl.list"), can("templates:write") ? `<a class="button-link" href="#/templates/new">+ ${t("tpl.new")}</a>` : "");
  const templates = await api("GET", "/v1/templates");
  const versions = await Promise.all(templates.map((x) => api("GET", `/v1/templates/${x.id}/versions`).catch(() => [])));
  app.appendChild(section("", table(
    [t("common.name"), t("tpl.slug"), t("tpl.published_version"), t("tpl.drafts"), t("col.created"), ""],
    templates.map((x, i) => {
      const published = [...versions[i]].reverse().find((v) => v.state === "published");
      const drafts = versions[i].filter((v) => v.state === "draft").length;
      return [
        `<a href="#/templates/${x.id}"><b>${esc(x.name)}</b></a>`,
        `<span class="mono">${esc(x.slug)}</span>`,
        published ? tag(`v${published.version}`) : `<span class="tag warn">${t("tpl.not_published")}</span>`,
        drafts || "—",
        fmt(x.created_at),
        `<a class="button-link secondary small" href="#/templates/${x.id}">${t("common.open")}</a>`,
      ];
    }),
    { filter: true },
  )));
}

function newTemplate() {
  pageHead(t("tpl.new"), `<a class="button-link secondary" href="#/templates">${t("tpl.list")}</a>`);
  if (!can("templates:write")) { app.insertAdjacentHTML("beforeend", `<div class="card muted">${t("common.no_permission")}</div>`); return; }
  const c = section("", `<p class="muted">${t("tpl.new_intro")}</p>`, "templates");
  c.appendChild(form(
    [
      { name: "slug", label: t("tpl.slug"), required: true, placeholder: t("tpl.slug_placeholder"), help: "template.slug" },
      { name: "name", label: t("common.name"), required: true, placeholder: t("tpl.name_placeholder"), help: "template.name" },
    ],
    t("common.create"),
    async (d) => {
      const created = await api("POST", "/v1/templates", d);
      toast(t("tpl.created"));
      location.hash = `#/templates/${created.id}`; // siguiente paso: definir y publicar una versión
    },
  ));
  app.appendChild(c);
}

async function templateDetail(id) {
  const templates = await api("GET", "/v1/templates");
  const tpl = templates.find((x) => x.id === id);
  if (!tpl) { pageHead(t("nav.templates")); app.insertAdjacentHTML("beforeend", `<div class="card muted">${t("tpl.not_found")}</div>`); return; }
  pageHead(tpl.name, `<a class="button-link secondary" href="#/templates">${t("tpl.list")}</a>`);
  crumbs.innerHTML = `${esc(org?.name || "")} / <a href="#/templates">${esc(t("nav.templates"))}</a> / <b>${esc(tpl.name)}</b>`;
  const versions = await api("GET", `/v1/templates/${tpl.id}/versions`);
  const info = section(t("tpl.versions"));
  info.innerHTML += `<p class="muted"><span class="mono">${esc(tpl.slug)}</span> · <span class="mono">${esc(tpl.vct)}</span></p>` + table(
    [t("col.version"), t("col.state"), t("col.selective_disclosure"), t("col.validity_days"), t("col.actions")],
    versions.map((v) => [
      v.version,
      tag(v.state),
      esc(v.selective_disclosure.join(", ") || "—"),
      v.validity_days,
      v.state === "draft" && can("templates:write") ? `<button class="secondary" data-publish="${tpl.id}/${v.id}">${t("tpl.publish")}</button>` : "",
    ]),
  );
  if (!versions.some((v) => v.state === "published")) info.innerHTML += `<p class="note">${t("tpl.publish_hint")}</p>`;
  app.appendChild(info);
  bind(info, "[data-publish]", "click", async (el) => {
    await api("POST", `/v1/templates/${el.dataset.publish.replace("/", "/versions/")}/publish`);
    toast(t("tpl.published"));
    route();
  });
  if (!can("templates:write")) return;
  const c = section(t("tpl.new_version"));
  c.appendChild(form(
    [
      { name: "claims_schema", label: t("tpl.schema"), type: "textarea", required: true, value: JSON.stringify(versions.at(-1)?.claims_schema || DEFAULT_SCHEMA, null, 2), help: "version.claims_schema" },
      { name: "selective_disclosure", label: t("tpl.selective_disclosure"), value: versions.at(-1)?.selective_disclosure.join(", ") || "given_name, family_name, completion_date, course.grade", help: "version.selective_disclosure" },
      { name: "validity_days", label: t("col.validity_days"), type: "number", value: versions.at(-1)?.validity_days || 365, required: true, help: "version.validity_days" },
    ],
    t("tpl.create_version"),
    async (d) => {
      await api("POST", `/v1/templates/${tpl.id}/versions`, {
        claims_schema: JSON.parse(d.claims_schema),
        selective_disclosure: d.selective_disclosure.split(",").map((x) => x.trim()).filter(Boolean),
        validity_days: Number(d.validity_days),
      });
      toast(t("tpl.version_created"));
      route();
    },
  ));
  app.appendChild(c);
  const versionForm = c.querySelector("form");
  schemaEditor(versionForm.querySelector("[name=claims_schema]"), versionForm.querySelector("[name=selective_disclosure]"), (m) => toast(m, true));
}

const DEFAULT_SCHEMA = {
  type: "object",
  properties: {
    course: { type: "object", properties: { title: { type: "string", maxLength: 200 }, hours: { type: "integer", minimum: 1 }, grade: { type: "string", enum: ["A", "B", "C"] } }, required: ["title"] },
    given_name: { type: "string", maxLength: 100 },
    family_name: { type: "string", maxLength: 100 },
    completion_date: { type: "date" },
    student_id: { type: "string", maxLength: 64 },
  },
  required: ["course", "given_name", "family_name", "completion_date"],
};

views.verify = async () => {
  app.innerHTML = `<h1>${t("nav.verify")}</h1>`;
  const policies = await api("GET", "/v1/trust-policies");
  if (can("trust_policies:write")) {
    const c = section(t("ver.new_policy"), "", "policy");
    c.appendChild(
      form(
        [
          { name: "name", label: t("common.name"), required: true, placeholder: t("ver.policy_placeholder"), help: "policy.name" },
          { name: "accepted_vcts", label: t("ver.accepted_vcts"), help: "policy.accepted_vcts" },
          { name: "required_claims", label: t("ver.required_claims"), placeholder: "family_name", help: "policy.required_claims" },
          { name: "require_holder_binding", label: t("ver.holder_binding"), type: "checkbox", checked: true, help: "policy.require_holder_binding" },
        ],
        t("ver.create_policy"),
        async (d) => {
          await api("POST", "/v1/trust-policies", {
            name: d.name,
            accepted_vcts: d.accepted_vcts.split(",").map((s) => s.trim()).filter(Boolean),
            required_claims: d.required_claims.split(",").map((s) => s.trim()).filter(Boolean),
            require_holder_binding: d.require_holder_binding,
          });
          route();
        },
      ),
    );
    app.appendChild(c);
  }
  for (const p of policies) {
    const c = section(t("ver.policy", { name: p.name }));
    c.innerHTML += `<p class="muted">${t("ver.policy_summary", { vcts: esc(p.accepted_vcts.join(", ") || t("ver.all")), claims: esc(p.required_claims.join(", ") || t("ver.none")), binding: p.require_holder_binding ? t("common.yes") : t("common.no") })}</p>` +
      table([t("col.trusted_issuer"), t("col.hosted"), t("col.note"), ""], p.trusted_issuers.map((ti) => [
        `<code>${esc(ti.issuer)}</code>`, ti.hosted_org_id ? t("common.yes") : t("common.no"), esc(ti.note || ""),
        can("trust_policies:write") ? `<button class="danger" data-rm="${p.id}/${ti.id}">${t("common.remove")}</button>` : "",
      ]));
    if (can("trust_policies:write")) {
      c.appendChild(form([{ name: "issuer", label: t("ver.add_issuer"), required: true, placeholder: location.origin + "/issuers/org_…", help: "policy.issuer" }], t("common.add"), async (d) => {
        await api("POST", `/v1/trust-policies/${p.id}/issuers`, { issuer: d.issuer });
        route();
      }));
    }
    app.appendChild(c);
    bind(c, "[data-rm]", "click", async (el) => {
      await api("DELETE", `/v1/trust-policies/${el.dataset.rm.replace("/", "/issuers/")}`);
      route();
    });
  }
  if (policies.length && can("verifications:create")) {
    const w = section(t("ver.oid4vp"), "", "oid4vp");
    w.innerHTML += `<p class="muted">${t("ver.oid4vp_intro")}</p>`;
    const withVct = policies.filter((p) => p.accepted_vcts.length);
    if (!withVct.length) {
      w.innerHTML += `<p class="muted">${t("ver.no_vct")}</p>`;
    } else {
      w.appendChild(form([
        { name: "trust_policy_id", label: t("ver.policy_label"), type: "select", options: withVct.map((p) => ({ value: p.id, label: p.name })), help: "oid4vp.trust_policy_id" },
        { name: "claims", label: t("ver.claims_to_request"), placeholder: "family_name, course.grade", help: "oid4vp.claims" },
        { name: "client_id_scheme", label: t("ver.client_id_scheme"), type: "select", options: [
          { value: "x509_hash", label: t("ver.x509_hash") },
          { value: "x509_san_dns", label: t("ver.x509_san_dns") },
          { value: "redirect_uri", label: t("ver.redirect_uri") },
        ], help: "oid4vp.client_id_scheme" },
        { name: "encrypt_response", label: t("ver.encrypt"), type: "checkbox", checked: true, help: "oid4vp.encrypt_response" },
      ], t("ver.create_oid4vp"), async (d) => {
        const body = { trust_policy_id: d.trust_policy_id, client_id_scheme: d.client_id_scheme, encrypt_response: d.encrypt_response };
        const paths = d.claims.split(",").map((x) => x.trim()).filter(Boolean).map((x) => x.split("."));
        if (paths.length) body.claims = paths;
        const r = await api("POST", "/v1/oid4vp/requests", body);
        const out = document.createElement("div");
        out.innerHTML = `<div class="row"><div class="qr"><img alt="QR OID4VP" src="${r.qr_svg}"></div>
          <div><p><b>${t("ver.status")}</b> <span data-state>${tag(r.status)}</span></p>
          <p class="muted">${t("ver.request_summary", { date: fmt(r.expires_at), scheme: esc(r.client_id_scheme), mode: esc(r.response_mode) })} <code>${esc(JSON.stringify(r.dcql_query.credentials[0].claims ?? []))}</code></p>
          <p><b>${t("ver.same_device")}</b><br><code>${esc(r.request_uri)}</code></p><div data-result></div></div></div>`;
        w.appendChild(out);
        const until = new Date(r.expires_at).getTime();
        const poll = async () => {
          if (!document.body.contains(out)) return; // se cambió de vista
          const st = await api("GET", `/v1/oid4vp/requests/${r.id}`).catch(() => null);
          if (st) out.querySelector("[data-state]").innerHTML = tag(st.status) + (st.error ? ` <span class="muted">${esc(st.error)}</span>` : "") +
            (st.status === "pending" && st.request_fetched ? ` <span class="muted">${t("ver.fetched")}</span>` : "");
          if (st && st.status !== "pending") {
            const res = st.result;
            out.querySelector("[data-result]").innerHTML = res
              ? `<h2>${t("ver.result")} ${tag(res.result)} ${res.reason ? `<span class="muted">(${esc(res.reason)})</span>` : ""}</h2>` +
                table([t("col.check"), t("col.result"), t("col.code")], res.checks.map((k) => [esc(k.name), tag(k.outcome), esc(k.code)])) +
                (res.disclosed_claims ? `<h2>${t("ver.disclosed")}</h2><pre>${esc(JSON.stringify(res.disclosed_claims, null, 2))}</pre>` : "")
              : "";
            return;
          }
          if (Date.now() < until) setTimeout(poll, 2000);
          else out.querySelector("[data-state]").innerHTML = tag("expired");
        };
        setTimeout(poll, 2000);
      }));
    }
    app.appendChild(w);

    const c = section(t("ver.present"), "", "present");
    c.innerHTML += `<p class="muted">${t("ver.present_intro_html")}</p>`;
    let request = null;
    const reqForm = form([{ name: "trust_policy_id", label: t("ver.policy_label"), type: "select", options: policies.map((p) => ({ value: p.id, label: p.name })), help: "present.trust_policy_id" }], t("ver.create_presentation"), async (d, f) => {
      request = await api("POST", "/v1/presentation-requests", { trust_policy_id: d.trust_policy_id });
      f.insertAdjacentHTML("beforeend", `<div class="secret"><b>nonce:</b> <code>${esc(request.nonce)}</code><br><b>aud:</b> <code>${esc(request.aud)}</code><br><span class="muted">${t("ver.expires", { date: fmt(request.expires_at) })}</span></div>`);
    });
    c.appendChild(reqForm);
    c.appendChild(form([{ name: "presentation", label: t("ver.presentation"), type: "textarea", required: true, help: "present.presentation" }], t("ver.verify"), async (d) => {
      const body = { presentation: d.presentation.trim() };
      if (request) body.presentation_request_id = request.id; else body.trust_policy_id = policies[0].id;
      const r = await api("POST", "/v1/verifications", body);
      c.insertAdjacentHTML("beforeend", `<h2>${t("ver.result")} ${tag(r.result)} ${r.reason ? `<span class="muted">(${esc(r.reason)})</span>` : ""}</h2>` +
        table([t("col.check"), t("col.result"), t("col.code")], r.checks.map((k) => [esc(k.name), tag(k.outcome), esc(k.code)])) +
        (r.disclosed_claims ? `<h2>${t("ver.disclosed")}</h2><pre>${esc(JSON.stringify(r.disclosed_claims, null, 2))}</pre>` : ""));
    }));
    app.appendChild(c);
  }
  const records = await api("GET", "/v1/verifications?limit=50");
  app.appendChild(section(t("verify.latest"), table([t("col.date"), t("col.result"), t("col.issuer"), "vct", t("col.credential")], records.map((r) => [fmt(r.created_at), tag(r.result), esc(r.issuer || "—"), esc((r.vct || "").split("/types/")[1] || r.vct || "—"), r.credential_id ? short(r.credential_id) : t("common.external")]))));
};

views.members = async () => {
  app.innerHTML = `<h1>${t("nav.members")}</h1>`;
  const roles = ["owner", "admin", "issuer", "verifier", "auditor"];
  const c = section(t("mem.add"), "", "members");
  c.appendChild(form([
    { name: "email", label: t("col.email"), type: "email", required: true, help: "member.email" },
    { name: "display_name", label: t("common.name"), required: true, help: "member.display_name" },
    { name: "role", label: t("col.role"), type: "select", options: roles, help: "member.role" },
  ], t("common.add"), async (d) => {
    const r = await api("POST", "/v1/members", d);
    if (r.temporary_password) c.insertAdjacentHTML("beforeend", `<div class="secret">${t("mem.temp_password", { email: esc(r.email) })} <code>${esc(r.temporary_password)}</code></div>`);
    await refresh();
  }));
  app.appendChild(c);
  const list = section(t("nav.members"));
  app.appendChild(list);
  async function refresh() {
    const members = await api("GET", "/v1/members");
    list.innerHTML = `<h2>${t("nav.members")}</h2>` + table([t("col.email"), t("common.name"), t("col.role"), t("col.since"), ""], members.map((m) => [
      esc(m.email), esc(m.display_name),
      `<select data-role="${m.user_id}">${roles.map((r) => `<option ${r === m.role ? "selected" : ""}>${r}</option>`).join("")}</select>`,
      fmt(m.created_at),
      `<div class="actions">${m.user_id === me.actor_id ? `<span class="muted">${t("mem.you")}</span>` : `<button class="secondary" data-reset="${m.user_id}" data-email="${esc(m.email)}">${t("mem.reset_password")}</button><button class="danger" data-remove="${m.user_id}">${t("common.remove")}</button>`}</div>`,
    ]));
    bind(list, "[data-reset]", "click", async (el) => {
      if (!confirm(t("mem.confirm_reset", { email: el.dataset.email }))) return;
      const r = await api("POST", `/v1/members/${el.dataset.reset}/password-reset`);
      list.insertAdjacentHTML("afterbegin", `<div class="secret">${t("mem.temp_password", { email: esc(r.email) })} <code>${esc(r.temporary_password)}</code><br><span class="muted">${t("mem.reset_note")}</span></div>`);
    });
    bind(list, "[data-role]", "change", async (el) => { await api("PATCH", `/v1/members/${el.dataset.role}`, { role: el.value }); toast(t("mem.role_updated")); });
    bind(list, "[data-remove]", "click", async (el) => { if (confirm(t("mem.confirm_remove"))) { await api("DELETE", `/v1/members/${el.dataset.remove}`); await refresh(); } });
  }
  await refresh();
};

views["api-clients"] = async () => {
  app.innerHTML = `<h1>${t("nav.api_clients")}</h1>`;
  const perms = me.permissions.filter((p) => !["members:manage", "signing_keys:compromise"].includes(p));
  const c = section(t("api.new"), "", "apiclients");
  c.innerHTML += `<label>${t("col.permissions")}</label><div>${perms.map((p) => `<label class="perm"><input type="checkbox" class="inline" value="${p}"> ${p}</label>`).join("")}</div>`;
  c.appendChild(form([{ name: "name", label: t("common.name"), required: true, placeholder: t("api.name_placeholder"), help: "apiclient.name" }], t("api.create"), async (d) => {
    const permissions = [...c.querySelectorAll("input[type=checkbox]:checked")].map((x) => x.value);
    const r = await api("POST", "/v1/api-clients", { name: d.name, permissions });
    c.insertAdjacentHTML("beforeend", `<div class="secret">${t("api.key_once")} <code>${esc(r.key)}</code></div>`);
    await refresh();
  }));
  app.appendChild(c);
  const list = section(t("api.keys"));
  app.appendChild(list);
  async function refresh() {
    const items = await api("GET", "/v1/api-clients");
    list.innerHTML = `<h2>${t("api.keys")}</h2>` + table([t("common.name"), t("col.prefix"), t("col.permissions"), t("col.last_used"), t("col.state"), ""], items.map((k) => [
      esc(k.name), `<code>${esc(k.key_prefix)}</code>`, esc(k.permissions.join(", ")), fmt(k.last_used_at),
      k.revoked_at ? tag("revoked") : tag("active"), k.revoked_at ? "" : `<button class="danger" data-revoke="${k.id}">${t("common.revoke")}</button>`,
    ]));
    bind(list, "[data-revoke]", "click", async (el) => { await api("DELETE", `/v1/api-clients/${el.dataset.revoke}`); await refresh(); });
  }
  await refresh();
};

views["signing-keys"] = async () => {
  app.innerHTML = `<h1>${t("nav.signing_keys")}</h1>`;
  const org = await api("GET", "/v1/organization");
  const c = section(t("col.issuer"), "", "signingkeys");
  c.innerHTML += `<p>iss: <code>${esc(org.issuer)}</code><br>${t("sk.metadata")} <a href="/.well-known/jwt-vc-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">jwt-vc-issuer</a> · <a href="/.well-known/openid-credential-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">openid-credential-issuer</a></p>
    <div class="actions"><button data-rotate>${t("sk.rotate")}</button></div>`;
  app.appendChild(c);
  const list = section(t("api.keys"));
  app.appendChild(list);
  async function refresh() {
    const keys = await api("GET", "/v1/signing-keys");
    list.innerHTML = `<h2>${t("api.keys")}</h2>` + table(["kid", "Backend", t("col.state"), t("col.activated"), t("col.retired"), ""], keys.map((k) => [
      `<code>${esc(k.kid)}</code>`, esc(k.backend), tag(k.state), fmt(k.activated_at), fmt(k.retired_at),
      k.state !== "compromised" && can("signing_keys:compromise") ? `<button class="danger" data-compromise="${k.id}">${t("sk.compromise")}</button>` : "",
    ]));
    bind(list, "[data-compromise]", "click", async (el) => {
      if (confirm(t("sk.confirm_compromise"))) { await api("POST", `/v1/signing-keys/${el.dataset.compromise}/compromise`); await refresh(); }
    });
  }
  bind(c, "[data-rotate]", "click", async () => { await api("POST", "/v1/signing-keys/rotate"); toast(t("sk.rotated")); await refresh(); });
  await refresh();
};

views.audit = async () => {
  app.innerHTML = `<h1>${t("nav.audit")}</h1>`;
  const events = await api("GET", "/v1/audit-events?limit=200");
  app.appendChild(section("", table([t("col.date"), "Actor", t("col.action"), t("col.target"), t("col.detail"), "request_id"], events.map((e) => [
    fmt(e.occurred_at), `${esc(e.actor_type)} ${e.actor_id ? short(e.actor_id) : ""}`, `<code>${esc(e.action)}</code>`,
    `${esc(e.target_type || "")} ${e.target_id ? short(e.target_id) : ""}`, `<code>${esc(JSON.stringify(e.metadata))}</code>`, e.request_id ? short(e.request_id) : "",
  ]), { filter: true })));
};

views.usage = async () => {
  app.innerHTML = `<h1>${t("nav.usage")}</h1>`;
  const r = await api("GET", "/v1/usage?months=12");
  const kinds = ["credential.offered", "credential.issued", "verification.performed", "status_list.served"];
  app.appendChild(section(t("usage.by_month"), table([t("col.month"), ...kinds], r.months.map((m) => [m.month, ...kinds.map((k) => m.totals[k] || 0)]))));
};

// ---------------------------------------------------------------------------
// Configuración: cuenta propia, contraseña, organización y perfil del emisor
// ---------------------------------------------------------------------------
views.settings = async () => {
  app.innerHTML = `<h1>${t("nav.settings")}</h1>`;
  const [profile] = await Promise.all([api("GET", "/v1/organization/issuer-profile").catch(() => null)]);
  const langName = (code) => LANGS[code] || code;
  const manage = can("org:manage");

  // Mi cuenta
  const account = section(t("set.account"));
  account.innerHTML += `<p class="muted">${t("set.signed_in_as", { email: esc(me.email || "") })} · ${t("col.role")}: <b>${esc(me.role || "")}</b></p>`;
  account.appendChild(form([
    { name: "display_name", label: t("set.display_name"), required: true, value: me.display_name || "" },
    { name: "language", label: t("set.language"), type: "select", options: [
      { value: "", label: t("set.language_org_default", { language: langName(org.default_language) }) },
      ...Object.entries(LANGS).map(([value, label]) => ({ value, label })),
    ], after: `<p class="muted small">${t("set.language_hint")}</p>` },
    { name: "theme", label: t("set.theme"), type: "select", options: [
      { value: "dark", label: t("set.theme_dark") },
      { value: "light", label: t("set.theme_light") },
      { value: "system", label: t("set.theme_system") },
    ], after: `<p class="muted small">${t("set.theme_hint")}</p>` },
  ], t("common.save"), async (d) => {
    const language = d.language || null;
    await api("PATCH", "/v1/auth/me", { display_name: d.display_name, language, theme: d.theme });
    applyTheme(d.theme); // inmediato, sin recargar
    rememberLang(language); // el acceso de este navegador también lo usa
    if ((language || org.default_language) !== lang) { location.reload(); return; }
    toast(t("set.saved"));
    await loadMe();
  }));
  account.querySelector("[name=language]").value = me.language || "";
  account.querySelector("[name=theme]").value = me.theme || "dark";
  // Vista previa al elegir; se guarda con «Guardar».
  account.querySelector("[name=theme]").addEventListener("change", (ev) => applyTheme(ev.target.value));
  app.appendChild(account);

  // Contraseña
  const password = section(t("set.password"));
  password.innerHTML += `<p class="muted">${t("set.password_intro")}</p>`;
  password.appendChild(form([
    { name: "current_password", label: t("set.current_password"), type: "password", required: true, autocomplete: "current-password" },
    { name: "new_password", label: t("set.new_password"), type: "password", required: true, autocomplete: "new-password" },
    { name: "repeat_password", label: t("set.repeat_password"), type: "password", required: true, autocomplete: "new-password" },
  ], t("set.change_password"), async (d, f) => {
    if (d.new_password.length < 12) throw new Error(t("set.password_short"));
    if (d.new_password !== d.repeat_password) throw new Error(t("set.password_mismatch"));
    const r = await api("POST", "/v1/auth/password", { current_password: d.current_password, new_password: d.new_password });
    f.reset();
    toast(t("set.password_changed", { count: r.sessions_revoked }));
  }));
  app.appendChild(password);

  // Organización
  const orgCard = section(t("set.organization"));
  orgCard.innerHTML += `<dl class="facts">
      <dt>${t("set.public_id")}</dt><dd class="mono">${esc(org.public_id)}</dd>
      <dt>${t("col.issuer")} (iss)</dt><dd class="mono">${esc(org.issuer)}</dd>
      <dt>${t("sk.metadata").replace(/:$/, "")}</dt><dd><a href="/.well-known/jwt-vc-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">jwt-vc-issuer</a> · <a href="/.well-known/openid-credential-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">openid-credential-issuer</a></dd>
      <dt>${t("col.created")}</dt><dd>${fmt(org.created_at)}</dd>
    </dl>`;
  if (manage) {
    orgCard.appendChild(form([
      { name: "name", label: t("set.org_name"), required: true, value: org.name,
        after: `<p class="muted small">${t("set.org_name_hint")}</p>` },
      { name: "default_language", label: t("set.default_language"), type: "select", options: Object.entries(LANGS).map(([value, label]) => ({ value, label })),
        after: `<p class="muted small">${t("set.default_language_hint")}</p>` },
    ], t("common.save"), async (d) => {
      const updated = await api("PATCH", "/v1/organization", d);
      if (!me.language && !chosenLang && updated.default_language !== lang) { location.reload(); return; }
      toast(t("set.saved"));
      await loadMe();
      route();
    }));
    orgCard.querySelector("[name=default_language]").value = org.default_language;
  } else {
    orgCard.innerHTML += `<p class="muted">${t("set.org_name")}: <b>${esc(org.name)}</b> · ${t("set.default_language")}: <b>${esc(langName(org.default_language))}</b></p>`;
  }
  app.appendChild(orgCard);

  // Perfil del emisor (lo que ven titulares y verificadores)
  if (profile) {
    const issuer = section(t("set.issuer_profile"));
    issuer.innerHTML += `<p class="muted">${t("set.issuer_profile_intro")}</p>`;
    if (manage) {
      issuer.appendChild(form([
        { name: "display_name", label: t("set.issuer_name"), required: true, value: profile.display_name,
          after: `<p class="muted small">${t("set.issuer_name_hint")}</p>` },
        { name: "default_credential_validity_days", label: t("set.default_validity"), type: "number", required: true, value: profile.default_credential_validity_days },
        { name: "offer_ttl_hours", label: t("set.offer_ttl"), type: "number", required: true, value: profile.offer_ttl_hours },
      ], t("common.save"), async (d) => {
        await api("PUT", "/v1/organization/issuer-profile", {
          display_name: d.display_name,
          default_credential_validity_days: Number(d.default_credential_validity_days),
          offer_ttl_hours: Number(d.offer_ttl_hours),
        });
        toast(t("set.saved"));
      }));
    } else {
      issuer.innerHTML += `<p>${t("set.issuer_name")}: <b>${esc(profile.display_name)}</b> · ${t("set.default_validity")}: ${profile.default_credential_validity_days} · ${t("set.offer_ttl")}: ${profile.offer_ttl_hours}</p>`;
    }
    app.appendChild(issuer);
  }
};

// ---------------------------------------------------------------------------
// Sesión y enrutado
// ---------------------------------------------------------------------------
views.help = async (root = app) => {
  const anchor = location.hash.split("/")[2];
  root.innerHTML = `<h1>${t("nav.help")}</h1>
    <div class="help-layout">
      <nav class="help-toc" aria-label="${t("help.contents")}">
        <div class="filter"><input type="search" placeholder="${t("help.search")}" data-help-search aria-label="${t("help.search")}"></div>
        ${HELP.DOCS.map((d) => `<a href="#/help/${d.id}" data-toc="${d.id}">${esc(d.title)}</a>`).join("")}
        <a href="/docs" target="_blank" rel="noopener">${t("help.api_reference")} ↗</a>
      </nav>
      <div class="help-body">
        ${HELP.DOCS.map((d) => `<section class="card help-doc" id="help-${d.id}" data-doc="${d.id}"><h2>${esc(d.title)}</h2>${d.body}</section>`).join("")}
        <p class="empty" data-help-empty hidden>${t("help.no_results_html")}</p>
      </div>
    </div>`;
  const search = root.querySelector("[data-help-search]");
  search.addEventListener("input", () => {
    const term = search.value.trim().toLowerCase();
    let shown = 0;
    root.querySelectorAll("[data-doc]").forEach((el) => {
      const hit = !term || el.textContent.toLowerCase().includes(term);
      el.hidden = !hit;
      root.querySelector(`[data-toc="${el.dataset.doc}"]`).hidden = !hit;
      if (hit) shown++;
      // Abre las preguntas frecuentes que coinciden con la búsqueda.
      el.querySelectorAll("details.faq").forEach((d) => (d.open = Boolean(term) && d.textContent.toLowerCase().includes(term)));
    });
    root.querySelector("[data-help-empty]").hidden = shown > 0;
  });
  if (anchor) {
    const target = document.getElementById(`help-${anchor}`);
    target?.scrollIntoView({ block: "start" });
    root.querySelector(`[data-toc="${anchor}"]`)?.classList.add("active");
  }
};

const TITLE_KEYS = {
  overview: "nav.overview", credentials: "nav.credentials", templates: "nav.templates", verify: "nav.verify",
  settings: "nav.settings", members: "nav.members", "api-clients": "nav.api_clients", "signing-keys": "nav.signing_keys",
  audit: "nav.audit", usage: "nav.usage", help: "nav.help",
};
const SUB_TITLE_KEYS = { "credentials/new": "cred.new_offer", "templates/new": "tpl.new" };
const titleFor = (key, sub) => t(SUB_TITLE_KEYS[`${key}/${sub}`] || TITLE_KEYS[key] || "nav.overview");

async function loadMe() {
  if (!sessionStorage.getItem(TOKEN_KEY)) { me = null; return; }
  try {
    me = await api("GET", "/v1/auth/me");
    org = await api("GET", "/v1/organization");
    // Idioma: el de la cuenta, si no el elegido en este navegador, si no el de la organización.
    applyLang(me.language || chosenLang || org.default_language);
    applyTheme(me.theme);
    who.innerHTML = `<strong title="${esc(me.email || "")}">${esc(me.display_name || org.name)}</strong>${esc(org.name)} · ${esc(me.role || me.actor_type)}<br><button class="secondary" id="logout" type="button">${t("shell.logout")}</button>`;
    topbarRight.innerHTML = `<span class="pill" title="${esc(org.public_id)}">${t("shell.organization", { name: esc(org.name) })}</span>`;
    document.getElementById("logout").onclick = async () => {
      await api("POST", "/v1/auth/logout").catch(() => {});
      sessionStorage.removeItem(TOKEN_KEY);
      me = null;
      location.hash = "#/login";
      route();
    };
  } catch { me = null; }
}

async function route() {
  const [name, sub] = (location.hash.replace(/^#\//, "") || "overview").split("/");
  if (!me) {
    shell.hidden = true;
    auth.hidden = false;
    // La guía de uso es pública: se puede leer antes de iniciar sesión.
    authCard.classList.toggle("wide", name === "help");
    if (name === "help") {
      await views.help(authCard);
      authCard.insertAdjacentHTML("afterbegin", `<p><a href="#/login">← ${t("login.back")}</a></p>`);
    } else {
      views.login();
    }
    return;
  }
  auth.hidden = true;
  shell.hidden = false;
  const key = views[name] && name !== "login" ? name : "overview";
  const here = sub ? `#/${key}/${sub}` : `#/${key}`;
  // Activo: el enlace exacto (subopción) o, en un grupo, la opción padre de la página.
  document.querySelectorAll(".nav a, .sidebar-footer a").forEach((a) => {
    const href = a.getAttribute("href");
    const parent = a.classList.contains("nav-parent");
    // En el detalle (#/templates/{id}) queda marcada la subopción del listado.
    a.classList.toggle("active", !parent && (href === here || (!!a.closest(".nav-sub") && href === `#/${key}` && !!sub && sub !== "new")));
    a.classList.toggle("open", a.classList.contains("nav-parent") && href === `#/${key}`);
  });
  openGroupOf(key);
  const title = titleFor(key, sub);
  crumbs.innerHTML = sub
    ? `${esc(org?.name || "")} / <a href="#/${key}">${esc(t(TITLE_KEYS[key]))}</a> / <b>${esc(title)}</b>`
    : `${esc(org?.name || "")} / <b>${esc(title)}</b>`;
  document.title = `${title} · CredoSeal`;
  try { await views[key](sub); } catch (e) { app.innerHTML = `<div class="card">${t("common.error", { message: esc(e.message) })}</div>`; }
}

try {
  if (localStorage.getItem("aletheia.sidebar") === "collapsed") shell.classList.add("collapsed");
} catch { /* almacenamiento no disponible */ }

// Grupos del menú (Credenciales, Plantillas): se pliegan con la flecha y se recuerda el
// estado en este navegador. El grupo de la sección actual se abre al entrar en ella.
const NAV_GROUPS_KEY = "aletheia.nav.closed";
const closedGroups = new Set((() => { try { return JSON.parse(localStorage.getItem(NAV_GROUPS_KEY) || "[]"); } catch { return []; } })());
function setGroup(row, open, remember = true) {
  const sub = document.getElementById(row.querySelector(".nav-toggle").getAttribute("aria-controls"));
  row.classList.toggle("closed", !open);
  sub.hidden = !open;
  row.querySelector(".nav-toggle").setAttribute("aria-expanded", String(open));
  if (!remember) return;
  if (open) closedGroups.delete(row.dataset.group); else closedGroups.add(row.dataset.group);
  try { localStorage.setItem(NAV_GROUPS_KEY, JSON.stringify([...closedGroups])); } catch { /* idem */ }
}
function wireNavGroups() {
  document.querySelectorAll(".nav-row").forEach((row) => {
    const toggle = row.querySelector(".nav-toggle");
    toggle.setAttribute("aria-label", t("nav.toggle_group", { name: row.querySelector(".nav-parent").textContent.trim() }));
    toggle.addEventListener("click", () => setGroup(row, row.classList.contains("closed")));
    setGroup(row, !closedGroups.has(row.dataset.group), false);
  });
}
const openGroupOf = (key) => {
  const row = document.querySelector(`.nav-row[data-group="${key}"]`);
  if (row && row.classList.contains("closed")) setGroup(row, true);
};
document.getElementById("collapse").addEventListener("click", () => {
  shell.classList.toggle("collapsed");
  try { localStorage.setItem("aletheia.sidebar", shell.classList.contains("collapsed") ? "collapsed" : "open"); } catch { /* idem */ }
});

await loadMe();
await loadHelp();
translateStatic();
document.getElementById("auth-lang").appendChild(langSwitch());
decorateNav();
wireNavGroups();
window.addEventListener("hashchange", route);
route();
