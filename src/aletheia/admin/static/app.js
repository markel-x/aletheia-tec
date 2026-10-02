// Panel de Aletheia: módulos ES, sin dependencias. Cliente de /v1 con token de sesión.

import { DOCS, ERROR_TIPS, FIELD_HELP, SECTION_HELP } from "./help.js";

const TOKEN_KEY = "aletheia.session";
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
const fmt = (iso) => (iso ? new Date(iso).toLocaleString("es-UY", { dateStyle: "short", timeStyle: "short" }) : "—");
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
    const tip = ERROR_TIPS[e.code] ? ` — ${ERROR_TIPS[e.code]}` : "";
    throw new Error(`${e.code || res.status}: ${e.message || "error"}${detail}${tip}`);
  }
  return data;
}

const can = (perm) => !!me && me.permissions.includes(perm);

// Ayuda desplegable bajo un campo o al inicio de una sección (contenido de help.js).
const fieldHelp = (key) =>
  key && FIELD_HELP[key]
    ? `<details class="field-help"><summary>Cómo completarlo</summary><div class="help-panel">${FIELD_HELP[key]}</div></details>`
    : "";
const sectionHelp = (key) =>
  key && SECTION_HELP[key]
    ? `<details class="section-help"><summary>¿Qué es esto?</summary><div class="help-panel">${SECTION_HELP[key]}</div></details>`
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
  const bar = filter && rows.length > 5 ? `<div class="filter"><input type="search" placeholder="Filtrar por texto" data-filter aria-label="Filtrar"></div>` : "";
  return `${bar}<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="muted">Sin datos</td></tr>`
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
    <div class="brand"><svg class="brand-mark" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 2 28 8v8c0 7.2-5 12.6-12 14C9 28.6 4 23.2 4 16V8z" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linejoin="round"/><path d="m10.5 16.2 3.8 3.8 7.4-8" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>aletheia</span></div>
    <h1>Inicie sesión para gestionar sus credenciales</h1>`;
  const f = form(
    [
      { name: "email", label: "Correo electrónico", type: "email", required: true, autocomplete: "username", help: "login.email" },
      { name: "password", label: "Contraseña", type: "password", required: true, autocomplete: "current-password", help: "login.password" },
    ],
    "Iniciar sesión",
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
          throw new Error("Pertenece a varias organizaciones: indique cuál.");
        }
        throw new Error(String(e.message).startsWith("invalid_credentials") ? "Correo o contraseña incorrectos." : e.message);
      }
      await loadMe();
      location.hash = "#/overview";
      route();
    },
  );
  f.querySelector("p").insertAdjacentHTML(
    "beforebegin",
    `<details class="more"><summary>¿Pertenece a varias organizaciones?</summary>
       <label for="f_organization">Organización (org_…)</label>
       <input id="f_organization" name="organization" autocomplete="off" placeholder="org_…">${fieldHelp("login.organization")}</details>`,
  );
  authCard.appendChild(f);
  authCard.insertAdjacentHTML("beforeend", `<p class="note">Las organizaciones las da de alta un operador de Aletheia. ¿Sin acceso? Pida una invitación a un administrador de su organización. <a href="#/help">Guía de uso</a></p>`);
  authCard.querySelector("input")?.focus();
};

// ---------------------------------------------------------------------------
// Resumen (tablero)
// ---------------------------------------------------------------------------
views.overview = async () => {
  app.innerHTML = `<h1>Resumen</h1>`;
  const [creds, usage, verifs] = await Promise.all([
    can("credentials:read") ? api("GET", "/v1/credentials?limit=500").catch(() => []) : [],
    can("usage:read") ? api("GET", "/v1/usage?months=6").catch(() => ({ months: [] })) : { months: [] },
    can("verifications:create") ? api("GET", "/v1/verifications?limit=200").catch(() => []) : [],
  ]);
  const count = (arr, key, val) => arr.filter((x) => x[key] === val).length;
  const tiles = [];
  if (can("credentials:read")) {
    tiles.push(
      { v: count(creds, "state", "issued"), label: "Credenciales emitidas", hint: "vigentes o expiradas", cls: "ok" },
      { v: count(creds, "state", "offered"), label: "Ofertas pendientes", hint: "esperando al wallet", cls: count(creds, "state", "offered") ? "warn" : "" },
      { v: count(creds, "state", "revoked"), label: "Revocadas / canceladas", hint: "irreversible", cls: count(creds, "state", "revoked") ? "bad" : "" },
    );
  }
  if (can("verifications:create")) {
    tiles.push(
      { v: count(verifs, "result", "valid"), label: "Verificaciones válidas", hint: "últimas 200", cls: "ok" },
      { v: count(verifs, "result", "invalid"), label: "Inválidas", hint: "últimas 200", cls: count(verifs, "result", "invalid") ? "bad" : "" },
      { v: count(verifs, "result", "indeterminate"), label: "Indeterminadas", hint: "dependencia no disponible", cls: count(verifs, "result", "indeterminate") ? "warn" : "" },
    );
  }
  if (tiles.length) {
    app.insertAdjacentHTML("beforeend", `<div class="billboards n${tiles.length}">${tiles.map((t) => `<div class="billboard ${t.cls}"><div class="value">${t.v}</div><div><div class="label">${esc(t.label)}</div><div class="hint">${esc(t.hint)}</div></div></div>`).join("")}</div>`);
  }
  const grid = document.createElement("div");
  grid.className = "grid";
  app.appendChild(grid);
  if (can("usage:read")) {
    const months = [...usage.months].reverse();
    const c = section("Actividad por mes");
    c.classList.add("span-8");
    c.innerHTML += months.length
      ? lineChart(months.map((m) => m.month), [
          { name: "Credenciales emitidas", values: months.map((m) => m.totals["credential.issued"] || 0) },
          { name: "Verificaciones", values: months.map((m) => m.totals["verification.performed"] || 0) },
        ])
      : `<div class="empty">Sin actividad registrada todavía.</div>`;
    grid.appendChild(c);
  }
  const quick = section("Acciones rápidas");
  quick.classList.add(can("usage:read") ? "span-4" : "span-12");
  quick.innerHTML += `<div class="actions">
      ${can("credentials:issue") ? `<a href="#/credentials"><button type="button">Nueva oferta</button></a>` : ""}
      ${can("verifications:create") ? `<a href="#/verify"><button type="button" class="secondary">Solicitar a un wallet</button></a>` : ""}
      ${can("templates:write") ? `<a href="#/templates"><button type="button" class="secondary">Plantillas</button></a>` : ""}
    </div>
    <p class="muted">Emisor: <code>${esc(org?.issuer || "")}</code></p>`;
  grid.appendChild(quick);
  if (can("verifications:create")) {
    const c = section("Últimas verificaciones");
    c.classList.add("span-12");
    c.innerHTML += table(["Fecha", "Resultado", "Emisor", "Tipo", "Credencial"], verifs.slice(0, 8).map((r) => [
      `<span class="mono">${fmt(r.created_at)}</span>`, tag(r.result), esc(r.issuer || "—"),
      esc((r.vct || "").split("/types/")[1] || r.vct || "—"), r.credential_id ? short(r.credential_id) : "externa",
    ]));
    grid.appendChild(c);
  }
};

views.credentials = async () => {
  app.innerHTML = `<h1>Credenciales</h1>`;
  if (can("credentials:issue")) {
    const templates = await api("GET", "/v1/templates").catch(() => []);
    const issue = section("Nueva oferta", "", "offer");
    issue.appendChild(
      form(
        [
          { name: "template", label: "Plantilla", type: "select", options: templates.map((t) => t.slug), help: "offer.template", after: `<div class="claims-guide" data-claims-guide></div>` },
          { name: "holder_reference", label: "Referencia del titular (opaca, opcional)", placeholder: "LEG-2026-00412", help: "offer.holder_reference" },
          { name: "claims", label: "Claims (JSON)", type: "textarea", required: true, value: "{}", help: "offer.claims" },
        ],
        "Crear oferta",
        async (d) => {
          const body = { template: d.template, claims: JSON.parse(d.claims) };
          if (d.holder_reference) body.holder_reference = d.holder_reference;
          const r = await api("POST", "/v1/credentials", body, { "Idempotency-Key": crypto.randomUUID() });
          showOffer(r);
          await refreshList();
        },
      ),
    );
    app.appendChild(issue);
    wireClaimsGuide(issue, templates);
  }
  const list = section("Emitidas y pendientes", "");
  app.appendChild(list);
  async function refreshList() {
    const items = await api("GET", "/v1/credentials?limit=100");
    list.innerHTML =
      "<h2>Emitidas y pendientes</h2>" +
      table(
        ["Id", "Estado", "Entrega", "Titular (ref.)", "Plantilla (vct)", "Creada", "Expira", "Acciones"],
        items.map((c) => [
          `<span class="mono">${esc(c.public_id)}</span>`,
          tag(c.state),
          c.state === "issued" || c.state === "revoked" ? ({ apple_pass: "Apple Wallet", google_pass: "Google Wallet" }[c.delivery] || "Wallet OID4VCI") : "—",
          esc(c.holder_reference || "—"),
          `<span class="mono">${esc(c.vct.split("/types/")[1] || c.vct)}</span>`,
          fmt(c.created_at),
          c.state === "offered" ? `oferta: ${fmt(c.offer_expires_at)}` : fmt(c.expires_at),
          `<div class="actions">${
            c.state === "offered" && can("credentials:issue") ? `<button class="secondary" data-reset="${c.id}">Nuevo enlace</button>` : ""
          }${
            (c.state === "offered" || c.state === "issued") && can("credentials:revoke")
              ? `<button class="danger" data-revoke="${c.id}">${c.state === "offered" ? "Cancelar" : "Revocar"}</button>`
              : ""
          }</div>`,
        ]),
        { filter: true },
      );
    bind(list, "[data-reset]", "click", async (el) => showOffer(await api("POST", `/v1/credentials/${el.dataset.reset}/offer:reset`)));
    bind(list, "[data-revoke]", "click", async (el) => {
      const reason = prompt("Motivo: superseded, issued_in_error, holder_request, policy_violation, key_compromise, other", "holder_request");
      if (!reason) return;
      await api("POST", `/v1/credentials/${el.dataset.revoke}/revoke`, { reason });
      toast("Revocada");
      await refreshList();
    });
  }
  await refreshList();
};

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
const TYPE_LABEL = { string: "texto", integer: "número entero", number: "número", boolean: "sí/no (true/false)", date: "fecha AAAA-MM-DD", object: "grupo" };
function wireClaimsGuide(card, templates) {
  const select = card.querySelector("[name=template]");
  const guide = card.querySelector("[data-claims-guide]");
  const textarea = card.querySelector("[name=claims]");
  if (!select || !guide) return;
  const render = async () => {
    const t = templates.find((x) => x.slug === select.value);
    if (!t) { guide.innerHTML = `<p class="muted">No hay plantillas publicadas. Cree una en <a href="#/templates">Plantillas</a>.</p>`; return; }
    const versions = await api("GET", `/v1/templates/${t.id}/versions`).catch(() => []);
    const v = [...versions].reverse().find((x) => x.state === "published");
    if (!v) { guide.innerHTML = `<p class="muted">La plantilla no tiene versión publicada.</p>`; return; }
    const sd = new Set(v.selective_disclosure);
    const fields = walkSchema(v.claims_schema, "", v.claims_schema.required || []);
    guide.innerHTML = `<div class="guide-head"><b>Campos de «${esc(t.name)}» (versión ${v.version})</b>
        <button type="button" class="secondary" data-insert>Insertar ejemplo</button></div>` +
      table(["Campo", "Tipo", "Obligatorio", "El titular puede ocultarlo"], fields.map((f) => [
        `<code>${esc(f.path)}</code>`,
        esc(TYPE_LABEL[f.type] || f.type) + (f.enum ? ` <span class="muted">(${esc(f.enum.join(" / "))})</span>` : ""),
        f.required ? "sí *" : "no",
        sd.has(f.path) ? "sí" : "no",
      ])) + `<p class="muted">Validez de cada credencial: ${v.validity_days} días.</p>`;
    guide.querySelector("[data-insert]").addEventListener("click", () => {
      textarea.value = JSON.stringify(exampleFor(v.claims_schema), null, 2);
      textarea.focus();
    });
    if (!textarea.value.trim() || textarea.value.trim() === "{}") textarea.value = JSON.stringify(exampleFor(v.claims_schema), null, 2);
  };
  select.addEventListener("change", render);
  render();
}

function showOffer(r) {
  const el = section("Oferta creada — entregue estos datos al titular por canales distintos");
  el.innerHTML += `
    <div class="row">
      <div class="qr"><img alt="QR de la oferta" src="${r.qr_svg}"></div>
      <div>
        <p><b>Enlace / QR para el titular (canal 1):</b><br><a href="${esc(r.claim_url)}" target="_blank" rel="noopener"><code>${esc(r.claim_url)}</code></a></p>
        <p class="muted">El titular elige ahí entre <b>Apple Wallet</b> o su wallet de credenciales (OpenID4VCI).
          Enlace directo para wallets: <code>${esc(r.offer_uri)}</code></p>
        <div class="secret"><b>Código tx_code (canal 2):</b> <span class="mono big">${esc(r.tx_code)}</span><br>
        <span class="muted">Se muestra una sola vez. Expira: ${fmt(r.offer_expires_at)}.</span></div>
        <p class="muted">Id: <span class="mono">${esc(r.public_id)}</span></p>
      </div>
    </div>`;
  app.insertBefore(el, app.children[1]);
  el.scrollIntoView({ behavior: "smooth" });
}

views.templates = async () => {
  app.innerHTML = `<h1>Plantillas</h1>`;
  const templates = await api("GET", "/v1/templates");
  if (can("templates:write")) {
    const c = section("Nueva plantilla", "", "templates");
    c.appendChild(
      form(
        [
          { name: "slug", label: "Identificador (slug)", required: true, placeholder: "certificado-curso", help: "template.slug" },
          { name: "name", label: "Nombre", required: true, placeholder: "Certificado de finalización de curso", help: "template.name" },
        ],
        "Crear",
        async (d) => {
          await api("POST", "/v1/templates", d);
          toast("Plantilla creada");
          route();
        },
      ),
    );
    app.appendChild(c);
  }
  for (const t of templates) {
    const versions = await api("GET", `/v1/templates/${t.id}/versions`);
    const c = section(`${t.name} · ${t.slug}`);
    c.innerHTML += `<p class="muted mono">${esc(t.vct)}</p>` + table(
      ["Versión", "Estado", "Divulgación selectiva", "Validez (días)", "Acciones"],
      versions.map((v) => [
        v.version,
        tag(v.state),
        esc(v.selective_disclosure.join(", ") || "—"),
        v.validity_days,
        v.state === "draft" && can("templates:write") ? `<button class="secondary" data-publish="${t.id}/${v.id}">Publicar</button>` : "",
      ]),
    );
    if (can("templates:write")) {
      c.innerHTML += `<h2>Nueva versión</h2>`;
      c.appendChild(
        form(
          [
            { name: "claims_schema", label: "Esquema de claims (JSON restringido)", type: "textarea", required: true, value: JSON.stringify(versions.at(-1)?.claims_schema || DEFAULT_SCHEMA, null, 2), help: "version.claims_schema" },
            { name: "selective_disclosure", label: "Campos que el titular puede ocultar (separados por coma)", value: versions.at(-1)?.selective_disclosure.join(", ") || "given_name, family_name, completion_date, course.grade", help: "version.selective_disclosure" },
            { name: "validity_days", label: "Validez (días)", type: "number", value: versions.at(-1)?.validity_days || 365, required: true, help: "version.validity_days" },
          ],
          "Crear versión (borrador)",
          async (d) => {
            await api("POST", `/v1/templates/${t.id}/versions`, {
              claims_schema: JSON.parse(d.claims_schema),
              selective_disclosure: d.selective_disclosure.split(",").map((s) => s.trim()).filter(Boolean),
              validity_days: Number(d.validity_days),
            });
            toast("Versión creada");
            route();
          },
        ),
      );
    }
    app.appendChild(c);
    bind(c, "[data-publish]", "click", async (el) => {
      await api("POST", `/v1/templates/${el.dataset.publish.replace("/", "/versions/")}/publish`);
      toast("Publicada");
      route();
    });
  }
};

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
  app.innerHTML = `<h1>Verificación</h1>`;
  const policies = await api("GET", "/v1/trust-policies");
  if (can("trust_policies:write")) {
    const c = section("Nueva política de confianza", "", "policy");
    c.appendChild(
      form(
        [
          { name: "name", label: "Nombre", required: true, placeholder: "admisión-posgrado", help: "policy.name" },
          { name: "accepted_vcts", label: "Tipos de credencial aceptados (vct, separados por coma)", help: "policy.accepted_vcts" },
          { name: "required_claims", label: "Datos requeridos (separados por coma)", placeholder: "family_name", help: "policy.required_claims" },
          { name: "require_holder_binding", label: "Exigir vinculación con el titular (KB-JWT)", type: "checkbox", checked: true, help: "policy.require_holder_binding" },
        ],
        "Crear política",
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
    const c = section(`Política: ${p.name}`);
    c.innerHTML += `<p class="muted">vct: ${esc(p.accepted_vcts.join(", ") || "todos")} · claims requeridos: ${esc(p.required_claims.join(", ") || "ninguno")} · vinculación: ${p.require_holder_binding ? "sí" : "no"}</p>` +
      table(["Emisor confiable", "Alojado", "Nota", ""], p.trusted_issuers.map((t) => [
        `<code>${esc(t.issuer)}</code>`, t.hosted_org_id ? "sí" : "no", esc(t.note || ""),
        can("trust_policies:write") ? `<button class="danger" data-rm="${p.id}/${t.id}">Quitar</button>` : "",
      ]));
    if (can("trust_policies:write")) {
      c.appendChild(form([{ name: "issuer", label: "Añadir emisor confiable (URL iss)", required: true, placeholder: location.origin + "/issuers/org_…", help: "policy.issuer" }], "Añadir", async (d) => {
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
    const w = section("Solicitar a un wallet (OID4VP)", "", "oid4vp");
    w.innerHTML += `<p class="muted">Muestra un QR que un wallet OID4VP 1.0 escanea; el titular elige compartir los claims pedidos y el resultado aparece aquí.</p>`;
    const withVct = policies.filter((p) => p.accepted_vcts.length);
    if (!withVct.length) {
      w.innerHTML += `<p class="muted">Ninguna política define vct aceptados: agregue al menos uno para poder pedir la credencial por DCQL.</p>`;
    } else {
      w.appendChild(form([
        { name: "trust_policy_id", label: "Política", type: "select", options: withVct.map((p) => ({ value: p.id, label: p.name })), help: "oid4vp.trust_policy_id" },
        { name: "claims", label: "Datos a pedir (separados por coma; vacío = los requeridos por la política)", placeholder: "family_name, course.grade", help: "oid4vp.claims" },
        { name: "client_id_scheme", label: "Identificación del verificador", type: "select", options: [
          { value: "x509_hash", label: "x509_hash — solicitud firmada (HAIP)" },
          { value: "x509_san_dns", label: "x509_san_dns — solicitud firmada, dominio en el certificado" },
          { value: "redirect_uri", label: "redirect_uri — sin firmar (sólo wallets que lo admitan)" },
        ], help: "oid4vp.client_id_scheme" },
        { name: "encrypt_response", label: "Cifrar la respuesta del wallet (direct_post.jwt)", type: "checkbox", checked: true, help: "oid4vp.encrypt_response" },
      ], "Crear solicitud OID4VP", async (d) => {
        const body = { trust_policy_id: d.trust_policy_id, client_id_scheme: d.client_id_scheme, encrypt_response: d.encrypt_response };
        const paths = d.claims.split(",").map((x) => x.trim()).filter(Boolean).map((x) => x.split("."));
        if (paths.length) body.claims = paths;
        const r = await api("POST", "/v1/oid4vp/requests", body);
        const out = document.createElement("div");
        out.innerHTML = `<div class="row"><div class="qr"><img alt="QR OID4VP" src="${r.qr_svg}"></div>
          <div><p><b>Estado:</b> <span data-state>${tag(r.status)}</span></p>
          <p class="muted">Expira ${fmt(r.expires_at)} · ${esc(r.client_id_scheme)} · ${esc(r.response_mode)} · pide: <code>${esc(JSON.stringify(r.dcql_query.credentials[0].claims ?? []))}</code></p>
          <p><b>Enlace (mismo dispositivo):</b><br><code>${esc(r.request_uri)}</code></p><div data-result></div></div></div>`;
        w.appendChild(out);
        const until = new Date(r.expires_at).getTime();
        const poll = async () => {
          if (!document.body.contains(out)) return; // se cambió de vista
          const st = await api("GET", `/v1/oid4vp/requests/${r.id}`).catch(() => null);
          if (st) out.querySelector("[data-state]").innerHTML = tag(st.status) + (st.error ? ` <span class="muted">${esc(st.error)}</span>` : "") +
            (st.status === "pending" && st.request_fetched ? ` <span class="muted">(el wallet descargó la solicitud)</span>` : "");
          if (st && st.status !== "pending") {
            const res = st.result;
            out.querySelector("[data-result]").innerHTML = res
              ? `<h2>Resultado: ${tag(res.result)} ${res.reason ? `<span class="muted">(${esc(res.reason)})</span>` : ""}</h2>` +
                table(["Comprobación", "Resultado", "Código"], res.checks.map((k) => [esc(k.name), tag(k.outcome), esc(k.code)])) +
                (res.disclosed_claims ? `<h2>Claims divulgados</h2><pre>${esc(JSON.stringify(res.disclosed_claims, null, 2))}</pre>` : "")
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

    const c = section("Verificar una presentación", "", "present");
    c.innerHTML += `<p class="muted">1) Cree una solicitud y entregue <code>nonce</code> y <code>aud</code> al titular. 2) Pegue la presentación (SD-JWT~disclosures~KB-JWT).</p>`;
    let request = null;
    const reqForm = form([{ name: "trust_policy_id", label: "Política", type: "select", options: policies.map((p) => ({ value: p.id, label: p.name })), help: "present.trust_policy_id" }], "Crear solicitud de presentación", async (d, f) => {
      request = await api("POST", "/v1/presentation-requests", { trust_policy_id: d.trust_policy_id });
      f.insertAdjacentHTML("beforeend", `<div class="secret"><b>nonce:</b> <code>${esc(request.nonce)}</code><br><b>aud:</b> <code>${esc(request.aud)}</code><br><span class="muted">expira ${fmt(request.expires_at)}</span></div>`);
    });
    c.appendChild(reqForm);
    c.appendChild(form([{ name: "presentation", label: "Presentación (SD-JWT~…~KB-JWT)", type: "textarea", required: true, help: "present.presentation" }], "Verificar", async (d) => {
      const body = { presentation: d.presentation.trim() };
      if (request) body.presentation_request_id = request.id; else body.trust_policy_id = policies[0].id;
      const r = await api("POST", "/v1/verifications", body);
      c.insertAdjacentHTML("beforeend", `<h2>Resultado: ${tag(r.result)} ${r.reason ? `<span class="muted">(${esc(r.reason)})</span>` : ""}</h2>` +
        table(["Comprobación", "Resultado", "Código"], r.checks.map((k) => [esc(k.name), tag(k.outcome), esc(k.code)])) +
        (r.disclosed_claims ? `<h2>Claims divulgados</h2><pre>${esc(JSON.stringify(r.disclosed_claims, null, 2))}</pre>` : ""));
    }));
    app.appendChild(c);
  }
  const records = await api("GET", "/v1/verifications?limit=50");
  app.appendChild(section("Últimas verificaciones", table(["Fecha", "Resultado", "Emisor", "vct", "Credencial"], records.map((r) => [fmt(r.created_at), tag(r.result), esc(r.issuer || "—"), esc((r.vct || "").split("/types/")[1] || r.vct || "—"), r.credential_id ? short(r.credential_id) : "externa"]))));
};

views.members = async () => {
  app.innerHTML = `<h1>Miembros</h1>`;
  const roles = ["owner", "admin", "issuer", "verifier", "auditor"];
  const c = section("Añadir miembro", "", "members");
  c.appendChild(form([
    { name: "email", label: "Correo", type: "email", required: true, help: "member.email" },
    { name: "display_name", label: "Nombre", required: true, help: "member.display_name" },
    { name: "role", label: "Rol", type: "select", options: roles, help: "member.role" },
  ], "Añadir", async (d) => {
    const r = await api("POST", "/v1/members", d);
    if (r.temporary_password) c.insertAdjacentHTML("beforeend", `<div class="secret">Contraseña temporal de ${esc(r.email)} (una sola vez): <code>${esc(r.temporary_password)}</code></div>`);
    await refresh();
  }));
  app.appendChild(c);
  const list = section("Miembros");
  app.appendChild(list);
  async function refresh() {
    const members = await api("GET", "/v1/members");
    list.innerHTML = "<h2>Miembros</h2>" + table(["Correo", "Nombre", "Rol", "Desde", ""], members.map((m) => [
      esc(m.email), esc(m.display_name),
      `<select data-role="${m.user_id}">${roles.map((r) => `<option ${r === m.role ? "selected" : ""}>${r}</option>`).join("")}</select>`,
      fmt(m.created_at), `<button class="danger" data-remove="${m.user_id}">Quitar</button>`,
    ]));
    bind(list, "[data-role]", "change", async (el) => { await api("PATCH", `/v1/members/${el.dataset.role}`, { role: el.value }); toast("Rol actualizado"); });
    bind(list, "[data-remove]", "click", async (el) => { if (confirm("¿Quitar miembro?")) { await api("DELETE", `/v1/members/${el.dataset.remove}`); await refresh(); } });
  }
  await refresh();
};

views["api-clients"] = async () => {
  app.innerHTML = `<h1>Claves de API</h1>`;
  const perms = me.permissions.filter((p) => !["members:manage", "signing_keys:compromise"].includes(p));
  const c = section("Nueva clave", "", "apiclients");
  c.innerHTML += `<label>Permisos</label><div>${perms.map((p) => `<label class="perm"><input type="checkbox" class="inline" value="${p}"> ${p}</label>`).join("")}</div>`;
  c.appendChild(form([{ name: "name", label: "Nombre", required: true, placeholder: "SIS académico — producción", help: "apiclient.name" }], "Crear clave", async (d) => {
    const permissions = [...c.querySelectorAll("input[type=checkbox]:checked")].map((x) => x.value);
    const r = await api("POST", "/v1/api-clients", { name: d.name, permissions });
    c.insertAdjacentHTML("beforeend", `<div class="secret">Clave (una sola vez): <code>${esc(r.key)}</code></div>`);
    await refresh();
  }));
  app.appendChild(c);
  const list = section("Claves");
  app.appendChild(list);
  async function refresh() {
    const items = await api("GET", "/v1/api-clients");
    list.innerHTML = "<h2>Claves</h2>" + table(["Nombre", "Prefijo", "Permisos", "Último uso", "Estado", ""], items.map((k) => [
      esc(k.name), `<code>${esc(k.key_prefix)}</code>`, esc(k.permissions.join(", ")), fmt(k.last_used_at),
      k.revoked_at ? tag("revoked") : tag("active"), k.revoked_at ? "" : `<button class="danger" data-revoke="${k.id}">Revocar</button>`,
    ]));
    bind(list, "[data-revoke]", "click", async (el) => { await api("DELETE", `/v1/api-clients/${el.dataset.revoke}`); await refresh(); });
  }
  await refresh();
};

views["signing-keys"] = async () => {
  app.innerHTML = `<h1>Claves de firma</h1>`;
  const org = await api("GET", "/v1/organization");
  const c = section("Emisor", "", "signingkeys");
  c.innerHTML += `<p>iss: <code>${esc(org.issuer)}</code><br>Metadatos: <a href="/.well-known/jwt-vc-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">jwt-vc-issuer</a> · <a href="/.well-known/openid-credential-issuer/issuers/${esc(org.public_id)}" target="_blank" rel="noopener">openid-credential-issuer</a></p>
    <div class="actions"><button data-rotate>Rotar clave (la actual pasa a retirada)</button></div>`;
  app.appendChild(c);
  const list = section("Claves");
  app.appendChild(list);
  async function refresh() {
    const keys = await api("GET", "/v1/signing-keys");
    list.innerHTML = "<h2>Claves</h2>" + table(["kid", "Backend", "Estado", "Activada", "Retirada", ""], keys.map((k) => [
      `<code>${esc(k.kid)}</code>`, esc(k.backend), tag(k.state), fmt(k.activated_at), fmt(k.retired_at),
      k.state !== "compromised" && can("signing_keys:compromise") ? `<button class="danger" data-compromise="${k.id}">Declarar comprometida</button>` : "",
    ]));
    bind(list, "[data-compromise]", "click", async (el) => {
      if (confirm("Irreversible: la clave sale del JWKS y las credenciales firmadas con ella dejan de verificar. ¿Continuar?")) { await api("POST", `/v1/signing-keys/${el.dataset.compromise}/compromise`); await refresh(); }
    });
  }
  bind(c, "[data-rotate]", "click", async () => { await api("POST", "/v1/signing-keys/rotate"); toast("Clave rotada"); await refresh(); });
  await refresh();
};

views.audit = async () => {
  app.innerHTML = `<h1>Auditoría</h1>`;
  const events = await api("GET", "/v1/audit-events?limit=200");
  app.appendChild(section("", table(["Fecha", "Actor", "Acción", "Objetivo", "Detalle", "request_id"], events.map((e) => [
    fmt(e.occurred_at), `${esc(e.actor_type)} ${e.actor_id ? short(e.actor_id) : ""}`, `<code>${esc(e.action)}</code>`,
    `${esc(e.target_type || "")} ${e.target_id ? short(e.target_id) : ""}`, `<code>${esc(JSON.stringify(e.metadata))}</code>`, e.request_id ? short(e.request_id) : "",
  ]), { filter: true })));
};

views.usage = async () => {
  app.innerHTML = `<h1>Consumo</h1>`;
  const r = await api("GET", "/v1/usage?months=12");
  const kinds = ["credential.offered", "credential.issued", "verification.performed", "status_list.served"];
  app.appendChild(section("Por mes", table(["Mes", ...kinds], r.months.map((m) => [m.month, ...kinds.map((k) => m.totals[k] || 0)]))));
};

// ---------------------------------------------------------------------------
// Sesión y enrutado
// ---------------------------------------------------------------------------
views.help = async (root = app) => {
  const anchor = location.hash.split("/")[2];
  root.innerHTML = `<h1>Ayuda</h1>
    <div class="help-layout">
      <nav class="help-toc" aria-label="Contenido">
        <div class="filter"><input type="search" placeholder="Buscar en la ayuda" data-help-search aria-label="Buscar en la ayuda"></div>
        ${DOCS.map((d) => `<a href="#/help/${d.id}" data-toc="${d.id}">${esc(d.title)}</a>`).join("")}
        <a href="/docs" target="_blank" rel="noopener">Referencia de la API ↗</a>
      </nav>
      <div class="help-body">
        ${DOCS.map((d) => `<section class="card help-doc" id="help-${d.id}" data-doc="${d.id}"><h2>${esc(d.title)}</h2>${d.body}</section>`).join("")}
        <p class="empty" data-help-empty hidden>Sin resultados. Pruebe con otras palabras o consulte la <a href="/docs" target="_blank" rel="noopener">referencia de la API</a>.</p>
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

const TITLES = {
  overview: "Resumen", credentials: "Credenciales", templates: "Plantillas", verify: "Verificación",
  members: "Miembros", "api-clients": "Claves de API", "signing-keys": "Claves de firma", audit: "Auditoría", usage: "Consumo",
  help: "Ayuda",
};

async function loadMe() {
  if (!sessionStorage.getItem(TOKEN_KEY)) { me = null; return; }
  try {
    me = await api("GET", "/v1/auth/me");
    org = await api("GET", "/v1/organization");
    who.innerHTML = `<strong title="${esc(org.name)}">${esc(org.name)}</strong>${esc(me.role || me.actor_type)}<br><button class="secondary" id="logout" type="button">Cerrar sesión</button>`;
    topbarRight.innerHTML = `<span class="pill" title="${esc(org.public_id)}">Organización: ${esc(org.name)}</span>`;
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
  const name = (location.hash.replace(/^#\//, "") || "overview").split("/")[0];
  if (!me) {
    shell.hidden = true;
    auth.hidden = false;
    // La guía de uso es pública: se puede leer antes de iniciar sesión.
    authCard.classList.toggle("wide", name === "help");
    if (name === "help") {
      await views.help(authCard);
      authCard.insertAdjacentHTML("afterbegin", `<p><a href="#/login">← Volver a iniciar sesión</a></p>`);
    } else {
      views.login();
    }
    return;
  }
  auth.hidden = true;
  shell.hidden = false;
  const key = views[name] && name !== "login" ? name : "overview";
  document.querySelectorAll(".nav a, .sidebar-footer a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#/${key}`));
  crumbs.innerHTML = `${esc(org?.name || "")} / <b>${esc(TITLES[key] || key)}</b>`;
  document.title = `${TITLES[key] || "Aletheia"} · Aletheia`;
  try { await views[key](); } catch (e) { app.innerHTML = `<div class="card">Error: ${esc(e.message)}</div>`; }
}

try {
  if (localStorage.getItem("aletheia.sidebar") === "collapsed") shell.classList.add("collapsed");
} catch { /* almacenamiento no disponible */ }
document.getElementById("collapse").addEventListener("click", () => {
  shell.classList.toggle("collapsed");
  try { localStorage.setItem("aletheia.sidebar", shell.classList.contains("collapsed") ? "collapsed" : "open"); } catch { /* idem */ }
});

decorateNav();
window.addEventListener("hashchange", route);
await loadMe();
route();
