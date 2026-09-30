// Panel de Aletheia: módulos ES, sin dependencias. Cliente de /v1 con token de sesión.

const TOKEN_KEY = "aletheia.session";
const app = document.getElementById("app");
const nav = document.getElementById("nav");
const who = document.getElementById("who");
let me = null;

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = (iso) => (iso ? new Date(iso).toLocaleString() : "—");
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
    throw new Error(`${e.code || res.status}: ${e.message || "error"}${detail}`);
  }
  return data;
}

const can = (perm) => !!me && me.permissions.includes(perm);

function form(fields, submitLabel, onSubmit) {
  const f = document.createElement("form");
  f.innerHTML =
    fields
      .map((x) => {
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
      })
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

function table(headers, rows) {
  return `<table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${
    rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="muted">Sin datos</td></tr>`
  }</tbody></table>`;
}

function section(title, html) {
  const el = document.createElement("section");
  el.className = "card";
  el.innerHTML = (title ? `<h2>${esc(title)}</h2>` : "") + (html || "");
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
  app.innerHTML = `<div class="card login"><h1>Iniciar sesión</h1></div>`;
  app.querySelector(".card").appendChild(
    form(
      [
        { name: "email", label: "Correo", type: "email", required: true, autocomplete: "username" },
        { name: "password", label: "Contraseña", type: "password", required: true, autocomplete: "current-password" },
        { name: "organization", label: "Organización (org_…, sólo si pertenece a varias)" },
      ],
      "Entrar",
      async (d) => {
        const body = { email: d.email, password: d.password };
        if (d.organization) body.organization = d.organization;
        const r = await api("POST", "/v1/auth/login", body);
        sessionStorage.setItem(TOKEN_KEY, r.token);
        await loadMe();
        location.hash = "#/credentials";
      },
    ),
  );
};

views.credentials = async () => {
  app.innerHTML = `<h1>Credenciales</h1>`;
  if (can("credentials:issue")) {
    const templates = await api("GET", "/v1/templates").catch(() => []);
    const issue = section("Nueva oferta");
    issue.appendChild(
      form(
        [
          { name: "template", label: "Plantilla", type: "select", options: templates.map((t) => t.slug) },
          { name: "holder_reference", label: "Referencia del titular (opaca, opcional)" },
          { name: "claims", label: "Claims (JSON)", type: "textarea", required: true, value: '{\n  "course": {"title": "", "hours": 0},\n  "given_name": "",\n  "family_name": "",\n  "completion_date": "2026-01-01"\n}' },
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
  }
  const list = section("Emitidas y pendientes", "");
  app.appendChild(list);
  async function refreshList() {
    const items = await api("GET", "/v1/credentials?limit=100");
    list.innerHTML =
      "<h2>Emitidas y pendientes</h2>" +
      table(
        ["Id", "Estado", "Titular (ref.)", "Plantilla (vct)", "Creada", "Expira", "Acciones"],
        items.map((c) => [
          `<span class="mono">${esc(c.public_id)}</span>`,
          tag(c.state),
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

function showOffer(r) {
  const el = section("Oferta creada — entregue estos datos al titular por canales distintos");
  el.innerHTML += `
    <div class="row">
      <div class="qr"><img alt="QR de la oferta" src="${r.qr_svg}"></div>
      <div>
        <p><b>Enlace / QR (canal 1):</b><br><code>${esc(r.offer_uri)}</code></p>
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
    const c = section("Nueva plantilla");
    c.appendChild(
      form(
        [
          { name: "slug", label: "Slug (minúsculas, guiones; forma parte del vct)", required: true, placeholder: "course-completion" },
          { name: "name", label: "Nombre", required: true },
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
            { name: "claims_schema", label: "Esquema de claims (JSON restringido)", type: "textarea", required: true, value: JSON.stringify(versions.at(-1)?.claims_schema || DEFAULT_SCHEMA, null, 2) },
            { name: "selective_disclosure", label: "Rutas divulgables (separadas por coma)", value: versions.at(-1)?.selective_disclosure.join(", ") || "given_name, family_name, completion_date, course.grade" },
            { name: "validity_days", label: "Validez (días)", type: "number", value: versions.at(-1)?.validity_days || 365, required: true },
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
    const c = section("Nueva política de confianza");
    c.appendChild(
      form(
        [
          { name: "name", label: "Nombre", required: true },
          { name: "accepted_vcts", label: "vct aceptados (coma; vacío = todos)" },
          { name: "required_claims", label: "Claims requeridos (coma)" },
          { name: "require_holder_binding", label: "Exigir vinculación con el titular (KB-JWT)", type: "checkbox", checked: true },
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
      c.appendChild(form([{ name: "issuer", label: "Añadir emisor confiable (URL iss)", required: true, placeholder: location.origin + "/issuers/org_…" }], "Añadir", async (d) => {
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
    const w = section("Solicitar a un wallet (OID4VP)");
    w.innerHTML += `<p class="muted">Muestra un QR que un wallet OID4VP 1.0 escanea; el titular elige compartir los claims pedidos y el resultado aparece aquí.</p>`;
    const withVct = policies.filter((p) => p.accepted_vcts.length);
    if (!withVct.length) {
      w.innerHTML += `<p class="muted">Ninguna política define vct aceptados: agregue al menos uno para poder pedir la credencial por DCQL.</p>`;
    } else {
      w.appendChild(form([
        { name: "trust_policy_id", label: "Política", type: "select", options: withVct.map((p) => ({ value: p.id, label: p.name })) },
        { name: "claims", label: "Claims a pedir (rutas separadas por coma; vacío = los requeridos por la política)", placeholder: "family_name, course.grade" },
        { name: "client_id_scheme", label: "Identificación del verificador", type: "select", options: [
          { value: "x509_hash", label: "x509_hash — solicitud firmada (HAIP)" },
          { value: "x509_san_dns", label: "x509_san_dns — solicitud firmada, dominio en el certificado" },
          { value: "redirect_uri", label: "redirect_uri — sin firmar (sólo wallets que lo admitan)" },
        ] },
        { name: "encrypt_response", label: "Cifrar la respuesta del wallet (direct_post.jwt)", type: "checkbox", checked: true },
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

    const c = section("Verificar una presentación");
    c.innerHTML += `<p class="muted">1) Cree una solicitud y entregue <code>nonce</code> y <code>aud</code> al titular. 2) Pegue la presentación (SD-JWT~disclosures~KB-JWT).</p>`;
    let request = null;
    const reqForm = form([{ name: "trust_policy_id", label: "Política", type: "select", options: policies.map((p) => ({ value: p.id, label: p.name })) }], "Crear solicitud de presentación", async (d, f) => {
      request = await api("POST", "/v1/presentation-requests", { trust_policy_id: d.trust_policy_id });
      f.insertAdjacentHTML("beforeend", `<div class="secret"><b>nonce:</b> <code>${esc(request.nonce)}</code><br><b>aud:</b> <code>${esc(request.aud)}</code><br><span class="muted">expira ${fmt(request.expires_at)}</span></div>`);
    });
    c.appendChild(reqForm);
    c.appendChild(form([{ name: "presentation", label: "Presentación", type: "textarea", required: true }], "Verificar", async (d) => {
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
  const c = section("Añadir miembro");
  c.appendChild(form([
    { name: "email", label: "Correo", type: "email", required: true },
    { name: "display_name", label: "Nombre", required: true },
    { name: "role", label: "Rol", type: "select", options: roles },
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
  const c = section("Nueva clave");
  c.innerHTML += `<label>Permisos</label><div>${perms.map((p) => `<label class="perm"><input type="checkbox" class="inline" value="${p}"> ${p}</label>`).join("")}</div>`;
  c.appendChild(form([{ name: "name", label: "Nombre", required: true }], "Crear clave", async (d) => {
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
  const c = section("Emisor");
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
  ]))));
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
async function loadMe() {
  if (!sessionStorage.getItem(TOKEN_KEY)) { me = null; return; }
  try {
    me = await api("GET", "/v1/auth/me");
    const org = await api("GET", "/v1/organization");
    who.innerHTML = `${esc(org.name)} · ${esc(me.role || me.actor_type)} <button class="secondary" id="logout">Salir</button>`;
    document.getElementById("logout").onclick = async () => { await api("POST", "/v1/auth/logout").catch(() => {}); sessionStorage.removeItem(TOKEN_KEY); me = null; location.hash = "#/login"; };
  } catch { me = null; }
}

async function route() {
  const name = (location.hash.replace(/^#\//, "") || "credentials").split("/")[0];
  if (!me) { nav.hidden = true; who.innerHTML = ""; views.login(); return; }
  nav.hidden = false;
  nav.querySelectorAll("a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === `#/${name}`));
  const view = views[name] || views.credentials;
  try { await view(); } catch (e) { app.innerHTML = `<div class="card">Error: ${esc(e.message)}</div>`; }
}

window.addEventListener("hashchange", route);
await loadMe();
route();
