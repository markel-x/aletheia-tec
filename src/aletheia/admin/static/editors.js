// Editores visuales para los campos JSON del panel: el esquema de claims de una plantilla y
// los datos (claims) de una oferta. El <textarea> original sigue siendo lo que se envía: el
// editor visual lo reescribe en cada cambio y el usuario puede pasar a JSON cuando quiera.
// Sin dependencias ni estilos en línea (CSP).

import { claimLabel, t } from "./i18n.js";

const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Mismas reglas que el servidor (issuance/schema.py).
const NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;
const RESERVED = new Set(["iss", "iat", "nbf", "exp", "vct", "cnf", "status", "_sd", "_sd_alg", "sub"]);
const MAX_DEPTH = 3;
const TYPES = ["string", "integer", "number", "boolean", "date", "object"];

// Etiqueta: la del esquema («title») o la del catálogo para los campos habituales.
const labelFor = (node, name, path) => node.title || claimLabel(path, name);

function el(tag, attrs = {}, html = "") {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === false || v === undefined || v === null) continue;
    node.setAttribute(k, v === true ? "" : v);
  }
  node.innerHTML = html;
  return node;
}

// Interruptor «Formulario | JSON» sobre el textarea. `toVisual` devuelve un mensaje de error
// si el JSON no se puede representar (se queda en JSON).
function modeSwitch(textarea, visual, { toVisual, onError }) {
  const bar = el("div", { class: "editor-switch", role: "group", "aria-label": t("editor.mode") },
    `<button type="button" data-mode="visual">${t("editor.form")}</button><button type="button" data-mode="json">JSON</button>`);
  textarea.before(bar, visual);
  const set = (mode) => {
    if (mode === "visual") {
      const problem = toVisual();
      if (problem) { onError(problem); return; }
    }
    visual.hidden = mode !== "visual";
    textarea.hidden = mode === "visual";
    bar.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.mode === mode));
  };
  bar.addEventListener("click", (ev) => {
    const b = ev.target.closest("button[data-mode]");
    if (!b) return;
    // Lo que el usuario elige se respeta en los redibujados (p. ej. al cambiar de plantilla).
    if (b.dataset.mode === "json") textarea.dataset.preferJson = "1";
    else delete textarea.dataset.preferJson;
    set(b.dataset.mode);
  });
  return set;
}

function parseJson(text, fallback) {
  if (!text.trim()) return { value: fallback };
  try { return { value: JSON.parse(text) }; } catch { return { error: t("editor.invalid_json") }; }
}

// ---------------------------------------------------------------------------
// Datos de la credencial (claims) a partir del esquema de la plantilla
// ---------------------------------------------------------------------------
export function claimsEditor(textarea, onError) {
  const visual = el("div", { class: "visual-editor" });
  let schema = null;

  const fieldFor = (name, node, value, required, path) => {
    const id = `claim_${path.replace(/\./g, "__")}`;
    const label = `${esc(labelFor(node, name, path))}${required ? ' <span class="req">*</span>' : ""}`;
    const hint = node.description ? `<span class="hint">${esc(node.description)}</span>` : "";
    if (node.type === "object") {
      const fs = el("fieldset", { "data-group": path }, `<legend>${label}</legend>${hint}`);
      for (const [k, sub] of Object.entries(node.properties || {})) {
        fs.appendChild(fieldFor(k, sub, value?.[k], (node.required || []).includes(k), `${path}.${k}`));
      }
      return fs;
    }
    const wrap = el("div", { class: "claim-field" });
    if (node.type === "boolean") {
      wrap.innerHTML = `<label><input type="checkbox" class="inline" id="${id}" data-path="${esc(path)}" data-type="boolean" ${value ? "checked" : ""}> ${label}</label>${hint}`;
      return wrap;
    }
    let input;
    if (node.enum) {
      input = `<select id="${id}" data-path="${esc(path)}" data-type="${node.type}">${required ? "" : '<option value="">—</option>'}${node.enum
        .map((o) => `<option value="${esc(o)}" ${String(value) === String(o) ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
    } else if (node.type === "integer" || node.type === "number") {
      input = `<input id="${id}" type="number" data-path="${esc(path)}" data-type="${node.type}" step="${node.type === "integer" ? 1 : "any"}"
        ${node.minimum !== undefined ? `min="${node.minimum}"` : ""} ${node.maximum !== undefined ? `max="${node.maximum}"` : ""} value="${esc(value ?? "")}">`;
    } else if (node.type === "date") {
      input = `<input id="${id}" type="date" data-path="${esc(path)}" data-type="date" value="${esc(value ?? "")}">`;
    } else {
      input = `<input id="${id}" type="text" data-path="${esc(path)}" data-type="string" ${node.maxLength ? `maxlength="${node.maxLength}"` : ""} value="${esc(value ?? "")}" autocomplete="off">`;
    }
    wrap.innerHTML = `<label for="${id}">${label}</label>${input}${hint}`;
    return wrap;
  };

  const collect = () => {
    const out = {};
    const requiredAt = (path) => {
      const parts = path.split(".");
      let node = schema;
      for (const p of parts.slice(0, -1)) node = node.properties[p];
      return (node.required || []).includes(parts.at(-1));
    };
    visual.querySelectorAll("[data-path]").forEach((input) => {
      const path = input.dataset.path;
      const type = input.dataset.type;
      let value;
      if (type === "boolean") value = input.checked ? true : requiredAt(path) ? false : undefined;
      else if (input.value === "") value = undefined;
      else if (type === "integer") value = Number.parseInt(input.value, 10);
      else if (type === "number") value = Number(input.value);
      else value = input.value;
      if (value === undefined) return;
      const parts = path.split(".");
      let target = out;
      for (const p of parts.slice(0, -1)) target = target[p] ??= {};
      target[parts.at(-1)] = value;
    });
    return out;
  };

  const render = (values) => {
    visual.innerHTML = "";
    if (!schema) {
      visual.innerHTML = `<p class="muted">${t("editor.pick_template")}</p>`;
      return;
    }
    for (const [k, sub] of Object.entries(schema.properties || {})) {
      visual.appendChild(fieldFor(k, sub, values?.[k], (schema.required || []).includes(k), k));
    }
    visual.appendChild(el("p", { class: "muted small" }, `<span class="req">*</span> ${t("editor.required_note")}`));
  };

  const sync = () => { textarea.value = JSON.stringify(collect(), null, 2); };
  visual.addEventListener("input", sync);
  visual.addEventListener("change", sync);

  const setMode = modeSwitch(textarea, visual, {
    toVisual: () => {
      const parsed = parseJson(textarea.value, {});
      if (parsed.error) return parsed.error;
      if (typeof parsed.value !== "object" || Array.isArray(parsed.value) || parsed.value === null) return t("editor.claims_object");
      render(parsed.value);
      return null;
    },
    onError,
  });

  setMode("json");
  return {
    // Plantilla elegida (o ninguna): con esquema se muestra el formulario; sin él, sólo JSON.
    setSchema(next) {
      schema = next;
      setMode(schema && !textarea.dataset.preferJson ? "visual" : "json");
    },
    // El textarea cambió desde fuera («Insertar ejemplo»): el formulario lo refleja.
    refresh() {
      const parsed = parseJson(textarea.value, {});
      if (schema && !parsed.error) render(parsed.value);
    },
  };
}

// ---------------------------------------------------------------------------
// Esquema de claims de una versión de plantilla
// ---------------------------------------------------------------------------
// Modelo: lista de campos { name, node (sin properties/required), required, hidden, children }.
function toModel(schema, sd, prefix = "") {
  return Object.entries(schema.properties || {}).map(([name, sub]) => {
    const { properties, required, ...node } = sub;
    const path = prefix + name;
    return {
      name,
      node,
      required: (schema.required || []).includes(name),
      hidden: sd.has(path),
      children: sub.type === "object" ? toModel(sub, sd, path + ".") : [],
    };
  });
}

function fromModel(fields) {
  const properties = {};
  const required = [];
  for (const f of fields) {
    if (!f.name) continue;
    properties[f.name] = f.node.type === "object" ? { ...f.node, ...fromModel(f.children) } : { ...f.node };
    if (f.required) required.push(f.name);
  }
  return { properties, ...(required.length ? { required } : {}) };
}

function hiddenPaths(fields, prefix = "") {
  return fields.flatMap((f) => [
    ...(f.hidden && f.name ? [prefix + f.name] : []),
    ...hiddenPaths(f.children, prefix + f.name + "."),
  ]);
}

export function schemaEditor(textarea, sdInput, onError) {
  const visual = el("div", { class: "visual-editor schema-editor" });
  let model = [];

  const sync = () => {
    textarea.value = JSON.stringify({ type: "object", ...fromModel(model) }, null, 2);
    if (sdInput) sdInput.value = hiddenPaths(model).join(", ");
  };

  const nameProblem = (name, depth, siblings) => {
    if (!name) return ""; // fila nueva o vacía: se omite al guardar
    if (!NAME_RE.test(name)) return t("editor.name_rule");
    if (depth === 2 && RESERVED.has(name)) return t("editor.name_reserved");
    if (siblings.filter((s) => s.name === name).length > 1) return t("editor.name_repeated");
    return "";
  };

  const options = (f) => {
    const n = f.node;
    if (n.type === "string") {
      return `<label>${t("editor.max_length")}<input type="number" min="1" max="1000" data-opt="maxLength" value="${esc(n.maxLength ?? "")}"></label>
        <label>${t("editor.allowed_values")} <span class="muted">${t("editor.allowed_values_hint")}</span><input type="text" data-opt="enum" value="${esc((n.enum || []).join(", "))}"></label>`;
    }
    if (n.type === "integer" || n.type === "number") {
      return `<label>${t("editor.minimum")}<input type="number" data-opt="minimum" value="${esc(n.minimum ?? "")}"></label>
        <label>${t("editor.maximum")}<input type="number" data-opt="maximum" value="${esc(n.maximum ?? "")}"></label>`;
    }
    return "";
  };

  const renderList = (fields, depth, container, prefix) => {
    fields.forEach((f, i) => {
      const problem = nameProblem(f.name, depth, fields);
      const row = el("div", { class: "schema-field" });
      const types = TYPES.filter((type) => type !== "object" || depth < MAX_DEPTH)
        .map((type) => `<option value="${type}" ${f.node.type === type ? "selected" : ""}>${t(`editor.type.${type}`)}</option>`).join("");
      row.innerHTML = `
        <div class="schema-row">
          <label>${t("editor.name")}<input type="text" data-k="name" value="${esc(f.name)}" placeholder="${t("editor.name_placeholder")}" class="${problem ? "invalid" : ""}" autocomplete="off"></label>
          <label>${t("editor.label")}<input type="text" data-k="title" value="${esc(f.node.title ?? "")}" placeholder="${t("editor.label_placeholder")}" autocomplete="off"></label>
          <label>${t("editor.type")}<select data-k="type">${types}</select></label>
          <label class="check"><input type="checkbox" class="inline" data-k="required" ${f.required ? "checked" : ""}>${t("editor.required")}</label>
          <label class="check" title="${t("editor.hidden_hint")}"><input type="checkbox" class="inline" data-k="hidden" ${f.hidden ? "checked" : ""}>${t("editor.hidden")}</label>
          <button type="button" class="danger small" data-k="remove" aria-label="${t("editor.remove_named", { name: esc(f.name || t("editor.field")) })}">${t("editor.remove")}</button>
        </div>
        ${problem ? `<p class="field-error">${esc(problem)}</p>` : ""}
        ${options(f) ? `<div class="schema-options">${options(f)}</div>` : ""}`;
      const bindField = (selector, handler, event = "input") => row.querySelector(selector)?.addEventListener(event, handler);
      bindField('[data-k="name"]', (ev) => {
        f.name = ev.target.value.trim();
        const p = nameProblem(f.name, depth, fields);
        ev.target.classList.toggle("invalid", !!p);
        let msg = row.querySelector(":scope > .field-error");
        if (p && !msg) { msg = el("p", { class: "field-error" }); row.querySelector(".schema-row").after(msg); }
        if (msg) { if (p) msg.textContent = p; else msg.remove(); }
        sync();
      });
      bindField('[data-k="title"]', (ev) => {
        if (ev.target.value) f.node.title = ev.target.value; else delete f.node.title;
        sync();
      });
      bindField('[data-k="type"]', (ev) => {
        const keep = Object.fromEntries(Object.entries(f.node).filter(([k]) => k === "title" || k === "description"));
        f.node = { type: ev.target.value, ...keep };
        f.children = ev.target.value === "object" ? f.children : [];
        sync();
        render();
      }, "change");
      bindField('[data-k="required"]', (ev) => { f.required = ev.target.checked; sync(); }, "change");
      bindField('[data-k="hidden"]', (ev) => { f.hidden = ev.target.checked; sync(); }, "change");
      bindField('[data-k="remove"]', () => { fields.splice(i, 1); sync(); render(); }, "click");
      row.querySelectorAll("[data-opt]").forEach((input) => input.addEventListener("input", () => {
        const key = input.dataset.opt;
        const raw = input.value.trim();
        if (raw === "") delete f.node[key];
        else if (key === "enum") f.node.enum = raw.split(",").map((s) => s.trim()).filter(Boolean);
        else f.node[key] = Number(raw);
        if (key === "enum" && !f.node.enum?.length) delete f.node.enum;
        sync();
      }));
      if (f.node.type === "object") {
        const group = el("div", { class: "schema-group" });
        renderList(f.children, depth + 1, group, prefix + f.name + ".");
        const add = el("button", { type: "button", class: "secondary small" }, `+ ${t("editor.add_in_group", { name: esc(f.node.title || f.name || t("editor.group")) })}`);
        add.addEventListener("click", () => { f.children.push(newField()); sync(); render(); });
        group.appendChild(add);
        row.appendChild(group);
      }
      container.appendChild(row);
    });
  };

  const newField = () => ({ name: "", node: { type: "string" }, required: false, hidden: false, children: [] });

  const render = () => {
    visual.innerHTML = "";
    renderList(model, 2, visual, "");
    const add = el("button", { type: "button", class: "secondary" }, `+ ${t("editor.add_field")}`);
    add.addEventListener("click", () => { model.push(newField()); sync(); render(); visual.querySelector(':scope > .schema-field:last-of-type [data-k="name"]')?.focus(); });
    visual.appendChild(add);
  };

  const setMode = modeSwitch(textarea, visual, {
    toVisual: () => {
      const parsed = parseJson(textarea.value, { type: "object", properties: {} });
      if (parsed.error) return parsed.error;
      const schema = parsed.value;
      if (schema?.type !== "object" || typeof schema.properties !== "object") return t("editor.schema_object");
      const sd = new Set((sdInput?.value || "").split(",").map((s) => s.trim()).filter(Boolean));
      model = toModel(schema, sd);
      render();
      return null;
    },
    onError,
  });
  setMode("visual");
}
