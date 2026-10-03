// Idioma de la interfaz (panel y páginas públicas): español o inglés.
//
// Cada texto vive una sola vez en strings.js con sus dos traducciones juntas, así que no
// puede existir en un idioma y faltar en el otro (tests/test_admin_i18n.py lo comprueba).
// Las ayudas largas, que son prosa con HTML, están en help.js (es) y help-en.js (en).
//
// Elección: lo que el usuario eligió (localStorage) o, si no eligió, el idioma del navegador
// (español si empieza por «es»; inglés en cualquier otro caso).

import { STRINGS } from "./strings.js";

export const LANGS = { es: "Español", en: "English" };
const STORAGE_KEY = "aletheia.lang";

function detect() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && saved in LANGS) return saved;
  } catch { /* almacenamiento no disponible: se usa el navegador */ }
  return (navigator.language || "es").toLowerCase().startsWith("es") ? "es" : "en";
}

export const lang = detect();
export const locale = lang === "en" ? "en-US" : "es-UY";
document.documentElement.lang = lang;

// t("clave", { var: valor }) → texto en el idioma actual. Las variables {var} se sustituyen
// tal cual: quien las usa en HTML debe escaparlas antes.
export function t(key, vars = {}) {
  const entry = STRINGS[key];
  const text = entry ? (entry[lang] ?? entry.es) : key;
  return text.replace(/\{(\w+)\}/g, (_, name) => (name in vars ? String(vars[name]) : `{${name}}`));
}

export const has = (key) => key in STRINGS;

// Etiqueta legible de un claim (p. ej. «course.title»): la del catálogo (claim.*) o una
// derivada del nombre del campo.
export const claimLabel = (path, name = path.split(".").at(-1)) =>
  has(`claim.${path}`) ? t(`claim.${path}`) : name.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

export function setLang(next) {
  if (!(next in LANGS) || next === lang) return;
  try { localStorage.setItem(STORAGE_KEY, next); } catch { /* sólo para esta visita */ }
  location.reload();
}

// Selector de idioma (<select>) listo para insertar.
export function langSwitch() {
  const select = document.createElement("select");
  select.className = "lang-switch";
  select.setAttribute("aria-label", t("lang.label"));
  select.innerHTML = Object.entries(LANGS)
    .map(([code, name]) => `<option value="${code}" ${code === lang ? "selected" : ""}>${name}</option>`)
    .join("");
  select.addEventListener("change", () => setLang(select.value));
  return select;
}

// Textos fijos del HTML: data-i18n (contenido) y data-i18n-<atributo> (atributos).
export function translateStatic(root = document) {
  root.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  root.querySelectorAll("*").forEach((el) => {
    for (const { name, value } of [...el.attributes]) {
      if (name.startsWith("data-i18n-")) el.setAttribute(name.slice("data-i18n-".length), t(value));
    }
  });
}

export const fmtDateTime = (iso, opts = { dateStyle: "short", timeStyle: "short" }) =>
  iso ? new Date(iso).toLocaleString(locale, opts) : "—";
export const fmtDate = (value, opts = { dateStyle: "long" }) =>
  value ? new Date(value).toLocaleDateString(locale, opts) : "—";
