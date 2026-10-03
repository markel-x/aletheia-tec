// Página de inicio de CredoSeal: idioma (el HTML trae el español en línea, para buscadores y
// para quien no ejecuta JS) y el formulario «Empezar gratis», que guarda una solicitud de acceso.

import { lang, langSwitch, t, translateStatic } from "./i18n.js";

if (lang !== "es") translateStatic();
document.title = t("home.meta.title");
document.getElementById("holder-lang").appendChild(langSwitch());

const form = document.getElementById("access-form");
const status = form.querySelector(".form-status");
const say = (text, kind = "") => {
  status.textContent = text;
  status.className = `form-status ${kind}`;
};

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  form.querySelectorAll(".invalid").forEach((el) => el.classList.remove("invalid"));
  const bad = [...form.querySelectorAll("input[required], textarea[required], input[type=email]")].filter((el) => !el.checkValidity());
  if (bad.length) {
    bad.forEach((el) => el.classList.add("invalid"));
    bad[0].focus();
    say(t("home.form.invalid"), "error");
    return;
  }
  const data = Object.fromEntries(new FormData(form));
  const button = form.querySelector("button[type=submit]");
  button.disabled = true;
  say(t("home.form.sending"));
  try {
    const res = await fetch("/public/access-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...data, website: data.website || null, nickname: data.nickname || null, language: lang }),
    });
    if (res.status === 202) {
      form.reset();
      say(t("home.form.sent", { email: data.email }), "ok");
    } else if (res.status === 429) {
      say(t("home.form.rate_limited"), "error");
    } else if (res.status === 422) {
      say(t("home.form.invalid"), "error");
    } else {
      say(t("home.form.error"), "error");
    }
  } catch {
    say(t("home.form.error"), "error");
  } finally {
    button.disabled = false;
  }
});
