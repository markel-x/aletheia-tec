// Página de inicio de CredoSeal: idioma (el HTML trae el español en línea, para buscadores y
// para quien no ejecuta JS) y el formulario «Empezar gratis», que guarda una solicitud de acceso.

import { lang, langSwitch, t, translateStatic } from "./i18n.js";

if (lang !== "es") translateStatic();
document.title = t("home.meta.title");
// Idioma: arriba, donde se busca al llegar en el idioma equivocado; también en el pie.
document.getElementById("head-lang").appendChild(langSwitch());
document.getElementById("holder-lang").appendChild(langSwitch());

// Menú en pantallas chicas: se despliega bajo la cabecera y se cierra al elegir una sección.
const menuButton = document.querySelector(".menu-btn");
const siteNav = document.getElementById("site-nav");
const setMenu = (open) => {
  menuButton.setAttribute("aria-expanded", String(open));
  siteNav.classList.toggle("open", open);
  document.body.classList.toggle("menu-open", open);
};
menuButton.addEventListener("click", () => setMenu(!siteNav.classList.contains("open")));
siteNav.addEventListener("click", (ev) => { if (ev.target.closest("a")) setMenu(false); });
document.addEventListener("keydown", (ev) => { if (ev.key === "Escape") setMenu(false); });

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

// «Pruébelo ahora»: sólo si el servidor tiene una organización de demostración. Si no, la
// sección queda oculta y los enlaces a la demo llevan a «Cómo funciona».
const demoSection = document.getElementById("demo");
const demoForm = document.getElementById("demo-form");
const demoStatus = demoForm.querySelector(".form-status");
const sayDemo = (text, kind = "") => {
  demoStatus.textContent = text;
  demoStatus.className = `form-status ${kind}`;
};

function withoutDemo() {
  document.querySelectorAll(".nav-demo").forEach((a) => a.remove());
  const hero = document.querySelector(".hero-demo");
  hero.href = "#how";
  hero.textContent = t("home.hero.secondary");
}

// El token del formulario (firmado con la hora de carga) se exige al generar: filtra envíos
// automáticos que no pasan por la página.
let formToken = null;
fetch("/public/demo")
  .then((r) => (r.ok ? r.json() : { enabled: false }))
  .then(({ enabled, form_token }) => {
    formToken = form_token;
    if (enabled) demoSection.hidden = false;
    else withoutDemo();
  })
  .catch(withoutDemo);

const nameInput = document.getElementById("demo-name");
const previewName = document.getElementById("demo-preview-name");
const defaultPreview = previewName.textContent;
nameInput.addEventListener("input", () => {
  previewName.textContent = nameInput.value.trim() || defaultPreview;
});

demoForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const button = demoForm.querySelector("button[type=submit]");
  button.disabled = true;
  nameInput.classList.remove("invalid");
  sayDemo(t("home.demo.generating"));
  try {
    const res = await fetch("/public/demo-credential", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        given_name: nameInput.value.trim() || null,
        language: lang,
        form_token: formToken,
        nickname: document.getElementById("demo-nickname").value || null,
      }),
    });
    if (res.status === 201) {
      const offer = await res.json();
      const card = demoSection.querySelector(".demo-card");
      card.querySelector(".demo-qr").src = offer.qr_svg;
      document.getElementById("demo-code").textContent = offer.tx_code;
      document.getElementById("demo-open").href = offer.claim_url;
      card.querySelector(".demo-result").hidden = false;
      card.querySelector(".demo-placeholder").hidden = true;
      const hours = Math.max(1, Math.round((new Date(offer.offer_expires_at) - Date.now()) / 3.6e6));
      sayDemo(t("home.demo.ready", { hours }), "ok");
    } else if (res.status === 422) {
      nameInput.classList.add("invalid");
      nameInput.focus();
      sayDemo(t("home.demo.invalid_name"), "error");
    } else if (res.status === 429) {
      sayDemo(t("home.demo.rate_limited"), "error");
    } else if (res.status === 400) {
      sayDemo(t("home.demo.too_fast"), "error");
    } else {
      sayDemo(t("home.demo.error"), "error");
    }
  } catch {
    sayDemo(t("home.demo.error"), "error");
  } finally {
    button.disabled = false;
  }
});

// Botón «Empezar gratis» fijo en móviles, oculto cuando el formulario ya está a la vista.
const sticky = document.querySelector(".sticky-cta");
const start = document.getElementById("start");
if ("IntersectionObserver" in window) {
  new IntersectionObserver(([entry]) => sticky.classList.toggle("away", entry.isIntersecting)).observe(start);
}
