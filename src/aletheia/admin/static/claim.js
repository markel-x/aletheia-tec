// Página del titular: recibir la credencial en Apple Wallet o Google Wallet (pases) o en una
// wallet OpenID4VCI.

import { applyLang, chosenLang, fmtDateTime, lang, langSwitch, t, translateStatic } from "./i18n.js";

// Textos fijos y selector, una vez decidido el idioma (el de la organización emisora, salvo
// que el visitante haya elegido otro en este navegador).
let chromeDone = false;
function chrome(orgLanguage) {
  if (chromeDone) return;
  chromeDone = true;
  if (!chosenLang) applyLang(orgLanguage);
  translateStatic();
  document.getElementById("holder-lang").appendChild(langSwitch());
  document.title = t("claim.page_title");
}

const root = document.getElementById("claim");
const offerId = location.pathname.split("/").filter(Boolean)[1] || "";
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = (iso) => fmtDateTime(iso, { dateStyle: "long", timeStyle: "short" });

const ERRORS = ["invalid_tx_code", "locked", "unavailable", "google_unavailable"];

// El código se pide igual en cada opción; los id distinguen los campos de cada formulario.
const codeField = (id, attemptsLeft) => `
        <label for="${id}">${t("claim.code")}</label>
        <input id="${id}" name="tx_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required placeholder="••••••">
        <details class="field-help"><summary>${t("claim.where_code")}</summary><div class="help-panel">
          ${t("claim.where_code_html", { attempts: esc(attemptsLeft) })}</div></details>`;

async function main() {
  const error = new URLSearchParams(location.search).get("error");
  const res = await fetch(`/claim-info/${encodeURIComponent(offerId)}`);
  const info = res.ok ? await res.json() : null;
  chrome(info?.language);
  if (!info) {
    root.innerHTML = `<h1>${t("claim.unavailable_title")}</h1><p>${t("claim.unavailable_body")}</p>`;
    return;
  }
  root.innerHTML = `
    <h1>${t("claim.title")}</h1>
    <p class="lead">${t("claim.lead_html", { credential: esc(info.credential_name), issuer: esc(info.issuer_name) })}</p>
    <p class="muted small">${t("claim.available_until", { date: esc(fmt(info.expires_at)) })}</p>
    ${error ? `<div class="alert">${esc(t(ERRORS.includes(error) ? `claim.error.${error}` : "claim.error.generic"))}</div>` : ""}

    ${info.apple_pass ? `
    <section class="option">
      <h2>Apple Wallet</h2>
      <p>${t("claim.apple_intro")}</p>
      <form method="post" action="/claim/${esc(offerId)}/apple-pass">
        ${codeField("tx", info.attempts_left)}
        <button type="submit" class="wallet-button">${t("claim.add_apple")}</button>
      </form>
      ${info.apple_pass_trusted ? "" : `<p class="note">${t("claim.apple_dev_note")}</p>`}
    </section>` : ""}

    ${info.google_pass ? `
    <section class="option">
      <h2>Google Wallet</h2>
      <p>${t("claim.google_intro")}</p>
      <form id="google-form">
        ${codeField("tx-google", info.attempts_left)}
        <button type="submit" class="gw-button" aria-label="${t("claim.add_google")}">
          <!-- Botón oficial de Google Wallet, sin modificar (pautas de marca de Google). -->
          <img src="/admin/static/google-wallet-add-${lang === "en" ? "en" : "es"}.svg" alt="${t("claim.add_google")}" height="48">
        </button>
      </form>
    </section>` : ""}

    <section class="option">
      <h2>${t("claim.oid4vci_title")}</h2>
      <p>${t("claim.oid4vci_intro")}</p>
      <p><a class="button-link" href="${esc(info.offer_uri)}">${t("claim.open_wallet")}</a></p>
      <details class="field-help"><summary>${t("claim.which_wallet")}</summary><div class="help-panel">
        ${t("claim.which_wallet_body")}</div></details>
    </section>`;
}

// Google Wallet: el canje devuelve el enlace de Google en JSON y la página navega a él
// (la CSP form-action 'self' no permite que un formulario redirija a otro sitio).
document.addEventListener("submit", async (event) => {
  if (event.target.id !== "google-form") return;
  event.preventDefault();
  const button = event.target.querySelector("button");
  button.disabled = true;
  try {
    const res = await fetch(`/claim/${encodeURIComponent(offerId)}/google-pass`, {
      method: "POST",
      body: new URLSearchParams(new FormData(event.target)),
    });
    const body = await res.json().catch(() => ({}));
    if (res.ok && body.save_url) {
      location.assign(body.save_url);
      return;
    }
    location.search = `?error=${encodeURIComponent(body.error || "unavailable")}`;
  } catch {
    location.search = "?error=google_unavailable";
  }
});

main().catch(() => {
  chrome();
  root.innerHTML = `<h1>${t("claim.failed_title")}</h1><p>${t("claim.failed_body")}</p>`;
});
