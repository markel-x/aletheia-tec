// Página pública del emisor: lo que ve quien abre en un navegador la URL «iss» de una
// credencial. Sólo datos ya públicos (nombre, desde cuándo, claves activas, metadatos).
// No afirma que la organización esté verificada: CredoSeal no la ha validado.

import { applyLang, chosenLang, fmtDate, langSwitch, t, translateStatic } from "./i18n.js";

const root = document.getElementById("issuer");
const orgId = location.pathname.split("/").filter(Boolean)[1] || "";
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

// Textos fijos y selector, con el idioma de la organización salvo elección del visitante.
let chromeDone = false;
function chrome(orgLanguage) {
  if (chromeDone) return;
  chromeDone = true;
  if (!chosenLang) applyLang(orgLanguage);
  translateStatic();
  document.getElementById("holder-lang").appendChild(langSwitch());
}

async function main() {
  const res = await fetch(`/issuer-info/${encodeURIComponent(orgId)}`);
  const info = res.ok ? await res.json() : null;
  chrome(info?.language);
  if (!info) {
    document.title = `${t("issuer.not_found_title")} · CredoSeal`;
    root.innerHTML = `<h1>${t("issuer.not_found_title")}</h1><p>${t("issuer.not_found_body")}</p>`;
    return;
  }
  document.title = `${info.name} · CredoSeal`;
  const keys = info.active_keys.length;
  root.innerHTML = `
    <p class="muted small">${t("issuer.kicker")}</p>
    <h1>${esc(info.name)}</h1>
    <p class="lead">${t("issuer.hosted_html", { since: esc(fmtDate(info.since)) })}</p>
    <div class="verdict ${keys ? "valid" : "indeterminate"}"><span class="verdict-icon" aria-hidden="true">${keys ? "✓" : "?"}</span>
      <div><p>${keys ? t("issuer.keys_active", { count: keys }) : t("issuer.keys_none")}</p></div></div>
    <p>${t("issuer.how_to_verify")}</p>
    <p class="note">${t("issuer.not_vetted")}</p>
    <details class="field-help"><summary>${t("issuer.technical")}</summary><div class="help-panel">
      <div>${t("issuer.identifier")}: <code>${esc(info.issuer)}</code></div>
      ${info.active_keys.map((k) => `<div>${t("issuer.key")}: <code>${esc(k.kid)}</code> (${esc(k.alg)})</div>`).join("")}
      <div><a href="${esc(info.metadata.jwt_vc_issuer)}" rel="noopener">JWT VC Issuer Metadata</a> ·
        <a href="${esc(info.metadata.openid_credential_issuer)}" rel="noopener">OpenID4VCI</a></div>
    </div></details>`;
}

main().catch(() => {
  chrome();
  root.innerHTML = `<h1>${t("issuer.not_found_title")}</h1><p>${t("claim.failed_body")}</p>`;
});
