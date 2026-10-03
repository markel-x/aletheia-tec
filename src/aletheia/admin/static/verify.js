// Verificación del QR de un pase: el token llega en el fragmento (#…), que el navegador
// no envía al servidor; se manda en el cuerpo de una petición POST y no queda en registros.

import { claimLabel, fmtDate, fmtDateTime, langSwitch, t, translateStatic } from "./i18n.js";

translateStatic();
document.getElementById("holder-lang").appendChild(langSwitch());
document.title = t("verify.page_title");

const root = document.getElementById("verify");
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const date = (s) => (s ? fmtDate(s * 1000) : "—");
// Etiquetas del catálogo (claim.*); el resto se deriva del nombre del campo.
const label = (k) => claimLabel(k, k.replace(/\./g, " · "));
const REASONS = ["credential_revoked", "credential_expired", "issuer_not_trusted", "signature_invalid",
  "issuer_key_compromised", "holder_bound_credential", "malformed"];

function flatten(obj, prefix = "") {
  return Object.entries(obj || {}).flatMap(([k, v]) =>
    v && typeof v === "object" && !Array.isArray(v) ? flatten(v, `${prefix}${k}.`) : [[`${prefix}${k}`, v]],
  );
}

async function main() {
  const token = decodeURIComponent(location.hash.slice(1));
  // Se quita el token de la barra de direcciones y del historial.
  history.replaceState(null, "", location.pathname);
  if (!token) {
    root.innerHTML = `<h1>${t("verify.empty_title")}</h1><p>${t("verify.empty_body")}</p>`;
    return;
  }
  const res = await fetch("/public/pass-verifications", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) throw new Error(String(res.status));
  const r = await res.json();
  const ok = r.result === "valid";
  const state = ok ? "valid" : r.result === "indeterminate" ? "indeterminate" : "invalid";
  const title = t(`verify.state.${state}`);
  const rows = ok ? flatten(r.claims).map(([k, v]) => `<tr><th>${esc(label(k))}</th><td>${esc(v)}</td></tr>`).join("") : "";
  root.innerHTML = `
    <div class="verdict ${state}"><span class="verdict-icon" aria-hidden="true">${ok ? "✓" : state === "indeterminate" ? "?" : "✕"}</span>
      <div><h1>${esc(title)}</h1>
      <p>${ok ? t("verify.valid_body") : esc(REASONS.includes(r.reason) ? t(`verify.reason.${r.reason}`) : state === "indeterminate" ? t("verify.indeterminate_body") : t("verify.reject"))}</p></div></div>
    ${r.issuer_name ? `<p class="lead">${t("claim.lead_html", { credential: esc(r.credential_name || t("col.credential")), issuer: esc(r.issuer_name) })}</p>` : ""}
    ${ok ? `<table class="claims">${rows}
      <tr><th>${t("verify.issued")}</th><td>${esc(date(r.issued_at))}</td></tr>
      <tr><th>${t("verify.valid_until")}</th><td>${esc(date(r.expires_at))}</td></tr></table>
      <p class="note">${t("verify.check_person", { date: esc(fmtDateTime(r.checked_at * 1000, { dateStyle: "long", timeStyle: "short" })) })}</p>` : ""}
    <details class="field-help"><summary>${t("verify.technical")}</summary><div class="help-panel">
      ${r.checks.map((c) => `<div><code>${esc(c.name)}</code>: ${esc(c.outcome)} (${esc(c.code)})</div>`).join("")}</div></details>`;
}

main().catch(() => {
  root.innerHTML = `<div class="verdict indeterminate"><span class="verdict-icon">?</span><div><h1>${t("verify.state.indeterminate")}</h1><p>${t("verify.failed_body")}</p></div></div>`;
});
