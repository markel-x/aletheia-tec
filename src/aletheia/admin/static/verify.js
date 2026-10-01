// Verificación del QR de un pase: el token llega en el fragmento (#…), que el navegador
// no envía al servidor; se manda en el cuerpo de una petición POST y no queda en registros.

const root = document.getElementById("verify");
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const date = (s) => (s ? new Date(s * 1000).toLocaleDateString("es-UY", { dateStyle: "long" }) : "—");
// Mismas etiquetas que el pase (passes/builder.py); el resto se deriva del nombre del campo.
const LABELS = {
  "given_name": "Nombre",
  "family_name": "Apellido",
  "course": "Curso",
  "course.title": "Curso",
  "course.hours": "Horas",
  "course.grade": "Calificación",
  "completion_date": "Fecha de finalización",
  "student_id": "Legajo",
  "birth_date": "Fecha de nacimiento",
  "honors": "Con honores",
};
const label = (k) => LABELS[k] || k.replace(/\./g, " · ").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

const REASONS = {
  credential_revoked: "El emisor revocó esta credencial.",
  credential_expired: "La credencial venció.",
  issuer_not_trusted: "La emite una organización que no está alojada en este servicio.",
  signature_invalid: "La credencial fue alterada: la firma del emisor no coincide.",
  issuer_key_compromised: "La clave del emisor fue declarada comprometida.",
  holder_bound_credential: "Esta credencial debe presentarse desde la wallet de su titular, no como código QR.",
  malformed: "El código no contiene una credencial válida.",
};

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
    root.innerHTML = `<h1>Verificar una credencial</h1><p>Escanee con la cámara el código QR del pase de la credencial.</p>`;
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
  const title = { valid: "Credencial válida", invalid: "Credencial NO válida", indeterminate: "No se pudo verificar" }[state];
  const rows = ok ? flatten(r.claims).map(([k, v]) => `<tr><th>${esc(label(k))}</th><td>${esc(v)}</td></tr>`).join("") : "";
  root.innerHTML = `
    <div class="verdict ${state}"><span class="verdict-icon" aria-hidden="true">${ok ? "✓" : state === "indeterminate" ? "?" : "✕"}</span>
      <div><h1>${esc(title)}</h1>
      <p>${ok ? "Firmada por el emisor y vigente en este momento." : esc(REASONS[r.reason] || (state === "indeterminate" ? "No se pudo consultar el estado. Inténtelo más tarde; no la acepte mientras tanto." : "No la acepte."))}</p></div></div>
    ${r.issuer_name ? `<p class="lead"><b>${esc(r.credential_name || "Credencial")}</b><br>emitida por <b>${esc(r.issuer_name)}</b></p>` : ""}
    ${ok ? `<table class="claims">${rows}
      <tr><th>Emitida</th><td>${esc(date(r.issued_at))}</td></tr>
      <tr><th>Válida hasta</th><td>${esc(date(r.expires_at))}</td></tr></table>
      <p class="note">Compruebe que los datos coinciden con la persona o el documento que tiene delante. Verificado: ${esc(new Date(r.checked_at * 1000).toLocaleString("es-UY", { dateStyle: "long", timeStyle: "short" }))}</p>` : ""}
    <details class="field-help"><summary>Detalle técnico</summary><div class="help-panel">
      ${r.checks.map((c) => `<div><code>${esc(c.name)}</code>: ${esc(c.outcome)} (${esc(c.code)})</div>`).join("")}</div></details>`;
}

main().catch(() => {
  root.innerHTML = `<div class="verdict indeterminate"><span class="verdict-icon">?</span><div><h1>No se pudo verificar</h1><p>Inténtelo de nuevo en unos minutos. No acepte la credencial mientras tanto.</p></div></div>`;
});
