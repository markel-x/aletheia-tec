// Página del titular: recibir la credencial en Apple Wallet (pase) o en una wallet OpenID4VCI.

const root = document.getElementById("claim");
const offerId = location.pathname.split("/").filter(Boolean)[1] || "";
const esc = (v) =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmt = (iso) => new Date(iso).toLocaleString("es-UY", { dateStyle: "long", timeStyle: "short" });

const ERRORS = {
  invalid_tx_code: "El código no es correcto. Revíselo e inténtelo de nuevo.",
  locked: "La oferta se bloqueó por demasiados intentos. Pida al emisor un enlace nuevo.",
  unavailable: "Esta credencial ya fue recibida o la oferta venció. Pida al emisor un enlace nuevo.",
};

async function main() {
  const error = new URLSearchParams(location.search).get("error");
  const res = await fetch(`/claim-info/${encodeURIComponent(offerId)}`);
  if (!res.ok) {
    root.innerHTML = `<h1>Oferta no disponible</h1>
      <p>Este enlace ya se usó, venció o no es válido. Si todavía necesita su credencial, pida al emisor un enlace nuevo.</p>`;
    return;
  }
  const info = await res.json();
  root.innerHTML = `
    <h1>Reciba su credencial</h1>
    <p class="lead"><b>${esc(info.credential_name)}</b><br>emitida por <b>${esc(info.issuer_name)}</b></p>
    <p class="muted small">Disponible hasta: ${esc(fmt(info.expires_at))}</p>
    ${error ? `<div class="alert">${esc(ERRORS[error] || "No se pudo completar la operación.")}</div>` : ""}

    ${info.apple_pass ? `
    <section class="option">
      <h2>Apple Wallet</h2>
      <p>Guarde el certificado en la app Wallet de su iPhone. Quien escanee su código QR verá al instante si es auténtico y si sigue vigente.</p>
      <form method="post" action="/claim/${esc(offerId)}/apple-pass">
        <label for="tx">Código de 6 dígitos</label>
        <input id="tx" name="tx_code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required placeholder="••••••">
        <details class="field-help"><summary>¿Dónde está mi código?</summary><div class="help-panel">
          El emisor se lo envió por un medio distinto al de este enlace (por ejemplo, SMS o correo aparte).
          Le quedan <b>${esc(info.attempts_left)}</b> intentos; después la oferta se bloquea.</div></details>
        <button type="submit" class="wallet-button">Agregar a Apple Wallet</button>
      </form>
      ${info.apple_pass_trusted ? "" : `<p class="note">Entorno de pruebas: el pase está firmado con un certificado de desarrollo y el iPhone lo rechazará hasta configurar el certificado de Apple.</p>`}
    </section>` : ""}

    <section class="option">
      <h2>Wallet de credenciales (OpenID4VCI)</h2>
      <p>Si usa una wallet de credenciales verificables, ábrala con este botón. Es la opción más privada: usted elige qué datos mostrar en cada verificación.</p>
      <p><a class="button-link" href="${esc(info.offer_uri)}">Abrir en mi wallet</a></p>
      <details class="field-help"><summary>¿Qué wallet puedo usar?</summary><div class="help-panel">
        Cualquier wallet compatible con OpenID4VCI y credenciales SD-JWT VC. La wallet le pedirá el mismo código de 6 dígitos.</div></details>
    </section>`;
}

main().catch(() => {
  root.innerHTML = `<h1>Algo salió mal</h1><p>No se pudo cargar la oferta. Inténtelo de nuevo en unos minutos.</p>`;
});
