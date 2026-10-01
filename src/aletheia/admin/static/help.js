// Textos de ayuda del panel: ayudas por campo, por sección, consejos para errores y la
// documentación de uso básico (vista "Ayuda"). Sólo contenido estático y de confianza.

// ---------------------------------------------------------------------------
// Ayudas por campo (desplegable "Cómo completarlo" bajo cada campo)
// ---------------------------------------------------------------------------
export const FIELD_HELP = {
  "login.email": `El correo con el que le dieron de alta en Aletheia. No distingue mayúsculas.`,
  "login.password": `Al menos 12 caracteres. Si su cuenta fue creada por un administrador, use la contraseña
    temporal que le entregó. Tras 10 intentos fallidos en 15 minutos el acceso se bloquea temporalmente.`,
  "login.organization": `Sólo si su correo pertenece a más de una organización. Escriba el identificador público
    (<code>org_</code> seguido de 22 caracteres); se lo indica el administrador o aparece en la parte superior
    del panel una vez dentro.`,

  "offer.template": `La plantilla define qué datos lleva la credencial. Sólo aparecen plantillas con una versión
    <b>publicada</b>; si falta la que necesita, publíquela en <a href="#/templates">Plantillas</a>.`,
  "offer.holder_reference": `Un identificador <b>suyo</b> para encontrar luego esta credencial (por ejemplo, el número
    de legajo). Es opcional y opaco: <b>no use correos ni datos personales</b>. Máximo 128 caracteres.
    <br>Ejemplo: <code>LEG-2026-00412</code>`,
  "offer.claims": `Los datos de la credencial en formato JSON, con los campos que define la plantilla elegida.
    Debajo se listan los campos (los marcados con * son obligatorios) y puede insertar un ejemplo para completar.
    <ul><li>Texto entre comillas: <code>"Ana"</code>.</li>
    <li>Números sin comillas: <code>40</code>.</li>
    <li>Fechas como texto <code>"AAAA-MM-DD"</code>: <code>"2026-09-30"</code>.</li>
    <li>Sí/no: <code>true</code> o <code>false</code>.</li></ul>
    Aletheia guarda estos datos cifrados sólo hasta que el titular recibe la credencial; después los borra.`,

  "template.slug": `Identificador corto y permanente de la plantilla: minúsculas, números y guiones; empieza con letra
    o número; hasta 63 caracteres. Forma parte del <b>tipo</b> de la credencial (<code>vct</code>) y no se puede
    cambiar después.<br>Ejemplos: <code>certificado-curso</code>, <code>diploma-grado</code>.`,
  "template.name": `Nombre legible para usted y su equipo. Ejemplo: <code>Certificado de finalización de curso</code>.`,
  "version.claims_schema": `Describe los datos de la credencial con un JSON Schema restringido:
    <ul><li>Tipos: <code>object</code>, <code>string</code>, <code>integer</code>, <code>number</code>,
      <code>boolean</code> y <code>date</code> (fecha AAAA-MM-DD).</li>
    <li>Restricciones: <code>required</code>, <code>minLength</code>/<code>maxLength</code>,
      <code>minimum</code>/<code>maximum</code>, <code>enum</code>.</li>
    <li>Hasta 3 niveles de anidación y 50 propiedades por objeto.</li>
    <li>Nombres en minúsculas con <code>_</code>; no se permiten <code>iss</code>, <code>exp</code>,
      <code>vct</code>, <code>cnf</code>, <code>status</code> ni otros reservados.</li></ul>
    Ejemplo mínimo:
    <pre>{"type": "object",
 "properties": {
   "given_name": {"type": "string"},
   "course": {"type": "object",
     "properties": {"title": {"type": "string"}},
     "required": ["title"]}},
 "required": ["given_name", "course"]}</pre>`,
  "version.selective_disclosure": `Campos que el titular puede <b>mostrar u ocultar</b> al presentar la credencial.
    Escriba rutas separadas por coma; para campos anidados use punto: <code>course.grade</code>.
    Recomendado para datos personales (nombre, fecha, nota). Los campos que no figuren aquí viajan siempre visibles.
    <br>Ejemplo: <code>given_name, family_name, completion_date, course.grade</code>`,
  "version.validity_days": `Cuántos días es válida cada credencial desde que se emite (1 a 3650). Pasado ese plazo,
    las verificaciones devuelven <code>invalid</code> por expiración. Ejemplo: <code>365</code>.`,

  "policy.name": `Nombre único de la política en su organización. Ejemplo: <code>admisión-posgrado</code>.`,
  "policy.accepted_vcts": `Tipos de credencial que acepta esta política, separados por coma. Copie el <code>vct</code>
    desde <a href="#/templates">Plantillas</a> (aparece bajo el nombre de cada una). Vacío acepta cualquier tipo,
    pero para pedir credenciales a un wallet (OID4VP) hace falta al menos uno.`,
  "policy.required_claims": `Campos que la presentación <b>debe</b> mostrar para ser válida, separados por coma.
    Ejemplo: <code>family_name</code>. Si el titular no los muestra, el resultado es
    <code>invalid</code> (<code>required_claim_missing</code>).`,
  "policy.require_holder_binding": `Exige que quien presenta demuestre tener la clave del titular (firma KB-JWT).
    Déjelo activado salvo que tenga un motivo concreto: sin esto, una copia robada de la credencial pasaría.`,
  "policy.issuer": `La URL del emisor (<code>iss</code>) en la que confía esta política. Para emisores alojados en
    Aletheia tiene la forma <code>${location.origin}/issuers/org_…</code>; la de su propia organización está en
    <a href="#/signing-keys">Claves de firma</a>. Un emisor <b>no</b> es confiable por estar en Aletheia: hay
    que agregarlo aquí.`,

  "oid4vp.trust_policy_id": `La política decide qué emisores y tipos de credencial se aceptan. Sólo se listan
    políticas con al menos un <code>vct</code> aceptado.`,
  "oid4vp.claims": `Qué datos pedir al titular. Rutas separadas por coma (anidadas con punto). Vacío pide los
    <b>claims requeridos</b> de la política. Pida sólo lo necesario: el titular verá la lista antes de aceptar.
    <br>Ejemplo: <code>family_name, course.grade</code>`,
  "oid4vp.client_id_scheme": `Cómo se identifica Aletheia ante el wallet:
    <ul><li><b>x509_hash</b> (recomendado): solicitud firmada con el certificado del verificador; es lo que exigen
      los wallets alineados con HAIP/EUDI.</li>
    <li><b>x509_san_dns</b>: igual, identificando por el dominio del certificado. Requiere un dominio, no una IP.</li>
    <li><b>redirect_uri</b>: solicitud sin firmar; sólo para wallets o pruebas que lo admitan.</li></ul>`,
  "oid4vp.encrypt_response": `El wallet cifra su respuesta para que sólo Aletheia pueda leerla (recomendado).
    Desactívelo sólo para wallets que no admitan respuestas cifradas.`,

  "present.trust_policy_id": `La política con la que se evaluará la presentación. Al crear la solicitud recibirá un
    <code>nonce</code> y un <code>aud</code> que debe entregar al titular para que firme la presentación.`,
  "present.presentation": `La presentación que le entregó el titular: el texto SD-JWT completo, con las partes
    separadas por <code>~</code> y terminando en la firma del titular (KB-JWT).
    <br>Forma: <code>eyJ…(credencial)~WyJ…(dato 1)~WyJ…(dato 2)~eyJ…(firma del titular)</code>
    <br>Si no creó una solicitud antes, el resultado será <code>indeterminate</code>: sin <code>nonce</code> no se
    puede descartar que sea una copia reutilizada.`,

  "member.email": `Correo de la persona. Si ya tiene cuenta en Aletheia (por otra organización), se le añade este rol;
    si no, se crea la cuenta y verá una <b>contraseña temporal</b> que debe entregarle por un canal seguro.`,
  "member.display_name": `Nombre que verá el resto del equipo. Ejemplo: <code>Ana Pérez (Secretaría)</code>.`,
  "member.role": `Qué puede hacer la persona:
    <ul><li><b>owner</b>: todo, incluido declarar comprometida una clave de firma.</li>
    <li><b>admin</b>: todo salvo comprometer claves.</li>
    <li><b>issuer</b>: emitir, consultar y revocar credenciales.</li>
    <li><b>verifier</b>: verificar presentaciones.</li>
    <li><b>auditor</b>: sólo lectura de credenciales, auditoría y consumo.</li></ul>
    Siempre debe quedar al menos un owner.`,

  "apiclient.name": `Para qué sistema es la clave. Ejemplo: <code>SIS académico — producción</code>. La clave
    completa se muestra <b>una sola vez</b>: guárdela en el gestor de secretos de ese sistema.`,
};

// Ayudas por sección (desplegable "¿Qué es esto?")
export const SECTION_HELP = {
  offer: `Una <b>oferta</b> prepara una credencial para un titular. Aletheia devuelve un <b>QR/enlace</b> y un
    <b>código de 6 dígitos</b> (<code>tx_code</code>). Entréguelos por <b>canales distintos</b> (p. ej. el QR por
    correo y el código por SMS): así, quien intercepte uno solo no puede quedarse con la credencial. El titular
    escanea el QR con su wallet, introduce el código y la credencial queda en su teléfono.`,
  templates: `Una <b>plantilla</b> define el tipo de credencial (p. ej. "certificado de curso"). Cada cambio crea una
    <b>versión</b> nueva en borrador; al <b>publicarla</b> queda fija y las ofertas nuevas la usan. Las credenciales ya
    emitidas no cambian.`,
  policy: `Una <b>política de confianza</b> es la regla con la que usted verifica: en qué emisores confía, qué tipos
    acepta y qué datos exige. Cree una por cada caso de uso (p. ej. "admisión a posgrado").`,
  oid4vp: `Pida una credencial directamente al <b>wallet</b> del titular: muestre el QR, el titular lo escanea, elige
    compartir los datos pedidos y el resultado aparece aquí solo. Es el protocolo estándar OpenID4VP.`,
  present: `Alternativa sin wallet estándar: cree una solicitud, entregue el <code>nonce</code> y el <code>aud</code>
    al titular (o a su aplicación) y pegue aquí la presentación que le devuelva.`,
  members: `Personas con acceso al panel de su organización y su rol. Cada persona entra con su propio correo y
    contraseña; nunca comparta cuentas.`,
  apiclients: `Claves para que <b>otros sistemas</b> (p. ej. su sistema académico) usen la API de Aletheia sin una
    persona. Cada clave tiene sólo los permisos que marque. Revoque las que ya no use.`,
  signingkeys: `La clave con la que su organización firma las credenciales. <b>Rotarla</b> crea una nueva y la anterior
    sigue sirviendo para verificar lo ya emitido. <b>Declararla comprometida</b> (sólo owner) invalida todo lo firmado
    con ella: úselo sólo si cree que alguien obtuvo la clave.`,
};

// Consejos que acompañan a los errores de la API
export const ERROR_TIPS = {
  invalid_credentials: "Revise el correo y la contraseña.",
  organization_required: "Su usuario pertenece a varias organizaciones: indique cuál.",
  rate_limited: "Demasiados intentos. Espere unos minutos.",
  invalid_claims: "Los datos no cumplen la plantilla. Revise la ayuda del campo «Claims».",
  invalid_schema: "El esquema no es válido. Despliegue la ayuda del campo para ver lo permitido.",
  invalid_dcql: "La política necesita al menos un vct aceptado para pedir credenciales a un wallet.",
  verifier_identity_unavailable: "Falta el certificado del verificador; use «redirect_uri» o pida al operador que lo configure.",
  invalid_permissions: "Una clave de API no puede tener más permisos que usted ni gestionar miembros.",
  last_owner: "La organización debe conservar al menos un owner.",
  conflict: "Ya existe un elemento con ese nombre o identificador.",
  forbidden: "Su rol no tiene permiso para esta acción.",
  unauthorized: "Su sesión expiró. Inicie sesión de nuevo.",
};

// ---------------------------------------------------------------------------
// Documentación de uso básico (vista "Ayuda")
// ---------------------------------------------------------------------------
export const DOCS = [
  {
    id: "conceptos",
    title: "Conceptos básicos",
    body: `
      <dl class="glossary">
        <dt>Credencial verificable</dt><dd>Un documento digital firmado (p. ej. un certificado de curso) que el titular
          guarda en su teléfono y puede mostrar a quien quiera. Cualquiera puede comprobar que es auténtico y que no fue
          alterado ni revocado, sin llamar al emisor.</dd>
        <dt>Emisor</dt><dd>Quien crea y firma la credencial: su organización.</dd>
        <dt>Titular</dt><dd>La persona a quien se emite la credencial y que la guarda.</dd>
        <dt>Wallet</dt><dd>La aplicación del teléfono donde el titular guarda sus credenciales.</dd>
        <dt>Verificador</dt><dd>Quien recibe la credencial y comprueba su validez (puede ser su misma organización u otra).</dd>
        <dt>Divulgación selectiva</dt><dd>El titular elige qué datos mostrar. Por ejemplo, puede probar que terminó un
          curso sin mostrar su nota.</dd>
        <dt>Revocación</dt><dd>Anular una credencial emitida (p. ej. por error). Es definitiva; los verificadores lo ven
          en minutos.</dd>
        <dt>vct</dt><dd>El identificador del tipo de credencial; Aletheia lo crea a partir de la plantilla.</dd>
      </dl>`,
  },
  {
    id: "primeros-pasos",
    title: "Primeros pasos: emitir su primera credencial",
    body: `
      <ol class="steps">
        <li><b>Cree una plantilla</b> en <a href="#/templates">Plantillas</a>: un identificador (p. ej.
          <code>certificado-curso</code>) y un nombre.</li>
        <li><b>Cree una versión</b> con los campos de la credencial y marque cuáles puede ocultar el titular. El panel
          propone un esquema de ejemplo que puede ajustar.</li>
        <li><b>Publique</b> la versión. A partir de ahí no se puede modificar (para cambiarla, cree otra versión).</li>
        <li>En <a href="#/credentials">Credenciales</a>, elija la plantilla, use «Insertar ejemplo» y complete los datos
          del titular. Pulse <b>Crear oferta</b>.</li>
        <li><b>Entregue el QR y el código de 6 dígitos por canales distintos.</b> El código se muestra una sola vez; si
          lo pierde, use «Nuevo enlace».</li>
        <li>Cuando el titular la recibe en su wallet, el estado pasa de <span class="tag offered">offered</span> a
          <span class="tag issued">issued</span>.</li>
      </ol>`,
  },
  {
    id: "estados",
    title: "Estados de una credencial",
    body: `
      <table><thead><tr><th>Estado</th><th>Significa</th><th>Qué puede hacer</th></tr></thead><tbody>
        <tr><td><span class="tag offered">offered</span></td><td>Oferta creada; el titular aún no la recibió.</td><td>Nuevo enlace (si perdió el código o expiró) o Cancelar.</td></tr>
        <tr><td><span class="tag issued">issued</span></td><td>El titular la tiene en su wallet.</td><td>Revocar si corresponde.</td></tr>
        <tr><td><span class="tag offer_expired">offer_expired</span></td><td>Nadie la recibió dentro del plazo (por defecto 72 h).</td><td>Crear una oferta nueva.</td></tr>
        <tr><td><span class="tag revoked">revoked</span></td><td>Revocada o cancelada. Definitivo.</td><td>Emitir otra si hace falta.</td></tr>
      </tbody></table>
      <p class="muted">Si el titular introduce mal el código 5 veces, la oferta se bloquea: use «Nuevo enlace».</p>`,
  },
  {
    id: "verificar-wallet",
    title: "Verificar una credencial desde el wallet del titular",
    body: `
      <ol class="steps">
        <li>En <a href="#/verify">Verificación</a>, cree una <b>política</b>: tipos aceptados (copie el <code>vct</code> de la
          plantilla) y datos requeridos.</li>
        <li><b>Agregue los emisores</b> en los que confía (su propia organización o terceros).</li>
        <li>En «Solicitar a un wallet», elija la política y pulse <b>Crear solicitud OID4VP</b>.</li>
        <li>El titular escanea el QR, revisa qué datos se piden y acepta.</li>
        <li>El resultado aparece solo en pocos segundos, con los datos que el titular decidió mostrar.</li>
      </ol>
      <p class="muted">Los datos mostrados se conservan cifrados 10 minutos; el historial guarda sólo el resultado, nunca los datos personales.</p>`,
  },
  {
    id: "resultados",
    title: "Qué significa cada resultado",
    body: `
      <table><thead><tr><th>Resultado</th><th>Significa</th></tr></thead><tbody>
        <tr><td><span class="tag valid">valid</span></td><td>Auténtica, vigente, no revocada, presentada por su titular y cumple la política.</td></tr>
        <tr><td><span class="tag invalid">invalid</span></td><td>No debe aceptarse. El motivo indica por qué (ver abajo).</td></tr>
        <tr><td><span class="tag indeterminate">indeterminate</span></td><td>No se pudo decidir (p. ej. no se pudo consultar el estado de revocación). <b>Nunca</b> lo trate como válido; reintente más tarde.</td></tr>
      </tbody></table>
      <h3>Motivos frecuentes</h3>
      <table><thead><tr><th>Código</th><th>Qué pasó</th><th>Qué hacer</th></tr></thead><tbody>
        <tr><td><code>issuer_not_trusted</code></td><td>El emisor no está en la política.</td><td>Agréguelo si confía en él.</td></tr>
        <tr><td><code>credential_revoked</code></td><td>El emisor la revocó.</td><td>No aceptarla.</td></tr>
        <tr><td><code>credential_expired</code></td><td>Venció su plazo de validez.</td><td>Pedir una credencial vigente.</td></tr>
        <tr><td><code>required_claim_missing</code> / <code>requested_claim_missing</code></td><td>El titular no mostró un dato exigido.</td><td>Pedir que comparta ese dato.</td></tr>
        <tr><td><code>vct_not_accepted</code></td><td>Es otro tipo de credencial.</td><td>Revisar los tipos aceptados de la política.</td></tr>
        <tr><td><code>presentation_replayed</code></td><td>Se reutilizó una presentación ya usada.</td><td>Crear una solicitud nueva.</td></tr>
        <tr><td><code>signature_invalid</code></td><td>La credencial fue alterada.</td><td>No aceptarla.</td></tr>
        <tr><td><code>issuer_key_compromised</code></td><td>La clave del emisor fue declarada comprometida.</td><td>Pedir al emisor que la reemita.</td></tr>
      </tbody></table>`,
  },
  {
    id: "revocar",
    title: "Revocar o cancelar",
    body: `
      <p>En <a href="#/credentials">Credenciales</a>, use <b>Revocar</b> (credencial ya recibida) o <b>Cancelar</b>
        (oferta pendiente) y elija el motivo:</p>
      <ul><li><code>issued_in_error</code>: se emitió por error.</li>
        <li><code>superseded</code>: se reemplazó por otra.</li>
        <li><code>holder_request</code>: lo pidió el titular.</li>
        <li><code>policy_violation</code>, <code>key_compromise</code>, <code>other</code>.</li></ul>
      <p>Es <b>irreversible</b>. Las verificaciones en Aletheia lo ven al instante; verificadores externos, en un máximo de
        5 minutos.</p>`,
  },
  {
    id: "roles",
    title: "Roles y permisos",
    body: `
      <table><thead><tr><th>Permiso</th><th>owner</th><th>admin</th><th>issuer</th><th>verifier</th><th>auditor</th></tr></thead><tbody>
        <tr><td>Emitir, revocar credenciales</td><td>✔</td><td>✔</td><td>✔</td><td></td><td></td></tr>
        <tr><td>Ver credenciales y plantillas</td><td>✔</td><td>✔</td><td>✔</td><td></td><td>✔</td></tr>
        <tr><td>Crear plantillas</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Verificar presentaciones</td><td>✔</td><td>✔</td><td></td><td>✔</td><td></td></tr>
        <tr><td>Políticas de confianza</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Miembros y claves de API</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Auditoría y consumo</td><td>✔</td><td>✔</td><td></td><td></td><td>✔</td></tr>
        <tr><td>Rotar clave de firma</td><td>✔</td><td>✔</td><td></td><td></td><td></td></tr>
        <tr><td>Declarar clave comprometida</td><td>✔</td><td></td><td></td><td></td><td></td></tr>
      </tbody></table>`,
  },
  {
    id: "integracion",
    title: "Integrar otro sistema (API)",
    body: `
      <ol class="steps">
        <li>En <a href="#/api-clients">Claves de API</a>, cree una clave con sólo los permisos necesarios (p. ej.
          <code>credentials:issue</code>). Se muestra una vez: guárdela como secreto.</li>
        <li>Su sistema envía <code>Authorization: Bearer ak_…</code> en cada petición.</li>
        <li>Para emitir: <code>POST /v1/credentials</code> con <code>{"template": "…", "claims": {…}}</code> y un encabezado
          <code>Idempotency-Key</code> único por emisión (evita duplicados si reintenta).</li>
      </ol>
      <p>La referencia completa de la API está en <a href="/docs" target="_blank" rel="noopener">/docs</a> (botón
        <b>Authorize</b> para probar con su clave).</p>`,
  },
  {
    id: "seguridad",
    title: "Buenas prácticas de seguridad",
    body: `
      <ul>
        <li>Entregue QR y código por canales distintos; nunca juntos en el mismo mensaje.</li>
        <li>Marque como ocultables los datos personales; pida en las verificaciones sólo lo imprescindible.</li>
        <li>Deje activada la vinculación con el titular en las políticas.</li>
        <li>Revise <a href="#/audit">Auditoría</a> periódicamente y revoque claves de API sin uso.</li>
        <li>Use <code>holder_reference</code> con identificadores internos, nunca correos ni documentos.</li>
        <li>Rote la clave de firma al menos una vez al año.</li>
      </ul>`,
  },
  {
    id: "faq",
    title: "Preguntas frecuentes",
    body: `
      <details class="faq"><summary>El titular perdió el código de 6 dígitos.</summary>
        <p>En <a href="#/credentials">Credenciales</a>, pulse «Nuevo enlace» en la oferta: genera QR y código nuevos e
          invalida los anteriores.</p></details>
      <details class="faq"><summary>El titular perdió el teléfono con la credencial.</summary>
        <p>Aletheia no guarda una copia de la credencial (por privacidad). Revoque la anterior con motivo
          <code>superseded</code> y emita una nueva.</p></details>
      <details class="faq"><summary>¿Puedo corregir un dato de una credencial emitida?</summary>
        <p>No: las credenciales firmadas no se modifican. Revoque la incorrecta (<code>issued_in_error</code>) y emita otra.</p></details>
      <details class="faq"><summary>¿Por qué no aparece mi plantilla al crear una oferta?</summary>
        <p>Sólo se listan plantillas con una versión <b>publicada</b>.</p></details>
      <details class="faq"><summary>La verificación dice «indeterminate».</summary>
        <p>Aletheia no pudo comprobar algo necesario (normalmente el estado de revocación de un emisor externo). Reintente
          en unos minutos; si persiste, contacte al emisor.</p></details>
      <details class="faq"><summary>¿Qué datos personales guarda Aletheia?</summary>
        <p>Los datos de la credencial sólo mientras la oferta está pendiente (cifrados, máximo 7 días) y los datos
          mostrados en una verificación durante 10 minutos (cifrados). El historial guarda resultados y fechas, no datos
          personales.</p></details>`,
  },
];
