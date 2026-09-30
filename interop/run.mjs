// Prueba de interoperabilidad con @sd-jwt/sd-jwt-vc (implementación independiente).
//
// Actúa como wallet y como verificador externo contra la API de Aletheia:
//   1. Obtiene una credencial por OID4VCI con su propia clave ES256 (Web Crypto).
//   2. La biblioteca verifica la credencial emitida por Aletheia (firma, digests,
//      vigencia, Status List) resolviendo la clave por `kid` en el JWKS publicado.
//   3. La biblioteca construye una presentación con KB-JWT y Aletheia la verifica
//      en POST /v1/verifications.
//   4. Tras revocar, la biblioteca rechaza la credencial por su estado.
//
// Variables: ALETHEIA_API (URL interna, p. ej. http://api:8000),
// ALETHEIA_PUBLIC_BASE (la que aparece en iss/uri), ALETHEIA_EMAIL, ALETHEIA_PASSWORD.

import { webcrypto } from "node:crypto";
import { digest, ES256, generateSalt } from "@sd-jwt/crypto-nodejs";
import { SDJwtVcInstance } from "@sd-jwt/sd-jwt-vc";

const API = process.env.ALETHEIA_API ?? "http://api:8000";
const PUBLIC = (process.env.ALETHEIA_PUBLIC_BASE ?? "http://127.0.0.1:8008").replace(/\/$/, "");
const EMAIL = process.env.ALETHEIA_EMAIL ?? "owner@example.org";
const PASSWORD = process.env.ALETHEIA_PASSWORD;
const GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`);
}

const internal = (url) => (url.startsWith(PUBLIC) ? API + url.slice(PUBLIC.length) : url);
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const b64json = (obj) => b64url(JSON.stringify(obj));

async function http(method, path, { json, form, token, headers = {} } = {}) {
  const res = await fetch(internal(path.startsWith("http") ? path : API + path), {
    method,
    headers: {
      ...(json ? { "content-type": "application/json" } : {}),
      ...(form ? { "content-type": "application/x-www-form-urlencoded" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: json ? JSON.stringify(json) : form ? new URLSearchParams(form).toString() : undefined,
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}: ${text.slice(0, 300)}`);
  return body;
}

// --- Emisor / verificador externo: resolución de clave por kid ---------------------
async function issuerVerifier(issuerUrl) {
  const orgId = issuerUrl.split("/issuers/")[1];
  const meta = await http("GET", `/.well-known/jwt-vc-issuer/issuers/${orgId}`);
  if (meta.issuer !== issuerUrl) throw new Error("metadata issuer mismatch");
  const keys = meta.jwks.keys;
  return async (data, sig) => {
    const header = JSON.parse(Buffer.from(data.split(".")[0], "base64url").toString());
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return false;
    const { kid, alg, use, ...publicJwk } = jwk;
    return (await ES256.getVerifier(publicJwk))(data, sig);
  };
}

// KB-JWT: la biblioteca pasa el payload del SD-JWT; la clave es cnf.jwk.
async function kbVerifier(data, sig, payload) {
  return (await ES256.getVerifier(payload.cnf.jwk))(data, sig);
}

async function main() {
  if (!PASSWORD) throw new Error("ALETHEIA_PASSWORD is required");

  // --- Preparación: sesión, plantilla publicada, política de confianza -------------
  const { token } = await http("POST", "/v1/auth/login", { json: { email: EMAIL, password: PASSWORD } });
  const org = await http("GET", "/v1/organization", { token });
  const slug = "interop-course";
  let template = (await http("GET", "/v1/templates", { token })).find((t) => t.slug === slug);
  if (!template) {
    template = await http("POST", "/v1/templates", { token, json: { slug, name: "Interop" } });
    const version = await http("POST", `/v1/templates/${template.id}/versions`, {
      token,
      json: {
        claims_schema: {
          type: "object",
          properties: {
            course: { type: "object", properties: { title: { type: "string" }, grade: { type: "string" } }, required: ["title"] },
            given_name: { type: "string" },
            family_name: { type: "string" },
          },
          required: ["course", "given_name", "family_name"],
        },
        selective_disclosure: ["given_name", "family_name", "course.grade"],
        validity_days: 30,
      },
    });
    await http("POST", `/v1/templates/${template.id}/versions/${version.id}/publish`, { token });
  }

  // --- Wallet: OID4VCI pre-autorizado con clave propia -----------------------------
  const holder = await ES256.generateKeyPair();
  const holderSign = await ES256.getSigner(holder.privateKey);
  const offer = await http("POST", "/v1/credentials", {
    token,
    json: { template: slug, claims: { course: { title: "Interoperabilidad", grade: "A" }, given_name: "Ada", family_name: "Lovelace" } },
  });
  const offerDoc = await http("GET", offer.credential_offer_uri);
  const tok = await http("POST", "/oid4vci/token", {
    form: { grant_type: GRANT, "pre-authorized_code": offerDoc.grants[GRANT]["pre-authorized_code"], tx_code: offer.tx_code },
  });
  const { c_nonce } = await http("POST", "/oid4vci/nonce");
  const { d, ...holderPublic } = holder.publicKey; // por si la implementación lo incluyera
  const proofInput = `${b64json({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk: holderPublic })}.${b64json({
    aud: offerDoc.credential_issuer,
    iat: Math.floor(Date.now() / 1000),
    nonce: c_nonce,
  })}`;
  const proof = `${proofInput}.${await holderSign(proofInput)}`;
  const issued = await http("POST", "/oid4vci/credential", {
    token: tok.access_token,
    json: { credential_configuration_id: slug, proofs: { jwt: [proof] } },
  });
  const credential = issued.credentials[0].credential;
  check("OID4VCI: proof firmado con Web Crypto aceptado por Aletheia", typeof credential === "string");

  // --- Verificación de la credencial por la biblioteca ----------------------------
  const sdjwt = new SDJwtVcInstance({
    hasher: digest,
    saltGenerator: generateSalt,
    verifier: await issuerVerifier(offerDoc.credential_issuer),
    kbVerifier,
    kbSigner: holderSign,
    kbSignAlg: "ES256",
    statusListFetcher: async (uri) => {
      const res = await fetch(internal(uri));
      if (!res.ok) throw new Error(`status list ${res.status}`);
      return res.text();
    },
  });

  const verified = await sdjwt.verify(credential, { requiredClaimKeys: ["vct", "cnf", "status"] });
  const claims = await sdjwt.getClaims(credential);
  check("Biblioteca verifica firma del emisor (kid → JWKS publicado)", verified.header?.typ === "dc+sd-jwt", `kid ${verified.header?.kid}`);
  check("Biblioteca reconstruye los claims divulgables", claims.given_name === "Ada" && claims.family_name === "Lovelace" && claims.course?.grade === "A");
  check("Claims no divulgables en claro y cnf del titular", claims.course?.title === "Interoperabilidad" && claims.cnf?.jwk?.x === holderPublic.x);
  check("Biblioteca acepta la Status List (statuslist+jwt) y el estado VALID", verified.payload.status?.status_list?.uri?.startsWith(PUBLIC));

  // --- Presentación construida por la biblioteca, verificada por Aletheia ----------
  const policy =
    (await http("GET", "/v1/trust-policies", { token })).find((p) => p.name === "interop") ??
    (await http("POST", "/v1/trust-policies", { token, json: { name: "interop", required_claims: ["family_name"] } }));
  if (!policy.trusted_issuers?.some((t) => t.issuer === offerDoc.credential_issuer)) {
    await http("POST", `/v1/trust-policies/${policy.id}/issuers`, { token, json: { issuer: offerDoc.credential_issuer } });
  }
  const request = await http("POST", "/v1/presentation-requests", { token, json: { trust_policy_id: policy.id } });
  const presentation = await sdjwt.present(
    credential,
    { family_name: true },
    { kb: { payload: { iat: Math.floor(Date.now() / 1000), aud: request.aud, nonce: request.nonce } } },
  );
  const libSelf = await sdjwt.verify(presentation, { keyBindingNonce: request.nonce, expectedKeyBindingAudience: request.aud });
  check("Biblioteca verifica su propia presentación (KB-JWT con cnf)", libSelf.kb?.payload?.nonce === request.nonce);

  const aletheia = await http("POST", "/v1/verifications", {
    token,
    json: { presentation, presentation_request_id: request.id },
  });
  check(
    "Aletheia verifica la presentación construida por la biblioteca",
    aletheia.result === "valid" && aletheia.holder_binding_verified,
    `${aletheia.result}${aletheia.reason ? " / " + aletheia.reason : ""}`,
  );
  check(
    "Divulgación selectiva respetada (sólo family_name)",
    aletheia.disclosed_claims?.family_name === "Lovelace" && !("given_name" in (aletheia.disclosed_claims ?? {})),
  );

  // --- OID4VP 1.0: la biblioteca como wallet frente a Aletheia verificador ---------
  const vctValue = verified.payload.vct;
  const vpPolicy =
    (await http("GET", "/v1/trust-policies", { token })).find((p) => p.name === "interop-oid4vp") ??
    (await http("POST", "/v1/trust-policies", {
      token,
      json: { name: "interop-oid4vp", accepted_vcts: [vctValue], required_claims: ["family_name"] },
    }));
  if (!vpPolicy.trusted_issuers?.some((t) => t.issuer === offerDoc.credential_issuer)) {
    await http("POST", `/v1/trust-policies/${vpPolicy.id}/issuers`, { token, json: { issuer: offerDoc.credential_issuer } });
  }
  const vpSession = await http("POST", "/v1/oid4vp/requests", {
    token,
    json: { trust_policy_id: vpPolicy.id, claims: [["family_name"], ["course", "grade"]] },
  });
  // El wallet sólo ve el enlace openid4vp:// (QR): de ahí saca todo lo que necesita.
  const vpUrl = new URL(vpSession.request_uri);
  const q = Object.fromEntries(vpUrl.searchParams);
  const dcql = JSON.parse(q.dcql_query);
  const query = dcql.credentials[0];
  const vctOk = query.format === "dc+sd-jwt" && query.meta.vct_values.includes(vctValue);
  // Marco de presentación a partir de las rutas DCQL: {family_name: true, course: {grade: true}}.
  const frame = {};
  for (const { path } of query.claims ?? []) {
    let node = frame;
    path.forEach((part, i) => {
      if (i === path.length - 1) node[part] = true;
      else node = node[part] ??= {};
    });
  }
  const vpPresentation = await sdjwt.present(credential, frame, {
    kb: { payload: { iat: Math.floor(Date.now() / 1000), aud: q.client_id, nonce: q.nonce } },
  });
  const vpRes = await fetch(internal(q.response_uri), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ state: q.state, vp_token: JSON.stringify({ [query.id]: [vpPresentation] }) }),
  });
  check("OID4VP: solicitud por valor (response_mode direct_post, DCQL dc+sd-jwt)", q.response_mode === "direct_post" && vctOk && q.client_id.startsWith("redirect_uri:"));
  check("OID4VP: Aletheia acepta el direct_post del wallet", vpRes.status === 200, `HTTP ${vpRes.status}`);
  const vpStatus = await http("GET", `/v1/oid4vp/requests/${vpSession.id}`, { token });
  check(
    "OID4VP: resultado valid con los claims pedidos por DCQL",
    vpStatus.status === "completed" && vpStatus.result?.result === "valid" &&
      vpStatus.result.disclosed_claims?.family_name === "Lovelace" && vpStatus.result.disclosed_claims?.course?.grade === "A" &&
      !("given_name" in (vpStatus.result.disclosed_claims ?? {})),
    `${vpStatus.status} / ${vpStatus.result?.result}${vpStatus.result?.reason ? " / " + vpStatus.result.reason : ""}`,
  );

  // --- Revocación: la biblioteca la ve en la Status List ---------------------------
  await http("POST", `/v1/credentials/${offer.id}/revoke`, { token, json: { reason: "other" } });
  let rejected = false;
  let reason = "";
  try {
    await sdjwt.verify(credential);
  } catch (e) {
    rejected = true;
    reason = String(e.message ?? e).slice(0, 120);
  }
  check("Tras revocar, la biblioteca rechaza la credencial por su estado", rejected, reason);

  // Alteración: cambiar un byte de la firma debe romper la verificación.
  const [jwt, ...rest] = credential.split("~");
  const parts = jwt.split(".");
  const sig = Buffer.from(parts[2], "base64url");
  sig[5] ^= 0x01;
  let tamperedRejected = false;
  try {
    await sdjwt.verify([`${parts[0]}.${parts[1]}.${b64url(sig)}`, ...rest].join("~"));
  } catch {
    tamperedRejected = true;
  }
  check("Firma alterada rechazada por la biblioteca", tamperedRejected);

  void webcrypto;
}

try {
  await main();
} catch (e) {
  check("ejecución", false, String(e.stack ?? e));
}
const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} comprobaciones superadas`);
process.exit(failed.length ? 1 : 0);
