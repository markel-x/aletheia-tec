// CloudFront Function (cloudfront-js-2.0), solicitud del visitante en el comportamiento por
// defecto (S3). Hace lo que hacía el router de páginas de la API (admin/router.py):
//   - acceso restringido temporal (HTTP Basic) mientras el sitio no está abierto;
//   - URLs limpias → archivo en S3 (/ → landing.html, /claim/<id> → claim.html, …);
//   - 404 para todo lo demás (S3 no lista ni expone otras claves).
// Plantilla de Terraform: AUTH y DOCS se completan en frontend.tf.

var AUTH = "${auth}"; // "Basic <base64>" o "" (sitio abierto)
var DOCS = ${docs}; // la referencia de la API no se publica en producción

var PAGES = {
  "/": "/admin/static/landing.html",
  "/admin/": "/admin/static/index.html",
  "/v": "/admin/static/verify.html",
  "/docs": "/admin/static/docs.html",
  "/favicon.ico": "/admin/static/favicon.ico",
};
var CLAIM = /^\/claim\/[A-Za-z0-9_-]{8,128}$/;
var ISSUER = /^\/issuers\/[A-Za-z0-9_-]{3,64}$/;
var ASSET = /^\/admin\/static\/[A-Za-z0-9._-]+$/;

function respond(status, description, headers, body) {
  var response = { statusCode: status, statusDescription: description, headers: headers };
  if (body) response.body = { encoding: "text", data: body };
  return response;
}

function handler(event) {
  var request = event.request;
  var uri = request.uri;

  if (AUTH) {
    var given = request.headers.authorization;
    if (!given || given.value !== AUTH) {
      return respond(401, "Unauthorized", {
        "www-authenticate": { value: 'Basic realm="CredoSeal", charset="UTF-8"' },
        "x-robots-tag": { value: "noindex, nofollow" },
        "cache-control": { value: "no-store" },
      });
    }
  }

  if (uri === "/admin") {
    return respond(308, "Permanent Redirect", { location: { value: "/admin/" } });
  }
  if (uri === "/docs" && !DOCS) {
    uri = "";
  }
  var page = PAGES[uri];
  if (page) {
    request.uri = page;
    return request;
  }
  if (CLAIM.test(uri)) {
    request.uri = "/admin/static/claim.html";
    return request;
  }
  if (ISSUER.test(uri)) {
    request.uri = "/admin/static/issuer.html";
    return request;
  }
  if (ASSET.test(uri)) {
    return request;
  }
  return respond(
    404,
    "Not Found",
    { "content-type": { value: "text/plain; charset=utf-8" }, "cache-control": { value: "no-store" } },
    "Not Found",
  );
}
