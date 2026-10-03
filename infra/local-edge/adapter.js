
// --- Adaptador njs (infra/local-edge): ejecuta en nginx la MISMA función de CloudFront que se
// publica en AWS (infra/terraform/cloudfront/viewer-request.js, concatenada antes de este texto al
// arrancar el contenedor). Traduce la petición de nginx al evento de CloudFront y su resultado a
// nginx: una respuesta generada (401, 308, 404) o el archivo de S3, servido desde /__site/.

function route(r) {
  var headers = {};
  for (var name in r.headersIn) {
    headers[name.toLowerCase()] = { value: r.headersIn[name] };
  }
  var result = handler({ request: { uri: r.uri, headers: headers } });
  if (!result.statusCode) {
    r.internalRedirect("/__site" + result.uri);
    return;
  }
  if (result.statusCode >= 300 && result.statusCode < 400) {
    r.return(result.statusCode, result.headers.location.value);
    return;
  }
  for (var h in result.headers) {
    r.headersOut[h] = result.headers[h].value;
  }
  r.return(result.statusCode, result.body ? result.body.data : "");
}

export default { route };
