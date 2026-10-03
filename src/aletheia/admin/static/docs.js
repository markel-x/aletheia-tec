// Documentación de la API: textos propios en el idioma elegido y Swagger UI con el estilo de
// CredoSeal (docs.css). El bundle de Swagger UI se carga antes desde el CDN fijado en docs.html.

import { lang, langSwitch, t, translateStatic } from "./i18n.js";

if (lang !== "es") translateStatic();
document.title = t("docs.meta.title");
document.getElementById("docs-base").textContent = `${location.origin}/v1`;
document.getElementById("docs-lang").appendChild(langSwitch());

window.SwaggerUIBundle({
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  deepLinking: true,
  docExpansion: "list",
  defaultModelsExpandDepth: 0,
  displayRequestDuration: true,
  filter: true,
  persistAuthorization: true,
  tryItOutEnabled: false,
  syntaxHighlight: { activated: true, theme: "obsidian" },
  presets: [window.SwaggerUIBundle.presets.apis],
  layout: "BaseLayout",
});
