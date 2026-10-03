"""La interfaz existe completa en español e inglés (admin/static).

- ``strings.js``: cada clave tiene texto en ambos idiomas, con las mismas variables ``{x}``.
- Toda clave usada en el código (``t("…")`` o ``data-i18n…="…"``) existe en el catálogo.
- ``help.js`` y ``help-en.js`` tienen las mismas claves en cada export y las mismas secciones.
Sin navegador: se leen los archivos como texto.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "src" / "aletheia" / "admin" / "static"
ENTRY = re.compile(r'^  ("[^"]+"): \{ es: (".*"), en: (".*") \},$')
VARS = re.compile(r"\{(\w+)\}")
# Claves que se arman en tiempo de ejecución (t(`prefijo.${valor}`)).
DYNAMIC_PREFIXES = (
    "type.",
    "editor.type.",
    "claim.error.",
    "verify.reason.",
    "verify.state.",
    "claim.",
)


def _catalog() -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for line in (STATIC / "strings.js").read_text().splitlines():
        match = ENTRY.match(line)
        if match:
            key, es, en = (json.loads(g) for g in match.groups())
            assert key not in entries, f"clave repetida: {key}"
            entries[key] = (es, en)
        elif line.startswith('  "'):
            raise AssertionError(f"entrada con formato inesperado: {line[:80]}")
    return entries


def test_every_string_has_both_languages_with_the_same_variables() -> None:
    catalog = _catalog()
    assert len(catalog) > 200
    for key, (es, en) in catalog.items():
        assert es.strip() and en.strip(), f"{key}: falta un idioma"
        assert set(VARS.findall(es)) == set(VARS.findall(en)), f"{key}: variables distintas"


def test_every_key_used_in_the_code_exists() -> None:
    catalog = _catalog()
    used: set[str] = set()
    for path in [*STATIC.glob("*.js"), *STATIC.glob("*.html")]:
        if path.name in {"strings.js", "help.js", "help-en.js"}:
            continue
        source = path.read_text()
        used |= set(re.findall(r'\bt\("([a-z_]+\.[a-z0-9_.]+)"', source))
        used |= set(re.findall(r'data-i18n(?:-[a-z-]+)?="([a-z_]+\.[a-z0-9_.]+)"', source))
    assert used, "no se encontraron usos de t()"
    assert sorted(used - catalog.keys()) == []
    unused = {k for k in catalog.keys() - used if not k.startswith(DYNAMIC_PREFIXES)}
    assert sorted(unused) == [], "claves sin uso: bórrelas o úselas"


def _help_structure(name: str) -> dict[str, list[str]]:
    structure: dict[str, list[str]] = {}
    current: str | None = None
    for line in (STATIC / name).read_text().splitlines():
        if start := re.match(r"^export const (\w+) = ", line):
            current = start.group(1)
            structure[current] = []
        elif line.startswith(("};", "];")):
            current = None
        elif current == "DOCS" and (doc := re.match(r'^    id: "([^"]+)"', line)):
            structure[current].append(doc.group(1))
        elif current and current != "DOCS" and (key := re.match(r'^  "?([\w.]+)"?:', line)):
            structure[current].append(key.group(1))
    return structure


def test_help_modules_mirror_each_other() -> None:
    es, en = _help_structure("help.js"), _help_structure("help-en.js")
    assert set(es) == {"FIELD_HELP", "SECTION_HELP", "ERROR_TIPS", "DOCS"}
    assert es == en
    assert all(es.values())
