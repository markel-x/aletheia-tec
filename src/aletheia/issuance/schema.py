"""Esquema de claims restringido (doc 03, ``template_version.claims_schema``).

Subconjunto de JSON Schema suficiente para certificados: objetos con
propiedades tipadas (``string``, ``integer``, ``number``, ``boolean``,
``date`` y ``object`` anidado), ``required``, ``minLength``/``maxLength``,
``minimum``/``maximum`` y ``enum``. Profundidad ≤ 3 y ≤ 50 propiedades por
objeto. Sin dependencias externas: lo que no está aquí, se rechaza.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from ..platform.errors import AppError

MAX_DEPTH = 3
MAX_PROPERTIES = 50
MAX_STRING_LENGTH = 1_000
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_RESERVED = frozenset({"iss", "iat", "nbf", "exp", "vct", "cnf", "status", "_sd", "_sd_alg", "sub"})
_SCALAR_TYPES = frozenset({"string", "integer", "number", "boolean", "date"})
_ALLOWED_KEYS = {
    "object": {"type", "properties", "required", "description", "title"},
    "string": {"type", "minLength", "maxLength", "enum", "description", "title"},
    "integer": {"type", "minimum", "maximum", "enum", "description", "title"},
    "number": {"type", "minimum", "maximum", "description", "title"},
    "boolean": {"type", "description", "title"},
    "date": {"type", "description", "title"},
}


class InvalidSchema(AppError):
    status_code = 422
    code = "invalid_schema"


class InvalidClaims(AppError):
    status_code = 422
    code = "invalid_claims"


def validate_schema(schema: Any) -> None:
    """Lanza ``InvalidSchema`` si el esquema sale del subconjunto permitido."""
    _validate_node(schema, path="$", depth=1, top=True)


def _validate_node(node: Any, *, path: str, depth: int, top: bool) -> None:
    if not isinstance(node, dict):
        raise InvalidSchema(f"{path}: schema node must be an object")
    node_type = node.get("type")
    if node_type not in _ALLOWED_KEYS:
        raise InvalidSchema(f"{path}: unsupported type {node_type!r}")
    extra = set(node) - _ALLOWED_KEYS[node_type]
    if extra:
        raise InvalidSchema(f"{path}: unsupported keywords {sorted(extra)}")
    if top and node_type != "object":
        raise InvalidSchema("$: root must be an object")
    if node_type == "object":
        if depth > MAX_DEPTH:
            raise InvalidSchema(f"{path}: nesting deeper than {MAX_DEPTH}")
        props = node.get("properties", {})
        if not isinstance(props, dict) or len(props) > MAX_PROPERTIES:
            raise InvalidSchema(
                f"{path}: properties must be an object with at most {MAX_PROPERTIES}"
            )
        if top and not props:
            raise InvalidSchema("$: at least one property is required")
        for name, sub in props.items():
            if not _NAME_RE.match(name):
                raise InvalidSchema(f"{path}.{name}: invalid property name")
            if top and name in _RESERVED:
                raise InvalidSchema(f"{path}.{name}: reserved claim name")
            _validate_node(sub, path=f"{path}.{name}", depth=depth + 1, top=False)
        required = node.get("required", [])
        if not isinstance(required, list) or any(r not in props for r in required):
            raise InvalidSchema(f"{path}: required must list defined properties")
        return
    if "enum" in node:
        enum = node["enum"]
        if not isinstance(enum, list) or not enum or len(enum) > 100:
            raise InvalidSchema(f"{path}: enum must be a non-empty list (≤100)")
        expected = str if node_type == "string" else int
        if any(type(v) is not expected for v in enum):
            raise InvalidSchema(f"{path}: enum values must match the type")
    for key in ("minLength", "maxLength", "minimum", "maximum"):
        if key in node and (not isinstance(node[key], int | float) or isinstance(node[key], bool)):
            raise InvalidSchema(f"{path}: {key} must be numeric")


def selectable_paths(schema: dict[str, Any]) -> set[str]:
    """Rutas con punto de todas las propiedades (para validar ``selective_disclosure``)."""
    out: set[str] = set()

    def walk(node: dict[str, Any], prefix: str) -> None:
        for name, sub in node.get("properties", {}).items():
            path = f"{prefix}{name}"
            out.add(path)
            if sub.get("type") == "object":
                walk(sub, path + ".")

    walk(schema, "")
    return out


def validate_claims(schema: dict[str, Any], claims: Any) -> dict[str, Any]:
    """Valida ``claims`` contra el esquema; devuelve el objeto (sin claves extra)."""
    result = _validate_value(schema, claims, path="$")
    if not isinstance(result, dict):  # el esquema raíz siempre es un objeto
        raise InvalidClaims("$: expected object")
    return result


def _validate_value(node: dict[str, Any], value: Any, *, path: str) -> Any:
    node_type = node["type"]
    if node_type == "object":
        if not isinstance(value, dict):
            raise InvalidClaims(f"{path}: expected object")
        props = node.get("properties", {})
        unknown = set(value) - set(props)
        if unknown:
            raise InvalidClaims(f"{path}: unknown properties {sorted(unknown)}")
        for name in node.get("required", []):
            if name not in value:
                raise InvalidClaims(f"{path}.{name}: required")
        return {
            name: _validate_value(props[name], val, path=f"{path}.{name}")
            for name, val in value.items()
        }
    if node_type == "string":
        if not isinstance(value, str):
            raise InvalidClaims(f"{path}: expected string")
        if len(value) > min(node.get("maxLength", MAX_STRING_LENGTH), MAX_STRING_LENGTH):
            raise InvalidClaims(f"{path}: too long")
        if len(value) < node.get("minLength", 0):
            raise InvalidClaims(f"{path}: too short")
        if "enum" in node and value not in node["enum"]:
            raise InvalidClaims(f"{path}: not an allowed value")
        return value
    if node_type == "integer":
        if type(value) is not int:
            raise InvalidClaims(f"{path}: expected integer")
    elif node_type == "number":
        if type(value) not in (int, float):
            raise InvalidClaims(f"{path}: expected number")
    elif node_type == "boolean":
        if type(value) is not bool:
            raise InvalidClaims(f"{path}: expected boolean")
        return value
    elif node_type == "date":
        if not isinstance(value, str):
            raise InvalidClaims(f"{path}: expected date (YYYY-MM-DD)")
        try:
            date.fromisoformat(value)
        except ValueError:
            raise InvalidClaims(f"{path}: expected date (YYYY-MM-DD)") from None
        if len(value) != 10:
            raise InvalidClaims(f"{path}: expected date (YYYY-MM-DD)")
        return value
    if "minimum" in node and value < node["minimum"]:
        raise InvalidClaims(f"{path}: below minimum")
    if "maximum" in node and value > node["maximum"]:
        raise InvalidClaims(f"{path}: above maximum")
    if "enum" in node and value not in node["enum"]:
        raise InvalidClaims(f"{path}: not an allowed value")
    return value
