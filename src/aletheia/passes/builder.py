"""Construcción del ``.pkpass``: ``pass.json`` (pase genérico), imágenes,
``manifest.json`` (SHA-1 de cada archivo, como exige PassKit) y ``signature``."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime
from typing import Any

from .images import pass_images
from .signing import PassSigner

PKPASS_MEDIA_TYPE = "application/vnd.apple.pkpass"

# Claims técnicos del SD-JWT VC que no se muestran como datos del certificado.
_TECHNICAL = {"iss", "iat", "nbf", "exp", "vct", "status", "cnf", "_sd", "_sd_alg"}


def _flatten(claims: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for key, value in claims.items():
        if not prefix and key in _TECHNICAL:
            continue
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.extend(_flatten(value, path + "."))
        else:
            out.append((path, value))
    return out


# Etiquetas legibles para los campos habituales; el resto se deriva del nombre.
LABELS = {
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
}


def _label(path: str) -> str:
    return LABELS.get(path) or path.replace(".", " · ").replace("_", " ").capitalize()


def pass_json(
    *,
    pass_type_identifier: str,
    team_identifier: str,
    serial_number: str,
    organization_name: str,
    credential_name: str,
    claims: dict[str, Any],
    issued_at: datetime,
    expires_at: datetime,
    verify_url: str,
) -> dict[str, Any]:
    """Pase genérico: título (p. ej. el curso), titular, fechas y el resto de datos al dorso."""
    flat = dict(_flatten(claims))
    holder = " ".join(str(flat[k]) for k in ("given_name", "family_name") if k in flat)
    title = flat.get("course.title") or flat.get("title") or credential_name
    shown = {"given_name", "family_name", "course.title", "title"}
    back = [
        {"key": f"c{i}", "label": _label(path), "value": str(value)}
        for i, (path, value) in enumerate(flat.items())
        if path not in shown
    ]
    back += [
        {"key": "issuer", "label": "Emisor", "value": organization_name},
        {"key": "credential", "label": "Identificador", "value": serial_number},
        {
            "key": "how",
            "label": "Cómo verificar",
            "value": "Escanee el código QR: abre la verificación de CredoSeal, que comprueba "
            "la firma del emisor y si la credencial sigue vigente o fue revocada.",
        },
    ]
    secondary = [{"key": "holder", "label": "TITULAR", "value": holder}] if holder else []
    return {
        "formatVersion": 1,
        "passTypeIdentifier": pass_type_identifier,
        "teamIdentifier": team_identifier,
        "serialNumber": serial_number,
        "organizationName": organization_name,
        "description": credential_name,
        "logoText": organization_name,
        "foregroundColor": "rgb(230, 235, 238)",
        "backgroundColor": "rgb(20, 27, 32)",
        "labelColor": "rgb(139, 149, 255)",
        "expirationDate": expires_at.astimezone(UTC).isoformat(timespec="seconds"),
        "barcodes": [
            {
                "format": "PKBarcodeFormatQR",
                "message": verify_url,
                "messageEncoding": "iso-8859-1",
                "altText": "Verificar",
            }
        ],
        "generic": {
            "headerFields": [{"key": "type", "label": "CREDENCIAL", "value": credential_name}],
            "primaryFields": [
                {"key": "title", "label": credential_name.upper(), "value": str(title)}
            ],
            "secondaryFields": secondary,
            "auxiliaryFields": [
                {
                    "key": "issued",
                    "label": "EMITIDA",
                    "value": issued_at.astimezone(UTC).isoformat(timespec="seconds"),
                    "dateStyle": "PKDateStyleMedium",
                },
                {
                    "key": "expires",
                    "label": "VÁLIDA HASTA",
                    "value": expires_at.astimezone(UTC).isoformat(timespec="seconds"),
                    "dateStyle": "PKDateStyleMedium",
                },
            ],
            "backFields": back,
        },
    }


def build_pkpass(pass_document: dict[str, Any], signer: PassSigner) -> bytes:
    files: dict[str, bytes] = {
        "pass.json": json.dumps(pass_document, ensure_ascii=False, indent=1).encode(),
        **pass_images(),
    }
    manifest = json.dumps(
        {name: hashlib.sha1(data).hexdigest() for name, data in files.items()},  # noqa: S324 - PassKit exige SHA-1
        sort_keys=True,
    ).encode()
    files["manifest.json"] = manifest
    files["signature"] = signer.sign(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()
