"""Etiquetas de campos para la verificación pública: los «title» de la plantilla (sin base)."""

from __future__ import annotations

from aletheia.passes.service import _schema_titles


def test_titles_follow_nested_paths_and_ignore_untitled_fields() -> None:
    schema = {
        "type": "object",
        "properties": {
            "member_id": {"type": "string", "title": "Nº de socio"},
            "given_name": {"type": "string"},
            # Un campo llamado «title» (no la palabra clave) no es una etiqueta.
            "course": {
                "type": "object",
                "title": "Curso",
                "properties": {
                    "title": {"type": "string"},
                    "hours": {"type": "integer", "title": "Horas"},
                },
            },
        },
    }
    assert _schema_titles(schema) == {
        "member_id": "Nº de socio",
        "course": "Curso",
        "course.hours": "Horas",
    }
