"""Esquema de claims restringido: validación del esquema y de los claims."""

from __future__ import annotations

from typing import Any

import pytest

from aletheia.issuance.schema import (
    InvalidClaims,
    InvalidSchema,
    selectable_paths,
    validate_claims,
    validate_schema,
)

COURSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "course": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "minLength": 1, "maxLength": 200},
                "hours": {"type": "integer", "minimum": 1, "maximum": 10000},
                "grade": {"type": "string", "enum": ["A", "B", "C"]},
            },
            "required": ["title", "hours"],
        },
        "given_name": {"type": "string", "maxLength": 100},
        "family_name": {"type": "string", "maxLength": 100},
        "completion_date": {"type": "date"},
        "student_id": {"type": "string"},
        "honors": {"type": "boolean"},
    },
    "required": ["course", "given_name", "family_name", "completion_date"],
}


def test_valid_schema_and_paths() -> None:
    validate_schema(COURSE_SCHEMA)
    assert selectable_paths(COURSE_SCHEMA) == {
        "course",
        "course.title",
        "course.hours",
        "course.grade",
        "given_name",
        "family_name",
        "completion_date",
        "student_id",
        "honors",
    }


@pytest.mark.parametrize(
    ("schema", "fragment"),
    [
        ({"type": "string"}, "root must be an object"),
        ({"type": "object", "properties": {}}, "at least one property"),
        ({"type": "object", "properties": {"x": {"type": "array"}}}, "unsupported type"),
        ({"type": "object", "properties": {"iss": {"type": "string"}}}, "reserved"),
        ({"type": "object", "properties": {"Bad-Name": {"type": "string"}}}, "invalid property"),
        (
            {"type": "object", "properties": {"x": {"type": "string", "pattern": ".*"}}},
            "unsupported keywords",
        ),
        (
            {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["y"]},
            "required must",
        ),
        (
            {"type": "object", "properties": {"x": {"type": "integer", "enum": ["1"]}}},
            "enum values",
        ),
        (
            {
                "type": "object",
                "properties": {
                    "a": {
                        "type": "object",
                        "properties": {
                            "b": {
                                "type": "object",
                                "properties": {
                                    "c": {"type": "object", "properties": {"d": {"type": "string"}}}
                                },
                            }
                        },
                    }
                },
            },
            "deeper than",
        ),
        (
            {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(51)}},
            "at most 50",
        ),
    ],
)
def test_invalid_schemas(schema: dict[str, Any], fragment: str) -> None:
    with pytest.raises(InvalidSchema, match=fragment):
        validate_schema(schema)


def test_valid_claims_are_returned_without_extras() -> None:
    claims = {
        "course": {"title": "Curso", "hours": 40, "grade": "A"},
        "given_name": "Ana",
        "family_name": "Pérez",
        "completion_date": "2026-09-30",
        "honors": True,
    }
    assert validate_claims(COURSE_SCHEMA, claims) == claims


@pytest.mark.parametrize(
    ("claims", "fragment"),
    [
        ({"given_name": "Ana"}, "required"),
        (
            {
                "course": {"title": "x", "hours": 1},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-13-01",
            },
            "date",
        ),
        (
            {
                "course": {"title": "x", "hours": 1},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-09-30",
                "extra": 1,
            },
            "unknown",
        ),
        (
            {
                "course": {"title": "x", "hours": "40"},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-09-30",
            },
            "integer",
        ),
        (
            {
                "course": {"title": "x", "hours": 0},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-09-30",
            },
            "minimum",
        ),
        (
            {
                "course": {"title": "x", "hours": 1, "grade": "Z"},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-09-30",
            },
            "allowed",
        ),
        (
            {
                "course": {"title": "x", "hours": True},
                "given_name": "A",
                "family_name": "B",
                "completion_date": "2026-09-30",
            },
            "integer",
        ),
        (
            {
                "course": {"title": "x", "hours": 1},
                "given_name": "A" * 101,
                "family_name": "B",
                "completion_date": "2026-09-30",
            },
            "too long",
        ),
    ],
)
def test_invalid_claims(claims: dict[str, Any], fragment: str) -> None:
    with pytest.raises(InvalidClaims, match=fragment):
        validate_claims(COURSE_SCHEMA, claims)
