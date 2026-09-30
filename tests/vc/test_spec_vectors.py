"""Vectores de prueba publicados en las especificaciones (evidencia de conformidad
del formato, independiente de nuestra propia implementación)."""

from __future__ import annotations

from aletheia.vc.sdjwt import create_disclosure, decode_disclosure
from aletheia.vc.status_list import StatusList

# RFC 9901, sección de creación de Disclosures (ejemplo "family_name": "Möbius").
RFC9901_FAMILY_NAME = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
RFC9901_FAMILY_NAME_DIGEST = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"
# RFC 9901, ejemplo de elemento de array ("FR").
RFC9901_ARRAY_FR = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"


def test_rfc9901_object_disclosure_digest() -> None:
    disclosure = decode_disclosure(RFC9901_FAMILY_NAME)
    assert (disclosure.salt, disclosure.name, disclosure.value) == (
        "_26bc4LT-ac6q2KI6cBW5es",
        "family_name",
        "Möbius",
    )
    assert disclosure.digest == RFC9901_FAMILY_NAME_DIGEST


def test_rfc9901_array_element_disclosure() -> None:
    disclosure = decode_disclosure(RFC9901_ARRAY_FR)
    assert (disclosure.salt, disclosure.name, disclosure.value) == (
        "lklxF5jMYlGTPUovMNIvCA",
        None,
        "FR",
    )


def test_created_disclosure_roundtrip_keeps_unicode() -> None:
    d = create_disclosure("family_name", "Möbius", salt="_26bc4LT-ac6q2KI6cBW5es")
    back = decode_disclosure(d.encoded)
    assert (back.name, back.value, back.digest) == ("family_name", "Möbius", d.digest)


# draft-ietf-oauth-status-list-21, ejemplo de lista de 1 bit.
TSL_EXAMPLE_1BIT = {"bits": 1, "lst": "eNrbuRgAAhcBXQ"}
TSL_EXAMPLE_STATUSES = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1]


def test_token_status_list_1bit_example_decodes() -> None:
    sl = StatusList.decode(TSL_EXAMPLE_1BIT)
    assert sl.to_bytes() == bytes([0xB9, 0xA3])
    assert [sl.get(i) for i in range(16)] == TSL_EXAMPLE_STATUSES


def test_token_status_list_1bit_example_reencodes_same_bytes() -> None:
    sl = StatusList(size=16)
    for idx, value in enumerate(TSL_EXAMPLE_STATUSES):
        sl.set(idx, value)
    assert sl.to_bytes() == bytes([0xB9, 0xA3])
    # La salida comprimida puede diferir byte a byte (nivel de compresión);
    # lo normativo es el contenido descomprimido.
    assert StatusList.decode(sl.encode()).to_bytes() == bytes([0xB9, 0xA3])
