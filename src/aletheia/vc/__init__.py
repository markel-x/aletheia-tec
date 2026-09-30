"""Núcleo de formato y firma de credenciales (perfil ALT-P1).

Este paquete no depende de la capa web ni de la base de datos. Los primitivos
criptográficos provienen de ``hashlib``, ``secrets``, ``cryptography`` y, en
entornos desplegados, de AWS KMS. La verificación JWS usa PyJWT, una
implementación independiente del código que produce las firmas (ADR-0003).
"""

PROFILE_ID = "ALT-P1"
SD_JWT_VC_TYP = "dc+sd-jwt"
KB_JWT_TYP = "kb+jwt"
STATUS_LIST_TYP = "statuslist+jwt"
OID4VCI_PROOF_TYP = "openid4vci-proof+jwt"
ALLOWED_ALGS: frozenset[str] = frozenset({"ES256"})
SD_ALG = "sha-256"
