"""
auth.py
-------
Autenticacao de usuarios com hash de senha (SHA-256 via PBKDF2 + salt).

Regra de ouro: a senha em texto claro NUNCA e armazenada nem comparada
diretamente. Armazenamos apenas o salt e o hash resultante. No login,
recalculamos o hash da senha digitada com o mesmo salt e comparamos os
hashes (comparacao em tempo constante, evitando timing attacks).
"""

import os
import hashlib
import hmac

# Numero de iteracoes do PBKDF2 (quanto maior, mais lento para atacantes
# tentarem forca bruta / rainbow tables).
PBKDF2_ITERATIONS = 100_000
SALT_SIZE = 16  # bytes


def hash_password(password: str) -> str:
    """Gera um novo salt aleatorio e retorna 'salt_hex$hash_hex'."""
    salt = os.urandom(SALT_SIZE)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return f"{salt.hex()}${pwd_hash.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Recalcula o hash da senha fornecida com o salt armazenado e
    compara com o hash salvo, em tempo constante."""
    try:
        salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False

    salt = bytes.fromhex(salt_hex)
    expected_hash = bytes.fromhex(hash_hex)

    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )

    return hmac.compare_digest(new_hash, expected_hash)
