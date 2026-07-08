"""
crypto_utils.py
----------------
Funcoes de criptografia usadas pelo sistema de mensagens seguras.

Conceitos aplicados (Capitulo 3 - Seguranca da Informacao):
- Criptografia assimetrica RSA (geracao de chaves, criptografia OAEP)
- Criptografia simetrica AES-256 em modo CBC
- Serializacao de chaves (PEM) para transmissao via rede

Toda a criptografia usa a biblioteca `cryptography`, que e auditada e
testada. Nenhum algoritmo criptografico e implementado do zero.
"""

import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


# ---------------------------------------------------------------------------
# RSA - criptografia assimetrica (troca de chaves)
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    """Gera um par de chaves RSA-2048 (privada + publica)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key) -> bytes:
    """Converte a chave publica para bytes PEM (para enviar pela rede)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_bytes: bytes):
    """Reconstroi um objeto de chave publica a partir de bytes PEM."""
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Criptografa dados (ex.: uma chave AES) com a chave publica RSA
    do destinatario, usando padding OAEP (recomendado, seguro contra
    ataques de padding oracle)."""
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Descriptografa dados com a chave privada RSA do destinatario."""
    return private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ---------------------------------------------------------------------------
# AES - criptografia simetrica (conteudo das mensagens)
# ---------------------------------------------------------------------------

def generate_aes_key() -> bytes:
    """Gera uma chave aleatoria de 256 bits (32 bytes) para AES-256."""
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Criptografa `plaintext` com AES-256 em modo CBC.

    Retorna (iv, ciphertext). O IV (vetor de inicializacao) deve ser
    aleatorio a cada mensagem e e enviado junto (nao precisa ser secreto).
    """
    iv = os.urandom(16)  # tamanho do bloco AES = 16 bytes

    # AES em modo CBC exige que o texto tenha tamanho multiplo de 16 bytes,
    # por isso aplicamos padding PKCS7 antes de criptografar.
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext


def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Descriptografa uma mensagem AES-256-CBC e remove o padding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext


# ---------------------------------------------------------------------------
# Helpers de codificacao (bytes <-> base64) para transportar dados binarios
# dentro de mensagens JSON via socket
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
