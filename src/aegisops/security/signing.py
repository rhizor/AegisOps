from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def keygen(private_key_path: Path, public_key_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    private_key_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def sign_message(private_key_path: Path, message: bytes) -> str:
    priv = load_private_key(private_key_path)
    sig = priv.sign(message)
    return base64.b64encode(sig).decode("ascii")


def verify_message(public_key_path: Path, message: bytes, signature_b64: str) -> bool:
    pub = load_public_key(public_key_path)
    try:
        sig = base64.b64decode(signature_b64.encode("ascii"))
        pub.verify(sig, message)
        return True
    except Exception:
        return False


def public_key_fingerprint(public_key_pem: bytes) -> str:
    return hashlib.sha256(public_key_pem).hexdigest()
