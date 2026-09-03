import hashlib
import json
import os
from datetime import datetime
from io import StringIO
from pathlib import Path

from django.conf import settings
from django.core.management import call_command


BACKUP_FILE = "backup.enc"
META_FILE = "backup_meta.json"


def get_backup_dir():
    return Path(getattr(settings, "SECURE_BACKUP_DIR", settings.BASE_DIR / "secure_backups"))


def get_backup_paths():
    backup_dir = get_backup_dir()
    return backup_dir / BACKUP_FILE, backup_dir / META_FILE


def _get_crypto():
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, hmac, padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise RuntimeError(
            "Brakuje pakietu cryptography. Zainstaluj zaleznosci z requirements.txt."
        ) from exc

    return Cipher, algorithms, modes, padding, hashes, hmac, HKDF, default_backend


def _derive_key():
    _, _, _, _, hashes, _, HKDF, _ = _get_crypto()
    secret = settings.SECRET_KEY.encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"fakeaccount-secure-backup-v1",
        info=b"database-backup",
    ).derive(secret)


def _dump_database():
    output = StringIO()
    call_command("dumpdata", stdout=output)
    return output.getvalue().encode("utf-8")


def _read_meta(meta_path):
    if not meta_path.exists():
        return None

    with meta_path.open("r", encoding="utf-8") as meta_file:
        return json.load(meta_file)


def create_secure_backup(skip_duplicate=True):
    backup_path, meta_path = get_backup_paths()
    backup_path.parent.mkdir(parents=True, exist_ok=True)

    data = _dump_database()
    digest = hashlib.sha256(data).hexdigest()
    previous_meta = _read_meta(meta_path)

    if skip_duplicate and backup_path.exists() and previous_meta and previous_meta.get("dump_sha256") == digest:
        return {
            "created": False,
            "reason": "duplicate",
            "backup_path": str(backup_path),
            "meta_path": str(meta_path),
        }

    Cipher, algorithms, modes, padding, hashes, hmac, _, default_backend = _get_crypto()
    aes_key = _derive_key()
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    mac = hmac.HMAC(aes_key, hashes.SHA256())
    mac.update(iv + ciphertext)
    hmac_value = mac.finalize()

    backup_path.write_bytes(iv + ciphertext)
    meta = {
        "algorithm": "AES-256-CBC-HMAC-SHA256",
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "dump_sha256": digest,
        "hmac": hmac_value.hex(),
    }

    with meta_path.open("w", encoding="utf-8") as meta_file:
        json.dump(meta, meta_file, indent=2)

    return {
        "created": True,
        "backup_path": str(backup_path),
        "meta_path": str(meta_path),
    }


def decrypt_secure_backup():
    backup_path, meta_path = get_backup_paths()

    if not backup_path.exists() or not meta_path.exists():
        raise FileNotFoundError("Nie znaleziono zaszyfrowanej kopii zapasowej.")

    Cipher, algorithms, modes, padding, hashes, hmac, _, default_backend = _get_crypto()
    aes_key = _derive_key()
    encrypted = backup_path.read_bytes()

    if len(encrypted) < 17:
        raise ValueError("Plik backupu jest uszkodzony.")

    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    meta = _read_meta(meta_path)

    mac = hmac.HMAC(aes_key, hashes.SHA256())
    mac.update(iv + ciphertext)
    mac.verify(bytes.fromhex(meta["hmac"]))

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()
