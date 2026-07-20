import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

try:
    from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes
except ImportError:
    legacy_modes = modes


class CryptoManager:
    VERSION_PREFIX = "v2:"
    SALT_SIZE = 16
    NONCE_SIZE = 12
    KEY_SIZE = 32
    PBKDF2_ITERATIONS = 200_000
    LEGACY_PBKDF2_ITERATIONS = 100_000

    def __init__(self):
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Производный AES-256 ключ из пароля."""
        if not password:
            raise ValueError("Password is required for encryption")

        if salt is None:
            salt = os.urandom(self.SALT_SIZE)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )
        key = kdf.derive(password.encode("utf-8"))
        return key, salt

    def encrypt(self, message: str, password: str) -> str:
        """Шифрование сообщения через AES-256-GCM."""
        if message is None:
            message = ""

        key, salt = self.derive_key(password)
        nonce = os.urandom(self.NONCE_SIZE)

        encrypted = AESGCM(key).encrypt(nonce, message.encode("utf-8"), None)
        combined = salt + nonce + encrypted

        return self.VERSION_PREFIX + base64.b64encode(combined).decode("utf-8")

    def decrypt(self, encrypted_message: str, password: str) -> str:
        """Дешифрование сообщения.

        Новые сообщения используют AES-GCM. Старый AES-CFB формат оставлен
        только для чтения уже созданных учебных сообщений.
        """
        try:
            if not encrypted_message or not password:
                return encrypted_message

            if not encrypted_message.startswith(self.VERSION_PREFIX):
                return self._decrypt_legacy_cfb(encrypted_message, password)

            payload = encrypted_message[len(self.VERSION_PREFIX):]
            combined = base64.b64decode(payload)
            if len(combined) <= self.SALT_SIZE + self.NONCE_SIZE:
                raise ValueError("Encrypted payload is too short")

            salt = combined[:self.SALT_SIZE]
            nonce = combined[self.SALT_SIZE:self.SALT_SIZE + self.NONCE_SIZE]
            encrypted = combined[self.SALT_SIZE + self.NONCE_SIZE:]

            key, _ = self.derive_key(password, salt)
            decrypted = AESGCM(key).decrypt(nonce, encrypted, None)

            return decrypted.decode("utf-8")
        except Exception:
            return "[Не удалось расшифровать]"

    def _derive_legacy_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.LEGACY_PBKDF2_ITERATIONS,
            backend=self.backend
        )
        return kdf.derive(password.encode("utf-8"))

    def _decrypt_legacy_cfb(self, encrypted_message: str, password: str) -> str:
        combined = base64.b64decode(encrypted_message)
        if len(combined) <= self.SALT_SIZE + 16:
            raise ValueError("Legacy encrypted payload is too short")

        salt = combined[:self.SALT_SIZE]
        iv = combined[self.SALT_SIZE:self.SALT_SIZE + 16]
        encrypted = combined[self.SALT_SIZE + 16:]

        key = self._derive_legacy_key(password, salt)
        cipher = Cipher(algorithms.AES(key), legacy_modes.CFB(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()

        return decrypted.decode("utf-8")
