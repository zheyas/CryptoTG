import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class CryptoManager:
    def __init__(self):
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes = None) -> tuple:
        """Производный ключ из пароля произвольной длины"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt(self, message: str, password: str) -> str:
        """Шифрование сообщения"""
        key, salt = self.derive_key(password)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        encrypted = encryptor.update(message.encode()) + encryptor.finalize()

        # Объединяем salt + iv + encrypted
        combined = salt + iv + encrypted
        return base64.b64encode(combined).decode()

    def decrypt(self, encrypted_message: str, password: str) -> str:
        """Дешифрование сообщения"""
        try:
            combined = base64.b64decode(encrypted_message)
            salt = combined[:16]
            iv = combined[16:32]
            encrypted = combined[32:]

            key, _ = self.derive_key(password, salt)

            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
            decryptor = cipher.decryptor()

            decrypted = decryptor.update(encrypted) + decryptor.finalize()
            return decrypted.decode()
        except Exception:
            return "[Не удалось расшифровать]"
