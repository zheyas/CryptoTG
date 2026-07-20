import base64
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from cryptography.hazmat.decrepit.ciphers import modes as legacy_modes
except ImportError:
    legacy_modes = modes

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from crypto_utils import CryptoManager


class CryptoManagerTest(unittest.TestCase):
    def setUp(self):
        self.crypto = CryptoManager()

    def test_encrypt_decrypt_round_trip(self):
        encrypted = self.crypto.encrypt("Привет, защищенный мир", "strong-passphrase")

        self.assertTrue(encrypted.startswith(CryptoManager.VERSION_PREFIX))
        self.assertEqual(
            self.crypto.decrypt(encrypted, "strong-passphrase"),
            "Привет, защищенный мир"
        )

    def test_wrong_key_does_not_return_plaintext(self):
        encrypted = self.crypto.encrypt("секрет", "right-password")

        self.assertEqual(
            self.crypto.decrypt(encrypted, "wrong-password"),
            "[Не удалось расшифровать]"
        )

    def test_legacy_cfb_messages_are_still_readable(self):
        password = "secret123"
        message = "старое учебное сообщение"
        salt = b"0" * 16
        iv = b"1" * 16

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode("utf-8"))
        cipher = Cipher(algorithms.AES(key), legacy_modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(message.encode("utf-8")) + encryptor.finalize()
        legacy_payload = base64.b64encode(salt + iv + encrypted).decode("utf-8")

        self.assertEqual(self.crypto.decrypt(legacy_payload, password), message)


if __name__ == "__main__":
    unittest.main()
