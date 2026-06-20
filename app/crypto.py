import os
import hmac
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
class KeyManager:
    def __init__(self, key_dir="instance/keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(
            parents=True,
            exist_ok=True
        )
        self.encryption_key_path = self.key_dir / "encryption.key"
        self.hmac_key_path = self.key_dir / "hmac.key"
        self.lookup_key_path = self.key_dir / "lookup.key"
        self._initialize_keys()
    def _initialize_keys(self):
        if not self.encryption_key_path.exists():
            self.encryption_key_path.write_bytes(
                os.urandom(32)
            )
        if not self.hmac_key_path.exists():
            self.hmac_key_path.write_bytes(
                os.urandom(32)
            )
        if not self.lookup_key_path.exists():
            self.lookup_key_path.write_bytes(
                os.urandom(32)
            )
    def get_master_key(self):
        return self.encryption_key_path.read_bytes()
    def get_hmac_key(self):
        return self.hmac_key_path.read_bytes()
    def get_lookup_key(self):
        return self.lookup_key_path.read_bytes()
    def get_fernet(self):
        return Fernet(
            base64.urlsafe_b64encode(
                self.get_master_key()
            )
        )
class CryptoService:
    def __init__(self):
        self.manager = KeyManager()
        self.fernet = self.manager.get_fernet()
        self.hmac_key = self.manager.get_hmac_key()
        self.lookup_key = self.manager.get_lookup_key()
    # ------------------
    # ENCRYPTION
    # ------------------
    def encrypt(self, plaintext):
        return self.fernet.encrypt(
            plaintext.encode()
        ).decode()
    def decrypt(self, ciphertext):
        try:
            return self.fernet.decrypt(
                ciphertext.encode()
            ).decode()
        except InvalidToken:
            raise ValueError(
                "Decryption failed"
            )
    # ------------------
    # MAC
    # ------------------
    def generate_mac(self, value):
        return hmac.new(
            self.hmac_key,
            value.encode(),
            hashlib.sha256
        ).hexdigest()
    def verify_mac(self, value, mac):
        expected = self.generate_mac(value)
        return hmac.compare_digest(
            expected,
            mac
        )
    # ------------------
    # USER LOOKUP
    # ------------------
    def username_lookup(self, username):
        normalized = username.strip().lower()
        return hmac.new(
            self.lookup_key,
            normalized.encode(),
            hashlib.sha256
        ).hexdigest()
    # ------------------
    # PER USER DATA KEY
    # ------------------
    def generate_user_key(self):
        return Fernet.generate_key().decode()
    def encrypt_user_key(self, user_key):
        return self.encrypt(user_key)
    def decrypt_user_key(self, encrypted_key):
        return self.decrypt(encrypted_key)
    def encrypt_with_user_key(
        self,
        plaintext,
        user_key
    ):
        f = Fernet(
            user_key.encode()
        )
        return f.encrypt(
            plaintext.encode()
        ).decode()
    def decrypt_with_user_key(
        self,
        ciphertext,
        user_key
    ):
        f = Fernet(
            user_key.encode()
        )
        return f.decrypt(
            ciphertext.encode()
        ).decode()
crypto = CryptoService()