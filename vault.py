"""
vault.py — Core encryption, hashing, and storage for the password manager.

Security design:
- Master password is never stored. A PBKDF2-HMAC-SHA256 derived key is used
  to encrypt vault data, and only a salted hash of the master password is
  stored to verify it on login.
- Vault entries are encrypted with AES-128-CBC (via Fernet, which wraps
  AES-128-CBC + HMAC-SHA256 for authenticated encryption).
- Each vault file contains: master hash, salt, and encrypted entries.
"""

import os
import json
import base64
import hashlib
import secrets
import string
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

VAULT_FILE = Path("vault.dat")
ITERATIONS = 390_000   # OWASP recommended minimum for PBKDF2-SHA256


#Key derivation

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte encryption key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def hash_master_password(master_password: str, salt: bytes) -> str:
    """
    Hash the master password for verification storage.
    Uses PBKDF2-HMAC-SHA256 with a separate salt so the stored hash
    cannot be used directly as the encryption key.
    """
    verify_salt = hashlib.sha256(salt + b"verify").digest()
    dk = hashlib.pbkdf2_hmac("sha256", master_password.encode(), verify_salt, ITERATIONS)
    return dk.hex()


#Vault file I/O

class Vault:
    """Manages encrypted storage of password entries."""

    def __init__(self):
        self._fernet = None
        self._entries: list[dict] = []
        self._master_hash: str = ""
        self._salt: bytes = b""

    #Setup and login

    def create(self, master_password: str):
        """Initialise a brand-new vault with a master password."""
        self._salt = os.urandom(16)
        self._master_hash = hash_master_password(master_password, self._salt)
        key = derive_key(master_password, self._salt)
        self._fernet = Fernet(key)
        self._entries = []
        self._save()

    def load(self, master_password: str) -> bool:
        """Load and decrypt the vault. Returns True on success, False on wrong password."""
        if not VAULT_FILE.exists():
            return False
        with open(VAULT_FILE, "r") as f:
            data = json.load(f)

        self._salt = bytes.fromhex(data["salt"])
        self._master_hash = data["master_hash"]

        # Verify master password
        if hash_master_password(master_password, self._salt) != self._master_hash:
            return False

        key = derive_key(master_password, self._salt)
        self._fernet = Fernet(key)

        # Decrypt entries
        try:
            raw = self._fernet.decrypt(data["entries"].encode())
            self._entries = json.loads(raw.decode())
        except InvalidToken:
            return False

        return True

    def vault_exists(self) -> bool:
        return VAULT_FILE.exists()

    #CRUD operations

    def add_entry(self, site: str, username: str, password: str, notes: str = "") -> bool:
        """Add a new entry. Returns False if site already exists."""
        if self._find(site) is not None:
            return False
        self._entries.append({
            "site": site,
            "username": username,
            "password": password,
            "notes": notes
        })
        self._save()
        return True

    def get_entry(self, site: str) -> dict | None:
        """Retrieve an entry by site name (case-insensitive)."""
        return self._find(site)

    def update_entry(self, site: str, username: str = None, password: str = None, notes: str = None) -> bool:
        """Update fields of an existing entry."""
        entry = self._find(site)
        if entry is None:
            return False
        if username is not None:
            entry["username"] = username
        if password is not None:
            entry["password"] = password
        if notes is not None:
            entry["notes"] = notes
        self._save()
        return True

    def delete_entry(self, site: str) -> bool:
        """Delete an entry by site name."""
        idx = self._find_index(site)
        if idx is None:
            return False
        self._entries.pop(idx)
        self._save()
        return True

    def list_sites(self) -> list[str]:
        """Return all site names sorted alphabetically."""
        return sorted(e["site"] for e in self._entries)

    def search(self, query: str) -> list[dict]:
        """Case-insensitive search across site name, username, and notes."""
        q = query.lower()
        return [e for e in self._entries
                if q in e["site"].lower()
                or q in e["username"].lower()
                or q in e.get("notes", "").lower()]

    #Internal helpers

    def _find(self, site: str) -> dict | None:
        for e in self._entries:
            if e["site"].lower() == site.lower():
                return e
        return None

    def _find_index(self, site: str) -> int | None:
        for i, e in enumerate(self._entries):
            if e["site"].lower() == site.lower():
                return i
        return None

    def _save(self):
        """Encrypt entries and write vault to disk."""
        encrypted = self._fernet.encrypt(json.dumps(self._entries).encode()).decode()
        data = {
            "salt": self._salt.hex(),
            "master_hash": self._master_hash,
            "entries": encrypted
        }
        with open(VAULT_FILE, "w") as f:
            json.dump(data, f)


#Password generator

def generate_password(length: int = 16, use_symbols: bool = True) -> str:
    """
    Generate a cryptographically secure random password.
    Uses secrets.choice (backed by os.urandom) — not random.choice.
    Guarantees at least one uppercase, lowercase, digit, and symbol.
    """
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    # Guarantee character class coverage
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    if use_symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"))

    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    combined = required + rest

    # Shuffle so required chars aren't always at the start
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)


def check_password_strength(password: str) -> tuple[str, list[str]]:
    """
    Evaluate password strength. Returns (rating, list_of_suggestions).
    Ratings: Weak / Fair / Strong / Very Strong
    A password can only be Strong or Very Strong if it meets ALL character class requirements.
    """
    suggestions = []

    has_upper   = any(c.isupper() for c in password)
    has_lower   = any(c.islower() for c in password)
    has_digit   = any(c.isdigit() for c in password)
    has_symbol  = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)
    long_enough = len(password) >= 8
    very_long   = len(password) >= 16

    if not long_enough:
        suggestions.append("Use at least 8 characters")
    if not has_upper:
        suggestions.append("Add uppercase letters (A-Z)")
    if not has_lower:
        suggestions.append("Add lowercase letters (a-z)")
    if not has_digit:
        suggestions.append("Add numbers (0-9)")
    if not has_symbol:
        suggestions.append("Add symbols (!@#$%^&*...)")

    all_classes = has_upper and has_lower and has_digit and has_symbol

    if not long_enough or not all_classes:
        # Missing fundamentals — Weak or Fair only
        missing = len(suggestions)
        rating = "Weak" if missing >= 3 else "Fair"
    else:
        # Meets all character classes and minimum length
        rating = "Very Strong" if very_long else "Strong"

    return rating, suggestions
