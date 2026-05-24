# Password-Manager
A command-line password manager that stores credentials in an encrypted vault. Built with real cryptographic security - the master password is never stored anywhere, and all vault data is encrypted using AES authenticated encryption.

What it does:

Creates and unlocks an encrypted vault protected by a master password
Stores, retrieves, updates, and deletes password entries
Generates cryptographically secure passwords using Python's secrets module
Analyses password strength with actionable suggestions
Locks the vault after 3 failed login attempts

Security design:
Master password: Never stored - verified via PBKDF2-SHA256 hash
Encryption: keyDerived from master password using PBKDF2-HMAC-SHA256 (390,000 iterations)
Vault encryption: AES-128-CBC + HMAC-SHA256 (Fernet authenticated encryption)
Password generation: secrets.choice() - cryptographically secure, backed by os.urandom

Technologies: Python 3, cryptography library (Fernet), secrets, hashlib, getpass

How to run:
pip install cryptography
python manager.py

What I learned: Symmetric encryption, key derivation functions, authenticated encryption, secure random generation, and the difference between hashing and encryption.
