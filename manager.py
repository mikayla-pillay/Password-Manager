"""
Password Manager - Mikayla Pillay
A CLI password manager with AES encryption, PBKDF2 key derivation,
secure password generation, and strength checking.
"""

import getpass
import sys
from vault import Vault, generate_password, check_password_strength

# Optional clipboard support
try:
    import pyperclip
    CLIPBOARD = True
except ImportError:
    CLIPBOARD = False

vault = Vault()

# UI helpers

def header():
    print("\n  SECURE PASSWORD MANAGER\n")

def menu():
    print("""
  [1] Add entry
  [2] Get entry
  [3] Update entry
  [4] Delete entry
  [5] List all sites
  [6] Search
  [7] Generate password
  [8] Check password strength
  [0] Lock & exit
""")

def prompt(label, secret=False):
    if secret:
        return getpass.getpass(f"  {label}: ")
    return input(f"  {label}: ").strip()

def success(msg): print(f"\n  [OK]  {msg}")
def error(msg):   print(f"\n  [ERR] {msg}")
def info(msg):    print(f"\n  [i]   {msg}")

def copy_to_clipboard(text, label="Password"):
    if CLIPBOARD:
        pyperclip.copy(text)
        info(f"{label} copied to clipboard.")

def print_entry(entry, show_password=False):
    pw = entry['password'] if show_password else '*' * len(entry['password'])
    print(f"""
  Site     : {entry['site']}
  Username : {entry['username']}
  Password : {pw}
  Notes    : {entry.get('notes', '') or '-'}""")

#Auth flow

def setup_vault():
    print("\n  No vault found. Let's create one.")
    print("  Choose a strong master password.\n")
    while True:
        pw = prompt("Master password", secret=True)
        rating, suggestions = check_password_strength(pw)
        print(f"\n  Strength: {rating}")
        if suggestions:
            for s in suggestions:
                print(f"    - {s}")
        if rating in ("Weak", "Fair"):
            choice = input("\n(r)etry or (u)se anyway? ").strip().lower()
            if choice != "u":
                print()
                continue
        confirm = prompt("\n  Confirm master password", secret=True)
        if pw != confirm:
            error("Passwords do not match. Try again.")
            print()
            continue
        vault.create(pw)
        success("Vault created!")
        return

def login():
    print("\n  Enter your master password to unlock the vault.")
    for attempt in range(3):
        pw = prompt("Master password", secret=True)
        if vault.load(pw):
            success("Vault unlocked.")
            return True
        remaining = 2 - attempt
        error(f"Wrong password. {remaining} attempt(s) remaining.")
    error("Too many failed attempts.")
    return False

#Actions

def action_add():
    print("\n  -- Add Entry --")
    site = prompt("Site / App name")
    username = prompt("Username / Email")
    if input("\n  Generate a password? (y/n): ").strip().lower() == "y":
        length_input = input("  Length (default 16): ").strip()
        length = int(length_input) if length_input.isdigit() else 16
        use_symbols = input("  Include symbols? (y/n, default y): ").strip().lower() != "n"
        password = generate_password(length, use_symbols)
        rating, _ = check_password_strength(password)
        print(f"\n  Generated: {password}  [{rating}]")
        copy_to_clipboard(password)
    else:
        password = prompt("Password", secret=True)
        rating, suggestions = check_password_strength(password)
        print(f"\n  Strength: {rating}")
        for s in suggestions:
            print(f"    - {s}")
    notes = prompt("Notes (optional)")
    if vault.add_entry(site, username, password, notes):
        success(f"Entry for '{site}' saved.")
    else:
        error(f"Entry for '{site}' already exists. Use Update.")

def action_get():
    print("\n  -- Get Entry --")
    site = prompt("Site / App name")
    entry = vault.get_entry(site)
    if not entry:
        error(f"No entry for '{site}'.")
        return
    print_entry(entry)
    if input("\n  Reveal password? (y/n): ").strip().lower() == "y":
        print(f"\n  Password : {entry['password']}")
        copy_to_clipboard(entry["password"])

def action_update():
    print("\n  -- Update Entry --")
    site = prompt("Site / App name")
    if not vault.get_entry(site):
        error(f"No entry for '{site}'.")
        return
    print("  Leave blank to keep current value.\n")
    username = prompt("New username") or None
    notes = prompt("New notes") or None
    if input("\n  Generate a new password? (y/n): ").strip().lower() == "y":
        password = generate_password()
        print(f"\n  Generated: {password}")
        copy_to_clipboard(password)
    else:
        password = prompt("New password (blank = keep)", secret=True) or None
    vault.update_entry(site, username=username, password=password, notes=notes)
    success(f"Entry for '{site}' updated.")

def action_delete():
    print("\n  -- Delete Entry --")
    site = prompt("Site / App name")
    if input(f"\n  Delete '{site}'? Cannot be undone. (y/n): ").strip().lower() == "y":
        if vault.delete_entry(site):
            success(f"'{site}' deleted.")
        else:
            error(f"No entry for '{site}'.")

def action_list():
    sites = vault.list_sites()
    if not sites:
        info("Vault is empty.")
        return
    print(f"\n  Saved sites ({len(sites)}):\n")
    for s in sites:
        print(f"    - {s}")

def action_search():
    print("\n  -- Search --")
    query = prompt("Search term")
    results = vault.search(query)
    if not results:
        info("No matches found.")
        return
    print(f"\n  {len(results)} result(s):\n")
    for entry in results:
        print_entry(entry)

def action_generate():
    print("\n  -- Generate Password --")
    length_input = input("  Length (default 16): ").strip()
    length = int(length_input) if length_input.isdigit() else 16
    use_symbols = input("  Include symbols? (y/n, default y): ").strip().lower() != "n"
    password = generate_password(length, use_symbols)
    rating, _ = check_password_strength(password)
    print(f"\n  Generated : {password}\n  Strength  : {rating}")
    copy_to_clipboard(password)

def action_strength():
    print("\n  -- Check Password Strength --")
    password = prompt("Password to check", secret=True)
    rating, suggestions = check_password_strength(password)
    print(f"\n  Strength: {rating}")
    if suggestions:
        for s in suggestions:
            print(f"    - {s}")
    else:
        print("  No suggestions — looks strong!")

#Main loop

def main():
    header()
    if not vault.vault_exists():
        setup_vault()
    else:
        if not login():
            sys.exit(1)

    actions = {
        "1": action_add, "2": action_get, "3": action_update,
        "4": action_delete, "5": action_list, "6": action_search,
        "7": action_generate, "8": action_strength,
    }

    while True:
        menu()
        choice = input("  Choice: ").strip()
        if choice == "0":
            print("\n  Vault locked. Goodbye.\n")
            sys.exit(0)
        elif choice in actions:
            try:
                actions[choice]()
            except KeyboardInterrupt:
                print("\n  Cancelled.")
        else:
            error("Invalid choice.")

if __name__ == "__main__":
    main()
