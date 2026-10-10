import base64
import getpass
import hashlib
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


# Configuration

VAULT_FILE = Path(__file__).resolve().parent / "passwords.vault"

MAGIC = b"PY_PASSWORD_MANAGER_V1"
SALT_SIZE = 16

# PBKDF2 work factor.
# Increase this over time as hardware gets faster.
PBKDF2_ITERATIONS = 600_000



# UI

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def header():
    print(r"""
╔══════════════════════════════════════════════════════╗
║                       PASSCODER                      ║
║                    Secure CLI Vault                  ║
╠══════════════════════════════════════════════════════╣
║  add       Add a password                            ║
║  list      List all saved passwords                  ║
║  search    Search by platform or username            ║
║  delete    Delete a password                         ║
║  help      Show commands                             ║
║  exit      Exit the password manager                 ║
╚══════════════════════════════════════════════════════╝ by zxxn212
""")


def print_help():
    print("""
Commands:

    add
        Add a new password.

    list
        Display all saved accounts.

    search <query>
        Search platforms and usernames.

    delete <number>
        Delete an entry by its displayed number.

    help
        Show this help menu.

    exit
        Exit the password manager.
""")


# Key derivation

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte encryption key from the master password.
    Fernet expects the key to be URL-safe base64 encoded.
    """

    key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )

    return base64.urlsafe_b64encode(key)



# Vault format

def create_empty_vault(master_password: str):
    """
    Create a new encrypted vault.
    """

    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    cipher = Fernet(key)

    plaintext = b""

    encrypted = cipher.encrypt(plaintext)

    with open(VAULT_FILE, "wb") as f:
        f.write(MAGIC + b"\n")
        f.write(base64.b64encode(salt) + b"\n")
        f.write(encrypted + b"\n")


def read_vault(master_password: str):
    """
    Decrypt the vault and return a list of entries.

    Each entry is:

        {
            "platform": "...",
            "user": "...",
            "password": "..."
        }
    """

    if not VAULT_FILE.exists():
        return None

    try:
        with open(VAULT_FILE, "rb") as f:
            magic = f.readline().strip()
            salt = base64.b64decode(f.readline().strip())
            encrypted = f.readline().strip()

        if magic != MAGIC:
            raise ValueError("Invalid vault format.")

        key = derive_key(master_password, salt)
        cipher = Fernet(key)

        plaintext = cipher.decrypt(encrypted)

        entries = []

        if plaintext:
            for line in plaintext.decode("utf-8").splitlines():
                parts = line.split("\t", 2)

                if len(parts) != 3:
                    continue

                platform, username, password = parts

                entries.append({
                    "platform": platform,
                    "user": username,
                    "password": password,
                })

        return entries

    except (InvalidToken, ValueError, UnicodeDecodeError):
        return False


def save_vault(master_password: str, entries):
    """
    Encrypt the entire database and save it to disk.
    """

    if VAULT_FILE.exists():

        with open(VAULT_FILE, "rb") as f:
            magic = f.readline().strip()
            salt = base64.b64decode(f.readline().strip())

        if magic != MAGIC:
            raise ValueError("Invalid vault.")

    else:
        salt = os.urandom(SALT_SIZE)

    key = derive_key(master_password, salt)
    cipher = Fernet(key)

    lines = []

    for entry in entries:

        platform = entry["platform"]
        username = entry["user"]
        password = entry["password"]

        # Tab-separated internally so spaces are allowed
        # in usernames/passwords.
        lines.append(
            f"{platform}\t{username}\t{password}"
        )

    plaintext = "\n".join(lines).encode("utf-8")

    encrypted = cipher.encrypt(plaintext)

    temp_file = VAULT_FILE.with_suffix(".tmp")

    with open(temp_file, "wb") as f:
        f.write(MAGIC + b"\n")
        f.write(base64.b64encode(salt) + b"\n")
        f.write(encrypted + b"\n")

    # Replace the old vault only after successful encryption.
    os.replace(temp_file, VAULT_FILE)


# Password operations

def add_password(entries):
    print("\n--- Add Password ---")

    platform = input("Platform: ").strip()
    username = input("Username: ").strip()

    password = getpass.getpass("Password: ")

    if not platform or not username:
        print("Platform and username cannot be empty.")
        return

    entries.append({
        "platform": platform,
        "user": username,
        "password": password,
    })

    print("\nPassword added.")


def display_entries(entries, show_password=True):

    if not entries:
        print("\nNo passwords stored.")
        return

    print()

    for i, entry in enumerate(entries, start=1):

        print(f"[{i}]")
        print(f"    Platform : {entry['platform']}")
        print(f"    User     : {entry['user']}")

        if show_password:
            print(f"    Password : {entry['password']}")

        print()


def search_entries(entries, query):

    query = query.lower()

    results = []

    for entry in entries:

        if (
            query in entry["platform"].lower()
            or query in entry["user"].lower()
        ):
            results.append(entry)

    return results


def delete_password(entries, number):

    try:
        index = int(number) - 1
    except ValueError:
        print("Invalid entry number.")
        return

    if index < 0 or index >= len(entries):
        print("Entry does not exist.")
        return

    entry = entries[index]

    print("\nSelected:")
    print(f"Platform : {entry['platform']}")
    print(f"User     : {entry['user']}")

    confirmation = input("\nDelete this entry? [y/N]: ")

    if confirmation.lower() == "y":
        entries.pop(index)
        print("Entry deleted.")
    else:
        print("Cancelled.")



# Vault initialization

def setup_vault():

    print("\nNo password vault was found.")
    print("Let's create one.\n")

    while True:

        password = getpass.getpass("Create master password: ")

        if not password:
            print("Master password cannot be empty.")
            continue

        confirmation = getpass.getpass(
            "Confirm master password: "
        )

        if password != confirmation:
            print("Passwords do not match.\n")
            continue

        break

    create_empty_vault(password)

    print("\nVault created successfully.")

    return password


def unlock_vault():

    if not VAULT_FILE.exists():
        return setup_vault()

    print("\nPassword vault found.")

    master_password = getpass.getpass(
        "Master password: "
    )

    entries = read_vault(master_password)

    if entries is False:
        print("\nIncorrect master password or corrupted vault.")
        sys.exit(1)

    print("\nVault unlocked.")

    return master_password



# Main CLI

def main():

    clear_screen()
    header()

    master_password = unlock_vault()

    entries = read_vault(master_password)

    if entries is False:
        print("Could not decrypt vault.")
        sys.exit(1)

    print_help()

    while True:

        try:
            command = input("vault> ").strip()

        except KeyboardInterrupt:
            print("\nExiting.")
            break

        if not command:
            continue

        parts = command.split(maxsplit=1)
        action = parts[0].lower()

        
        # ADD
        
        if action == "add":

            add_password(entries)

            save_vault(
                master_password,
                entries
            )

            print("Vault encrypted and saved.")

        
        # LIST

        elif action == "list":

            display_entries(entries)

        
        # SEARCH

        elif action == "search":

            if len(parts) != 2:
                print("Usage: search <platform or username>")
                continue

            query = parts[1]

            results = search_entries(
                entries,
                query
            )

            if results:
                display_entries(results)
            else:
                print("No matching entries.")

        
        # DELETE

        elif action == "delete":

            if len(parts) != 2:
                print("Usage: delete <entry number>")
                continue

            delete_password(
                entries,
                parts[1]
            )

            save_vault(
                master_password,
                entries
            )

            print("Vault encrypted and saved.")

        
        # HELP

        elif action == "help":

            print_help()

        
        # EXIT
        
        elif action in ("exit", "quit"):

            print("\nGoodbye.")
            break

        else:

            print(
                f"Unknown command: {action}. "
                "Type 'help' for commands."
            )


if __name__ == "__main__":
    main()
