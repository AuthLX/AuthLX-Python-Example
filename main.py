"""
AuthLX Python SDK – Example Application
========================================
Demonstrates every major SDK feature in an interactive console application.

Quick Start
-----------
1.  pip install -r requirements.txt
2.  Set YOUR_APP_ID below to the UUID from your AuthLX Dashboard.
3.  python main.py

Docs / Source: https://github.com/AuthLX/AuthLX-Python-Example
"""

import os
import time
from authlx import api, others

# ---------------------------------------------------------------------------
# ★  CONFIGURATION  – fill in your details from the AuthLX Dashboard
# ---------------------------------------------------------------------------
APP_NAME    = "MyApp"
APP_ID      = "YOUR-APP-UUID-HERE"    # ← paste your App UUID here
APP_VERSION = "1.0"

# Use others.get_checksum() to enable server-side integrity verification.
# During development you can pass a plain string to skip the hash check.
APP_HASH = others.get_checksum()
# ---------------------------------------------------------------------------


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner(authlxapp: api):
    clear()
    print("=" * 56)
    print(f"  {APP_NAME}  –  Powered by AuthLX")
    print("=" * 56)
    print(f"  Hardware ID : {others.get_hwid()}")
    print(f"  App hash    : {authlxapp.hash_to_check[:24]}…")
    print("=" * 56)


def menu_main():
    print("\n  MAIN MENU")
    print("  ─────────────────────────────────")
    print("  [1] Login")
    print("  [2] Register with License Key")
    print("  [3] Web Login  (no HWID)")
    print("  [4] Forgot Password  (HWID reset)")
    print("  [5] Verify Standalone API Token")
    print("  [0] Exit")
    return input("\n  › ").strip()


def menu_account(authlxapp: api):
    print(f"\n  Welcome back, {authlxapp.user_data.username}!")
    print(f"  Subscription : {authlxapp.user_data.subscription or 'N/A'}")
    print(f"  Expires      : {authlxapp.user_data.expires or 'N/A'}")
    print(f"  Last login   : {authlxapp.user_data.lastlogin or 'N/A'}")
    remaining = authlxapp.expiry_remaining()
    if remaining > 0:
        days = int(remaining // 86400)
        hours = int((remaining % 86400) // 3600)
        print(f"  Time left    : {days}d {hours}h")
    else:
        print("  Time left    : EXPIRED")

    print("\n  ACCOUNT MENU")
    print("  ─────────────────────────────────")
    print("  [1] Change Username")
    print("  [2] Upgrade Account  (apply another license)")
    print("  [3] Check Session validity")
    print("  [4] Logout")
    print("  [0] Back to main menu")
    return input("\n  › ").strip()


# ---------------------------------------------------------------------------
# Feature flows
# ---------------------------------------------------------------------------

def flow_login(authlxapp: api) -> bool:
    print("\n  ── LOGIN ──")
    user     = input("  Username : ").strip()
    password = input("  Password : ").strip()

    if authlxapp.login(user, password):
        print("\n  ✓ Login successful!")
        authlxapp.mark_authenticated()

        # Optional: start ban monitor (checks every 120 s)
        authlxapp.start_ban_monitor(interval_seconds=120)

        while True:
            choice = menu_account(authlxapp)

            if choice == "1":
                new_name = input("  New username : ").strip()
                if authlxapp.changeUsername(new_name):
                    print(f"  ✓ Username changed to '{new_name}'")
                else:
                    print("  ✗ Username change failed.")

            elif choice == "2":
                key = input("  License Key : ").strip()
                if authlxapp.upgrade(authlxapp.user_data.username, key):
                    print("  ✓ Account upgraded!")
                else:
                    print("  ✗ Upgrade failed.")

            elif choice == "3":
                if authlxapp.check():
                    print("  ✓ Session is valid.")
                else:
                    print("  ✗ Session has expired or been revoked.")

            elif choice == "4":
                authlxapp.stop_ban_monitor()
                authlxapp.logout()
                print("  ✓ Logged out.")
                return True

            elif choice == "0":
                authlxapp.stop_ban_monitor()
                authlxapp.logout()
                return True

    else:
        print("  ✗ Login failed. Check credentials.")
        return False


def flow_register(authlxapp: api):
    print("\n  ── REGISTER ──")
    user    = input("  Username    : ").strip()
    email   = input("  Email       : ").strip()
    password = input("  Password    : ").strip()
    key     = input("  License Key : ").strip()

    if authlxapp.register(user, email, password, key):
        print("  ✓ Registration successful!  You can now log in.")
    else:
        print("  ✗ Registration failed.  Check the license key and try again.")


def flow_web_login(authlxapp: api):
    print("\n  ── WEB LOGIN  (no HWID) ──")
    user     = input("  Username : ").strip()
    password = input("  Password : ").strip()

    if authlxapp.web_login(user, password):
        print(f"\n  ✓ Authenticated as '{authlxapp.user_data.username}'")
        print(f"  Subscription : {authlxapp.user_data.subscription or 'N/A'}")
        print(f"  Expires      : {authlxapp.user_data.expires or 'N/A'}")
    else:
        print("  ✗ Web login failed.")


def flow_forgot(authlxapp: api):
    print("\n  ── FORGOT PASSWORD ──")
    print("  Your HWID will be used to verify your identity.")
    user         = input("  Username     : ").strip()
    new_password = input("  New Password : ").strip()

    hwid = others.get_hwid()
    print(f"  Using HWID   : {hwid}")

    if authlxapp.forgot(user, new_password, hwid=hwid):
        print("  ✓ Password reset!  You can now log in with your new password.")
    else:
        print("  ✗ Password reset failed.  Is your HWID bound to this account?")


def flow_verify_token(authlxapp: api):
    print("\n  ── VERIFY API TOKEN ──")
    token = input("  Token : ").strip()
    if authlxapp.verify_token(token):
        print("  ✓ Token is valid.")
    else:
        print("  ✗ Token is invalid or banned.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("Initialising AuthLX security modules…")

    authlxapp = api(
        name=APP_NAME,
        ownerid=APP_ID,
        version=APP_VERSION,
        hash_to_check=APP_HASH,
    )

    print("✓ Initialised.\n")

    while True:
        banner(authlxapp)
        choice = menu_main()

        if choice == "1":
            flow_login(authlxapp)
        elif choice == "2":
            flow_register(authlxapp)
        elif choice == "3":
            flow_web_login(authlxapp)
        elif choice == "4":
            flow_forgot(authlxapp)
        elif choice == "5":
            flow_verify_token(authlxapp)
        elif choice == "0":
            print("\nGoodbye.")
            break
        else:
            print("  Invalid option.")

        input("\n  Press Enter to continue…")


if __name__ == "__main__":
    main()
