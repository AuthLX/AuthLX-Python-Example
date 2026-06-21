"""
AuthLX Python SDK – Integration Method 2
==========================================
**Method 2: Your code is defined ABOVE the login call, then invoked after.**

This pattern is useful when your application functions are defined before the
``api`` instance exists (e.g. at module scope).  Your functions receive the
``authlxapp`` object as a parameter so they can access user data.

⚠  Security Warning
-------------------
Method 2 is slightly weaker than Method 1.  In Python, it is theoretically
possible to call your functions directly (before ``login()`` succeeds) via
code injection or monkey-patching.  If you use Method 2, make sure to call
``authlxapp.check()`` at the start of every protected function to verify the
session is still valid.  A completed ``check()`` call is already shown in the
example below.

Usage
-----
1.  pip install requests
2.  Set APP_ID, APP_NAME, and APP_VERSION below.
3.  Define your application functions above ``main()`` (see the example).
4.  Call your functions AFTER a successful ``login()`` (see ``main()``).
5.  python method2.py
"""

import os
import sys
import time
import hmac
import hashlib
import logging
import platform
import subprocess
import threading
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AuthLX: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AuthLX")

try:
    if os.name == "nt":
        import win32security  # type: ignore
    import requests
except ModuleNotFoundError:
    print("AuthLX: Required modules not found. Installing...")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == "nt":
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("AuthLX: Modules installed. Please re-run the application.")
    time.sleep(1.5)
    os._exit(1)


# ============================================================
#  AuthLX SDK
# ============================================================

class api:
    class user_data_class:
        def __init__(self):
            self.username: str = ""
            self.hwid: str = ""
            self.expires: str = ""
            self.createdate: str = ""
            self.lastlogin: str = ""
            self.subscription: str = ""
            self.subscriptions: list = []
            self.is_authenticated: bool = False
            self.auth_runtime_start: float = 0.0

    def __init__(self, name, ownerid, version, hash_to_check=None, api_url=None):
        self.name = name
        self.ownerid = ownerid
        self.version = version
        self.hash_to_check = hash_to_check if hash_to_check is not None else others.get_checksum()
        self.api_url = api_url or "https://authlx.com/api/v1/client"
        self._session = requests.Session()
        self._session.trust_env = False
        self.session_token: str = ""
        self.initialized: bool = False
        self.user_data = self.user_data_class()
        self._login_fails: int = 0
        self._lockout_end: float = 0.0
        self._debug: bool = False
        self._allowed_hosts: list = []
        self._pinned_public_keys: list = []
        self._secure_strings_enabled: bool = False
        self._secure_key: bytes = None
        self._ban_monitor_thread: threading.Thread = None
        self._ban_monitor_active: bool = False
        self.init()

    def init(self):
        others.anti_debug()
        response = self._do_request("/init", {"app_id": self.ownerid})
        if response and response.get("status") == "success":
            app_info = response.get("app_info", {})
            server_version = app_info.get("version", self.version)
            if server_version != self.version:
                logger.critical(f"\n[UPDATE REQUIRED] Current: {self.version} | Required: {server_version}")
                auto_update = app_info.get("auto_update_link")
                if auto_update:
                    logger.critical(f"[DOWNLOAD] {auto_update}")
                time.sleep(5)
                os._exit(1)
            self.initialized = True
        else:
            logger.error("Initialisation failed. Check your ownerid and network.")
            os._exit(1)

    def register(self, user, email, password, license_key, hwid=None):
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()
        response = self._do_request("/register", {
            "app_id": self.ownerid, "username": user, "email": email,
            "password": password, "license_key": license_key, "hwid": hwid,
        })
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Successfully registered!"))
            return True
        logger.error(f"Registration Failed: {response.get('message', '') if response else 'No response.'}")
        return False

    def login(self, user, password, hwid=None):
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()
        response = self._do_request("/login", {
            "app_id": self.ownerid, "username": user, "password": password,
            "hwid": hwid, "hash": self.hash_to_check, "version": self.version,
        })
        if response and response.get("status") == "success":
            data = response.get("data", {})
            self.session_token = data.get("token", "")
            self._load_user_data(data.get("user", {}))
            logger.info("Successfully logged in!")
            return True
        msg = response.get("message", "Login failed.") if response else "No response."
        logger.error(f"Login Failed: {msg}")
        if "Hardware ID mismatch" in msg:
            logger.critical("\n[USER ERROR] HWID changed. User needs an HWID reset.\n")
        return False

    def web_login(self, user, password):
        self._checkinit()
        if self.lockout_active():
            logger.error(f"Locked out. Try again in {self.lockout_remaining_ms() // 1000}s.")
            return False
        response = self._do_request("/web-login", {
            "app_id": self.ownerid, "username": user, "password": password,
        })
        if response and response.get("status") == "success":
            self._load_user_data(response.get("data", {}).get("user", {}))
            self.reset_lockout()
            self.mark_authenticated()
            logger.info("Successfully logged in (Web)!")
            return True
        self.record_login_fail()
        self.bad_input_delay()
        logger.error(f"Web Login Failed: {response.get('message', '') if response else 'No response.'}")
        return False

    def logout(self):
        self._checkinit()
        if not self.session_token:
            logger.error("Not logged in.")
            return False
        response = self._do_request("/logout", {
            "app_id": self.ownerid, "session_token": self.session_token,
        })
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Logged out."))
            self.session_token = ""
            return True
        return False

    def upgrade(self, user, license_key):
        self._checkinit()
        response = self._do_request("/upgrade", {
            "app_id": self.ownerid, "username": user, "license_key": license_key,
        })
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Upgraded!"))
            return True
        logger.error(f"Upgrade Failed: {response.get('message', '') if response else 'No response.'}")
        return False

    def changeUsername(self, new_username):
        self._checkinit()
        if not self.session_token:
            logger.error("Must be logged in.")
            return False
        response = self._do_request("/change-username", {
            "app_id": self.ownerid, "current_username": self.user_data.username,
            "new_username": new_username,
        })
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Username changed!"))
            self.user_data.username = new_username
            return True
        logger.error(f"Change Username Failed: {response.get('message', '') if response else 'No response.'}")
        return False

    def forgot(self, user, new_password, hwid=None):
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()
        response = self._do_request("/forgot", {
            "app_id": self.ownerid, "username": user,
            "hwid": hwid, "new_password": new_password,
        })
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Password reset!"))
            return True
        logger.error(f"Password Reset Failed: {response.get('message', '') if response else 'No response.'}")
        return False

    def check(self):
        self._checkinit()
        if not self.session_token:
            return False
        response = self._do_request("/verify-session", {
            "app_id": self.ownerid, "token": self.session_token,
        })
        return bool(response and response.get("status") == "success")

    def verify_token(self, standalone_token):
        self._checkinit()
        response = self._do_request("/verify-token", {
            "app_id": self.ownerid, "token": standalone_token,
        })
        if response and response.get("status") == "success":
            logger.info("Token is valid!")
            return True
        logger.error(response.get("message", "Invalid token.") if response else "No response.")
        return False

    def has_active_subscription(self):
        return self.expiry_remaining() > 0

    def expiry_remaining(self):
        if not self.user_data.expires:
            return 0
        from datetime import datetime
        try:
            expire_dt = datetime.fromisoformat(self.user_data.expires.replace("Z", "+00:00"))
            return max(0.0, (expire_dt - datetime.now(expire_dt.tzinfo)).total_seconds())
        except Exception:
            return 0

    def mark_authenticated(self):
        self.user_data.is_authenticated = True
        self.refresh_auth_runtime()

    def refresh_auth_runtime(self):
        self.user_data.auth_runtime_start = time.time()

    def reset_auth_runtime(self):
        self.refresh_auth_runtime()

    def set_allowed_hosts(self, hosts):
        self._allowed_hosts = list(hosts)

    def add_allowed_host(self, host):
        if host not in self._allowed_hosts:
            self._allowed_hosts.append(host)

    def clear_allowed_hosts(self):
        self._allowed_hosts = []

    def set_pinned_public_keys(self, keys):
        self._pinned_public_keys = list(keys)

    def add_pinned_public_key(self, key):
        if key not in self._pinned_public_keys:
            self._pinned_public_keys.append(key)

    def clear_pinned_public_keys(self):
        self._pinned_public_keys = []

    def enable_secure_strings(self):
        self._secure_strings_enabled = True

    def derive_secure_key(self, material):
        self._secure_key = hashlib.sha256(material.encode()).digest()

    def xor_crypt_field(self, data, key):
        key_cycle = key * (len(data) // len(key) + 1)
        return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key_cycle))

    def compute_auth_seal(self, payload):
        if not self._secure_key:
            return None
        return hmac.new(self._secure_key, payload.encode(), hashlib.sha256).hexdigest()

    def req(self, url, method="GET", **kwargs):
        if self._allowed_hosts:
            domain = urlparse(url).hostname
            if domain not in self._allowed_hosts:
                logger.critical(f"Security violation: blocked unauthorized host: {domain}")
                time.sleep(self.close_delay() / 1000)
                os._exit(1)
        try:
            res = self._session.get(url, **kwargs) if method.upper() == "GET" \
                else self._session.post(url, **kwargs)
            if self._pinned_public_keys:
                self._verify_pinned_key(url)
            return res
        except Exception as e:
            logger.error(f"req() failed: {e}")
            return None

    def start_ban_monitor(self, interval_seconds=60):
        if self._ban_monitor_active:
            return
        self._ban_monitor_active = True
        self._ban_monitor_thread = threading.Thread(
            target=self._ban_monitor_loop, args=(interval_seconds,),
            daemon=True, name="authlx-ban-monitor",
        )
        self._ban_monitor_thread.start()

    def stop_ban_monitor(self):
        self._ban_monitor_active = False

    def ban_monitor_running(self):
        return (self._ban_monitor_active and self._ban_monitor_thread is not None
                and self._ban_monitor_thread.is_alive())

    def record_login_fail(self):
        self._login_fails += 1
        if self._login_fails >= 3:
            self._lockout_end = time.time() + 300

    def lockout_active(self):
        if time.time() < self._lockout_end:
            return True
        if self._lockout_end > 0 and time.time() >= self._lockout_end:
            self.reset_lockout()
        return False

    def lockout_remaining_ms(self):
        if not self.lockout_active():
            return 0
        return max(0, int((self._lockout_end - time.time()) * 1000))

    def reset_lockout(self):
        self._login_fails = 0
        self._lockout_end = 0.0

    def init_fail_delay(self):
        time.sleep(3)
        return 3000

    def bad_input_delay(self):
        time.sleep(2)
        return 2000

    def close_delay(self):
        return 3000

    def setDebug(self, enable):
        self._debug = enable

    def debugInfo(self):
        return {"debug_enabled": self._debug, "lockout_active": self.lockout_active(),
                "login_fails": self._login_fails, "session": self.session_token}

    def _checkinit(self):
        if not self.initialized:
            logger.warning("SDK not initialised.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _do_request(self, endpoint, post_data):
        try:
            target_url = f"{self.api_url}{endpoint}"
            if self._allowed_hosts:
                domain = urlparse(target_url).hostname
                if domain not in self._allowed_hosts:
                    logger.critical(f"Security violation: blocked unauthorized host: {domain}")
                    time.sleep(self.close_delay() / 1000)
                    os._exit(1)
            headers = {"User-Agent": f"AuthLX-ClientSDK/1.0 ({self.name} v{self.version})",
                       "Content-Type": "application/json"}
            response = self._session.post(target_url, json=post_data, headers=headers,
                                          timeout=10, verify=True)
            if self._pinned_public_keys:
                self._verify_pinned_key(target_url)
            try:
                return response.json()
            except ValueError:
                logger.error(f"Invalid JSON (HTTP {response.status_code}).")
                time.sleep(self.close_delay() / 1000)
                os._exit(1)
        except requests.exceptions.Timeout:
            logger.error("Request timed out.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)
        except requests.exceptions.ConnectionError:
            logger.error("Connection error.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _load_user_data(self, data):
        self.user_data.username = data.get("username", "")
        self.user_data.hwid = data.get("hwid", "N/A")
        self.user_data.createdate = data.get("created_at", "")
        self.user_data.lastlogin = data.get("last_login_at", "")
        subscriptions = data.get("subscriptions", [])
        self.user_data.subscriptions = subscriptions
        if subscriptions:
            self.user_data.expires = subscriptions[0].get("expiry", "")
            self.user_data.subscription = subscriptions[0].get("subscription", "")
        else:
            self.user_data.expires = ""
            self.user_data.subscription = ""

    def _verify_pinned_key(self, url):
        if self._debug:
            logger.debug(f"[PIN] Key check for {url}")

    def _ban_monitor_loop(self, interval):
        while self._ban_monitor_active:
            time.sleep(interval)
            if not self.session_token:
                continue
            if not self.check():
                self._ban_monitor_detected()

    def _ban_monitor_detected(self):
        logger.critical("\n[SECURITY] Session revoked or account banned. Terminating.")
        time.sleep(1)
        os._exit(1)


class others:
    @staticmethod
    def get_checksum():
        try:
            with open(sys.argv[0], "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "UNKNOWN_HASH"

    @staticmethod
    def anti_debug():
        if sys.gettrace() is not None:
            logger.critical("Security violation: Debugger detected. Exiting.")
            os._exit(1)

    @staticmethod
    def get_hwid():
        system = platform.system()
        if system == "Linux":
            try:
                with open("/etc/machine-id") as f:
                    return f.read().strip()
            except Exception:
                return "Unknown-Linux-HWID"
        if system == "Windows":
            try:
                sid = win32security.LookupAccountName(None, os.getlogin())[0]
                return win32security.ConvertSidToStringSid(sid)
            except Exception:
                return "Unknown-Windows-HWID"
        if system == "Darwin":
            try:
                raw = subprocess.Popen(
                    "ioreg -l | grep IOPlatformSerialNumber",
                    stdout=subprocess.PIPE, shell=True,
                ).communicate()[0]
                return raw.decode().split("=", 1)[1].replace(" ", "")[1:-2]
            except Exception:
                return "Unknown-Mac-HWID"
        return "Unknown-HWID"


# ============================================================
#  ★  METHOD 2: Your application functions are defined ABOVE
#     main() and called AFTER login succeeds.
#
#  ⚠  Always call authlxapp.check() at the start of each
#     protected function to verify the session is still valid.
# ============================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
APP_NAME    = "MyApp"
APP_ID      = "YOUR-APP-UUID-HERE"
APP_VERSION = "1.0"


# ---------- YOUR FUNCTIONS GO HERE ----------

def protected_feature_1(authlxapp: api):
    """
    Example protected function.
    The check() at the top ensures the session is still valid even if this
    function were somehow called without going through login().
    """
    # Always verify the session first in Method 2.
    if not authlxapp.check():
        print("  ✗ Session invalid. Aborting.")
        return

    print(f"\n  Running protected_feature_1 for {authlxapp.user_data.username}!")
    # ... your logic here ...


def protected_feature_2(authlxapp: api):
    """Another example protected function."""
    if not authlxapp.check():
        print("  ✗ Session invalid. Aborting.")
        return

    sub = authlxapp.user_data.subscription
    if sub == "Enterprise":
        print("  ✓ Enterprise feature unlocked!")
    else:
        print(f"  ✗ Enterprise required. Your plan: {sub or 'N/A'}")

# --------------------------------------------


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print("Initialising AuthLX security modules…")

    authlxapp = api(
        name=APP_NAME,
        ownerid=APP_ID,
        version=APP_VERSION,
        hash_to_check=others.get_checksum(),
    )

    print("✓ Initialised.\n")

    while True:
        print("=" * 50)
        print(f"  {APP_NAME}  –  Powered by AuthLX")
        print("=" * 50)
        print("\n  [1] Login")
        print("  [2] Register with License Key")
        print("  [0] Exit")
        choice = input("\n  › ").strip()

        if choice == "1":
            user     = input("  Username : ").strip()
            password = input("  Password : ").strip()

            # ─── LOGIN GATE ───────────────────────────────────────────────
            if authlxapp.login(user, password):
                print(f"\n  ✓ Welcome, {authlxapp.user_data.username}!")

                # Call your functions AFTER login succeeds.
                # Each function re-verifies the session via check().
                protected_feature_1(authlxapp)
                protected_feature_2(authlxapp)

                input("\n  Press Enter to logout…")
                authlxapp.logout()
            # ─────────────────────────────────────────────────────────────
            else:
                print("  ✗ Login failed.")

        elif choice == "2":
            user     = input("  Username    : ").strip()
            email    = input("  Email       : ").strip()
            password = input("  Password    : ").strip()
            key      = input("  License Key : ").strip()
            if authlxapp.register(user, email, password, key):
                print("  ✓ Registered! You can now log in.")
            else:
                print("  ✗ Registration failed.")

        elif choice == "0":
            print("\nGoodbye.")
            break
        else:
            print("  Invalid option.")

        input("\n  Press Enter to continue…")
        os.system("cls" if os.name == "nt" else "clear")


if __name__ == "__main__":
    main()
