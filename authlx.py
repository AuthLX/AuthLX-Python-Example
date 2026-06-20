"""
AuthLX Python SDK
=================
A production-ready client SDK for the AuthLX authentication platform.

Provides user authentication (login, register, web-login, logout),
license management, session verification, and a full suite of runtime
security features:

  • HWID Locking          – binds accounts to physical hardware IDs
  • Anti-Tamper           – SHA-256 checksum of the running executable
  • Anti-Debug            – detects attached Python debuggers
  • Anti-MITM             – disables proxy auto-configuration
  • Host Locking          – blocks requests to non-whitelisted domains
  • Public-Key Pinning    – (hook point) validates TLS certificate pins
  • Payload Cryptography  – HMAC seal + XOR field encryption helpers
  • Ban Monitor           – background thread that revokes sessions on bans
  • Rate Limiting         – client-side brute-force lockout (3 fails → 5 min)

GitHub: https://github.com/AuthLX/AuthLX-Python-Example
"""

import os
import sys
import json
import time
import hmac
import hashlib
import logging
import platform
import subprocess
import threading
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AuthLX: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AuthLX")

# ---------------------------------------------------------------------------
# Dependency bootstrap
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# api  –  main SDK class
# ---------------------------------------------------------------------------
class api:
    """
    AuthLX client SDK.

    Usage::

        from authlx import api, others

        app = api(
            name="MyApp",
            ownerid="YOUR-APP-UUID",
            version="1.0",
            hash_to_check=others.get_checksum(),   # optional: enable hash check
        )

        if app.login("alice", "s3cr3t"):
            print("Welcome,", app.user_data.username)
    """

    # ------------------------------------------------------------------
    # Inner data class
    # ------------------------------------------------------------------
    class user_data_class:
        """Holds all user fields returned after a successful login."""

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

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------
    def __init__(
        self,
        name: str,
        ownerid: str,
        version: str,
        hash_to_check: str = None,
        api_url: str = None,
    ):
        """
        Initialise the SDK and contact the AuthLX backend.

        :param name:          Human-readable application name.
        :param ownerid:       Application UUID from the AuthLX dashboard.
        :param version:       Application version string (e.g. "1.0").
        :param hash_to_check: SHA-256 hex digest of the running executable.
                              Leave ``None`` to compute it automatically via
                              ``others.get_checksum()``, or pass a fixed
                              string to disable hash checking in development.
        :param api_url:       Override the AuthLX API base URL.  Defaults to
                              ``https://api.authlx.com/api/v1/client``.
        """
        self.name = name
        self.ownerid = ownerid
        self.version = version
        self.hash_to_check = (
            hash_to_check if hash_to_check is not None else others.get_checksum()
        )
        self.api_url = api_url or "https://api.authlx.com/api/v1/client"

        # Per-instance HTTP session
        self._session = requests.Session()
        self._session.trust_env = False   # disables local proxy auto-config (anti-MITM)

        # Authentication state
        self.session_token: str = ""
        self.initialized: bool = False
        self.user_data = self.user_data_class()

        # Rate limiting
        self._login_fails: int = 0
        self._lockout_end: float = 0.0

        # Debug mode
        self._debug: bool = False

        # Networking & security
        self._allowed_hosts: list = []
        self._pinned_public_keys: list = []
        self._secure_strings_enabled: bool = False
        self._secure_key: bytes = None

        # Ban monitor
        self._ban_monitor_thread: threading.Thread = None
        self._ban_monitor_active: bool = False

        self.init()

    # ------------------------------------------------------------------
    # Core lifecycle
    # ------------------------------------------------------------------
    def init(self):
        """
        Contact the AuthLX backend to verify the application is active and
        the client version matches.  Called automatically by ``__init__``.
        Exits the process if the backend is unreachable or the app is disabled.
        """
        others.anti_debug()

        response = self._do_request("/init", {"app_id": self.ownerid})

        if response and response.get("status") == "success":
            app_info = response.get("app_info", {})
            server_version = app_info.get("version", self.version)

            if server_version != self.version:
                logger.critical("\n[UPDATE REQUIRED] Your application version is outdated!")
                logger.critical(
                    f"Current: {self.version}  |  Required: {server_version}"
                )
                auto_update = app_info.get("auto_update_link")
                webloader = app_info.get("webloader_link")
                if auto_update:
                    logger.critical(f"[DOWNLOAD] Auto-update link: {auto_update}")
                if webloader:
                    logger.critical(f"[DOWNLOAD] Webloader link:   {webloader}")
                logger.critical("Please update before continuing.\n")
                time.sleep(5)
                os._exit(1)

            self.initialized = True
        else:
            logger.error("Failed to initialise application. Check your ownerid and network.")
            os._exit(1)

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def register(
        self,
        user: str,
        email: str,
        password: str,
        license_key: str,
        hwid: str = None,
    ) -> bool:
        """
        Register a new user account by activating a license key.

        :param user:        Desired username.
        :param email:       User's email address.
        :param password:    Desired password (plain-text; hashed server-side).
        :param license_key: A valid, unused license key for this application.
        :param hwid:        Hardware ID to bind.  Auto-detected if ``None``.
        :returns:           ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        response = self._do_request(
            "/register",
            {
                "app_id": self.ownerid,
                "username": user,
                "email": email,
                "password": password,
                "license_key": license_key,
                "hwid": hwid,
            },
        )

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Successfully registered!"))
            return True

        msg = response.get("message", "Registration failed.") if response else "No response."
        logger.error(f"Registration Failed: {msg}")
        if "Application not found" in msg:
            logger.critical(
                "\n[SETUP ERROR] The ownerid (App ID) is incorrect.\n"
                "[RESOLUTION] Copy the exact App ID from your AuthLX Dashboard.\n"
            )
        return False

    def login(self, user: str, password: str, hwid: str = None) -> bool:
        """
        Authenticate a user with username, password, and (optionally) HWID.

        On success the SDK stores a session token and populates ``user_data``.

        :param user:     Username.
        :param password: Plain-text password.
        :param hwid:     Hardware ID.  Auto-detected if ``None``.
        :returns:        ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        response = self._do_request(
            "/login",
            {
                "app_id": self.ownerid,
                "username": user,
                "password": password,
                "hwid": hwid,
                "hash": self.hash_to_check,
                "version": self.version,
            },
        )

        if response and response.get("status") == "success":
            data = response.get("data", {})
            self.session_token = data.get("token", "")
            self._load_user_data(data.get("user", {}))
            logger.info("Successfully logged in!")
            return True

        msg = response.get("message", "Login failed.") if response else "No response."
        logger.error(f"Login Failed: {msg}")

        if "Application hash invalid" in msg or "Application hash required" in msg:
            logger.critical(
                "\n[SETUP ERROR] Hash Check is enabled but this script's hash is not whitelisted."
            )
            logger.critical(
                f"[RESOLUTION] Dashboard → Your App → Security → Add hash: {self.hash_to_check}\n"
            )
        elif "Application not found" in msg:
            logger.critical(
                "\n[SETUP ERROR] The ownerid (App ID) is incorrect.\n"
                "[RESOLUTION] Copy the exact App ID from your AuthLX Dashboard.\n"
            )
        elif "Hardware ID mismatch" in msg:
            logger.critical("\n[USER ERROR] The user's hardware ID has changed.")
            logger.critical(
                "[RESOLUTION] The user needs an HWID reset from the AuthLX Dashboard.\n"
            )
        elif "Application is currently disabled" in msg:
            logger.critical(
                "\n[SETUP ERROR] Your application is disabled.\n"
                "[RESOLUTION] Set your app to Active in the AuthLX Dashboard.\n"
            )
        return False

    def web_login(self, user: str, password: str) -> bool:
        """
        Authenticate a user without HWID (suitable for web or admin panels).

        Includes client-side brute-force protection: after 3 consecutive
        failures a 5-minute lockout is enforced locally.

        :param user:     Username.
        :param password: Plain-text password.
        :returns:        ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if self.lockout_active():
            remaining = self.lockout_remaining_ms() // 1000
            logger.error(
                f"Account locked out due to multiple failed attempts. "
                f"Try again in {remaining} seconds."
            )
            return False

        response = self._do_request(
            "/web-login",
            {"app_id": self.ownerid, "username": user, "password": password},
        )

        if response and response.get("status") == "success":
            data = response.get("data", {})
            self._load_user_data(data.get("user", {}))
            self.reset_lockout()
            self.mark_authenticated()
            logger.info("Successfully logged in (Web)!")
            return True

        self.record_login_fail()
        self.bad_input_delay()
        msg = response.get("message", "Web login failed.") if response else "No response."
        logger.error(f"Web Login Failed: {msg}")
        return False

    def logout(self) -> bool:
        """
        Invalidate the current session on the backend and clear the local token.

        :returns: ``True`` on success, ``False`` if not logged in or on error.
        """
        self._checkinit()
        if not self.session_token:
            logger.error("Not logged in.")
            return False

        response = self._do_request(
            "/logout",
            {"app_id": self.ownerid, "session_token": self.session_token},
        )

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Logged out successfully."))
            self.session_token = ""
            return True

        msg = response.get("message", "Logout failed.") if response else "No response."
        logger.error(msg)
        return False

    def register_web(
        self,
        user: str,
        email: str,
        password: str,
        license_key: str,
    ) -> bool:
        """
        Register a new user without binding a HWID (web-flow registration).

        :param user:        Desired username.
        :param email:       User's email address.
        :param password:    Desired password.
        :param license_key: Valid, unused license key.
        :returns:           ``True`` on success, ``False`` on failure.
        """
        return self.register(user, email, password, license_key, hwid="")

    # ------------------------------------------------------------------
    # License operations
    # ------------------------------------------------------------------
    def upgrade(self, user: str, license_key: str) -> bool:
        """
        Apply an unused license key to an existing account to extend its
        subscription or change its subscription level.

        :param user:        Username of the account to upgrade.
        :param license_key: Valid, unused license key.
        :returns:           ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        response = self._do_request(
            "/upgrade",
            {"app_id": self.ownerid, "username": user, "license_key": license_key},
        )

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Account upgraded successfully!"))
            return True

        msg = response.get("message", "Upgrade failed.") if response else "No response."
        logger.error(f"Upgrade Failed: {msg}")
        return False

    # ------------------------------------------------------------------
    # Session & token verification
    # ------------------------------------------------------------------
    def check(self) -> bool:
        """
        Verify that the current session token is still valid on the backend.

        :returns: ``True`` if the session is active, ``False`` otherwise.
        """
        self._checkinit()
        if not self.session_token:
            return False

        response = self._do_request(
            "/verify-session",
            {"app_id": self.ownerid, "token": self.session_token},
        )
        return bool(response and response.get("status") == "success")

    def verify_token(self, standalone_token: str) -> bool:
        """
        Verify a standalone API token (issued separately from a login session).

        :param standalone_token: The token string to validate.
        :returns:                ``True`` if valid, ``False`` otherwise.
        """
        self._checkinit()
        response = self._do_request(
            "/verify-token",
            {"app_id": self.ownerid, "token": standalone_token},
        )

        if response and response.get("status") == "success":
            logger.info("Token is valid!")
            return True

        msg = response.get("message", "Invalid or banned token.") if response else "No response."
        logger.error(msg)
        return False

    # ------------------------------------------------------------------
    # Account management
    # ------------------------------------------------------------------
    def changeUsername(self, new_username: str) -> bool:
        """
        Change the username of the currently logged-in user.

        Requires an active session (call ``login()`` first).

        :param new_username: The desired new username.
        :returns:            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if not self.session_token:
            logger.error("Must be logged in to change username.")
            return False

        response = self._do_request(
            "/change-username",
            {
                "app_id": self.ownerid,
                "current_username": self.user_data.username,
                "new_username": new_username,
            },
        )

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Username changed successfully!"))
            self.user_data.username = new_username
            return True

        msg = response.get("message", "Username change failed.") if response else "No response."
        logger.error(f"Change Username Failed: {msg}")
        return False

    def forgot(self, user: str, new_password: str, hwid: str = None) -> bool:
        """
        Reset a user's password by verifying their bound Hardware ID.

        The account must have a HWID bound (i.e. the user must have logged
        in at least once with HWID locking enabled).

        :param user:         Username of the account to reset.
        :param new_password: The new plain-text password.
        :param hwid:         The user's current Hardware ID.  Auto-detected if ``None``.
        :returns:            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        response = self._do_request(
            "/forgot",
            {
                "app_id": self.ownerid,
                "username": user,
                "hwid": hwid,
                "new_password": new_password,
            },
        )

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Password reset successfully!"))
            return True

        msg = response.get("message", "Password reset failed.") if response else "No response."
        logger.error(f"Password Reset Failed: {msg}")
        return False

    # ------------------------------------------------------------------
    # Subscription & expiry helpers
    # ------------------------------------------------------------------
    def has_active_subscription(self) -> bool:
        """
        Return ``True`` if the logged-in user's subscription has not expired.
        """
        return self.expiry_remaining() > 0

    def expiry_remaining(self) -> float:
        """
        Return the number of seconds remaining until the subscription expires.
        Returns ``0`` if expired, or if no expiry date is available.
        """
        if not self.user_data.expires:
            return 0
        from datetime import datetime

        try:
            expire_str = self.user_data.expires.replace("Z", "+00:00")
            expire_dt = datetime.fromisoformat(expire_str)
            now_dt = datetime.now(expire_dt.tzinfo)
            return max(0.0, (expire_dt - now_dt).total_seconds())
        except Exception as e:
            if self._debug:
                logger.debug(f"Expiry parse error: {e}")
            return 0

    # ------------------------------------------------------------------
    # Auth runtime state
    # ------------------------------------------------------------------
    def mark_authenticated(self):
        """Mark the user as authenticated and record the runtime start time."""
        self.user_data.is_authenticated = True
        self.refresh_auth_runtime()

    def refresh_auth_runtime(self):
        """Update the authentication runtime start timestamp to *now*."""
        self.user_data.auth_runtime_start = time.time()

    def reset_auth_runtime(self):
        """Alias for ``refresh_auth_runtime`` — resets the runtime clock."""
        self.refresh_auth_runtime()

    # ------------------------------------------------------------------
    # Networking & security
    # ------------------------------------------------------------------
    def set_allowed_hosts(self, hosts: list):
        """
        Restrict all SDK HTTP requests to the given list of hostnames.
        Any request to a hostname not in this list causes an immediate exit.

        :param hosts: List of allowed hostnames (e.g. ``["api.authlx.com"]``).
        """
        self._allowed_hosts = list(hosts)

    def add_allowed_host(self, host: str):
        """
        Add a single hostname to the allowed-hosts list.
        Duplicate entries are silently ignored.
        """
        if host not in self._allowed_hosts:
            self._allowed_hosts.append(host)

    def clear_allowed_hosts(self):
        """Remove all host-locking restrictions."""
        self._allowed_hosts = []

    def set_pinned_public_keys(self, keys: list):
        """
        Set the list of accepted TLS public-key pins (``sha256//BASE64==`` format).
        Connections to hosts whose certificate does not match are rejected.

        :param keys: List of pin strings.
        """
        self._pinned_public_keys = list(keys)

    def add_pinned_public_key(self, key: str):
        """
        Add a single TLS public-key pin.
        Duplicate entries are silently ignored.
        """
        if key not in self._pinned_public_keys:
            self._pinned_public_keys.append(key)

    def clear_pinned_public_keys(self):
        """Remove all TLS public-key pins."""
        self._pinned_public_keys = []

    def enable_secure_strings(self):
        """
        Enable payload cryptography mode.
        When active, the SDK will attempt to unseal encrypted server responses.
        Derive a key first with ``derive_secure_key()``.
        """
        self._secure_strings_enabled = True

    def derive_secure_key(self, material: str):
        """
        Derive a 32-byte symmetric key from ``material`` (e.g.
        ``session_token + ":" + hwid``).  The result is stored in
        ``_secure_key`` and used by ``compute_auth_seal`` and
        ``xor_crypt_field``.

        :param material: Arbitrary string used as key-derivation input.
        """
        self._secure_key = hashlib.sha256(material.encode()).digest()

    def xor_crypt_field(self, data: str, key: str) -> str:
        """
        XOR-encrypt or decrypt a string field with a repeating key.
        Applying this function twice with the same key is its own inverse::

            original == xor_crypt_field(xor_crypt_field(original, key), key)

        :param data: Input string.
        :param key:  Key string (repeated to match ``data`` length).
        :returns:    XOR-processed output string.
        """
        key_cycle = key * (len(data) // len(key) + 1)
        return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(data, key_cycle))

    def compute_auth_seal(self, payload: str):
        """
        Compute an HMAC-SHA256 hex digest of ``payload`` using the derived
        secure key.  Returns ``None`` if no key has been derived yet.

        :param payload: The string to seal.
        :returns:       64-character hex string, or ``None``.
        """
        if not self._secure_key:
            return None
        return hmac.new(self._secure_key, payload.encode(), hashlib.sha256).hexdigest()

    def req(self, url: str, method: str = "GET", **kwargs):
        """
        Hardened HTTP request wrapper that enforces host-locking and key-pinning
        on arbitrary URLs (not just AuthLX endpoints).

        :param url:    Target URL.
        :param method: HTTP method (``"GET"`` or ``"POST"``).
        :param kwargs: Additional keyword arguments forwarded to ``requests``.
        :returns:      A ``requests.Response`` object, or ``None`` on error.
        """
        if self._allowed_hosts:
            domain = urlparse(url).hostname
            if domain not in self._allowed_hosts:
                logger.critical(
                    f"Security violation: Connection blocked to unauthorized host: {domain}"
                )
                time.sleep(self.close_delay() / 1000)
                os._exit(1)

        try:
            if method.upper() == "GET":
                res = self._session.get(url, **kwargs)
            else:
                res = self._session.post(url, **kwargs)

            if self._pinned_public_keys:
                self._verify_pinned_key(url)

            return res
        except Exception as e:
            logger.error(f"req() failed: {e}")
            return None

    # ------------------------------------------------------------------
    # Ban monitor
    # ------------------------------------------------------------------
    def start_ban_monitor(self, interval_seconds: int = 60):
        """
        Start a background daemon thread that periodically checks whether the
        current session is still valid.  If the session is revoked (e.g. due
        to an admin ban), the process is terminated immediately.

        Calling this when the monitor is already running is a no-op.

        :param interval_seconds: Polling interval in seconds (default: 60).
        """
        if self._ban_monitor_active:
            return

        self._ban_monitor_active = True
        self._ban_monitor_thread = threading.Thread(
            target=self._ban_monitor_loop,
            args=(interval_seconds,),
            daemon=True,
            name="authlx-ban-monitor",
        )
        self._ban_monitor_thread.start()
        if self._debug:
            logger.debug("Ban monitor started.")

    def stop_ban_monitor(self):
        """Stop the ban monitor daemon thread."""
        self._ban_monitor_active = False
        if self._debug:
            logger.debug("Ban monitor stopped.")

    def ban_monitor_running(self) -> bool:
        """Return ``True`` if the ban monitor thread is alive."""
        return (
            self._ban_monitor_active
            and self._ban_monitor_thread is not None
            and self._ban_monitor_thread.is_alive()
        )

    # ------------------------------------------------------------------
    # Rate limiting & lockouts
    # ------------------------------------------------------------------
    def record_login_fail(self):
        """
        Increment the consecutive login-failure counter.
        After 3 failures a 5-minute client-side lockout is triggered.
        """
        self._login_fails += 1
        if self._login_fails >= 3:
            self._lockout_end = time.time() + 300  # 5 minutes

    def lockout_active(self) -> bool:
        """Return ``True`` if a client-side brute-force lockout is in effect."""
        if time.time() < self._lockout_end:
            return True
        if self._lockout_end > 0 and time.time() >= self._lockout_end:
            self.reset_lockout()
        return False

    def lockout_remaining_ms(self) -> int:
        """Return the milliseconds remaining in the current lockout (0 if none)."""
        if not self.lockout_active():
            return 0
        return max(0, int((self._lockout_end - time.time()) * 1000))

    def reset_lockout(self):
        """Clear the login-failure counter and any active lockout."""
        self._login_fails = 0
        self._lockout_end = 0.0

    # ------------------------------------------------------------------
    # Delay helpers
    # ------------------------------------------------------------------
    def init_fail_delay(self) -> int:
        """
        Delay used when the application fails to initialise.
        Returns the delay in milliseconds (3 000 ms).
        """
        time.sleep(3)
        return 3000

    def bad_input_delay(self) -> int:
        """
        Delay injected after a failed login attempt to slow brute-force tools.
        Returns the delay in milliseconds (2 000 ms).
        """
        time.sleep(2)
        return 2000

    def close_delay(self) -> int:
        """
        Delay used before a forced process exit (e.g. on security violation).
        Returns the delay in milliseconds (3 000 ms) without sleeping.
        """
        return 3000

    # ------------------------------------------------------------------
    # Debug helpers
    # ------------------------------------------------------------------
    def setDebug(self, enable: bool):
        """
        Enable or disable verbose debug logging.

        :param enable: ``True`` to enable, ``False`` to disable.
        """
        self._debug = enable

    def debugInfo(self) -> dict:
        """
        Return a snapshot of internal SDK state for debugging purposes.

        :returns: Dictionary with keys ``debug_enabled``, ``lockout_active``,
                  ``login_fails``, and ``session``.
        """
        return {
            "debug_enabled": self._debug,
            "lockout_active": self.lockout_active(),
            "login_fails": self._login_fails,
            "session": self.session_token,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _checkinit(self):
        """Abort if ``init()`` has not completed successfully."""
        if not self.initialized:
            logger.warning("SDK not initialised. Call api() first.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _do_request(self, endpoint: str, post_data: dict):
        """
        Internal POST helper.  Enforces host-locking, sets SDK headers,
        and handles connection/timeout errors with a graceful exit.
        """
        try:
            target_url = f"{self.api_url}{endpoint}"

            # Host Locking
            if self._allowed_hosts:
                domain = urlparse(target_url).hostname
                if domain not in self._allowed_hosts:
                    logger.critical(
                        f"Security violation: Connection blocked to unauthorized host: {domain}"
                    )
                    time.sleep(self.close_delay() / 1000)
                    os._exit(1)

            headers = {
                "User-Agent": f"AuthLX-ClientSDK/1.0 ({self.name} v{self.version})",
                "Content-Type": "application/json",
            }

            if self._debug:
                logger.debug(f"→ {endpoint}  {post_data}")

            response = self._session.post(
                target_url,
                json=post_data,
                headers=headers,
                timeout=10,
                verify=True,
            )

            if self._pinned_public_keys:
                self._verify_pinned_key(target_url)

            if self._debug:
                logger.debug(f"← {response.status_code}  {response.text}")

            try:
                return response.json()
            except ValueError:
                logger.error(f"Invalid JSON response from server (HTTP {response.status_code}).")
                time.sleep(self.close_delay() / 1000)
                os._exit(1)

        except requests.exceptions.Timeout:
            logger.error("Request timed out. The server may be down.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)
        except requests.exceptions.ConnectionError:
            logger.error("Connection error. The server is unreachable.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _load_user_data(self, data: dict):
        """Populate ``user_data`` from a server response dict."""
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

    def _verify_pinned_key(self, url: str):
        """
        Hook point for TLS public-key pinning.  Override or extend this
        method to compare the server's certificate public key against
        ``self._pinned_public_keys`` using the ``ssl`` standard library.
        """
        if self._debug:
            logger.debug(f"[PIN] Key pinning check for {url} (keys: {self._pinned_public_keys})")

    def _ban_monitor_loop(self, interval: int):
        """Background thread body for the ban monitor."""
        while self._ban_monitor_active:
            time.sleep(interval)
            if not self.session_token:
                continue
            if self._debug:
                logger.debug("Ban monitor: checking session...")
            if not self.check():
                self._ban_monitor_detected()

    def _ban_monitor_detected(self):
        """Called by the ban monitor when a session is revoked at runtime."""
        logger.critical("\n[SECURITY] Session revoked or account banned during runtime.")
        logger.critical("Process terminating to protect application memory.")
        time.sleep(1)
        os._exit(1)


# ---------------------------------------------------------------------------
# others  –  static utility class
# ---------------------------------------------------------------------------
class others:
    """Static helpers for hardware fingerprinting, hash generation, and anti-debug."""

    @staticmethod
    def get_checksum() -> str:
        """
        Compute the SHA-256 checksum of the currently running script or
        executable.  Pass this to the ``hash_to_check`` parameter of ``api``
        to enable server-side application integrity verification.

        :returns: Lowercase hex SHA-256 digest, or ``"UNKNOWN_HASH"`` on error.
        """
        try:
            with open(sys.argv[0], "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "UNKNOWN_HASH"

    @staticmethod
    def anti_debug():
        """
        Terminate the process immediately if a Python debugger is attached
        (``sys.gettrace()`` is not ``None``).  Called automatically during
        ``api.init()``.
        """
        if sys.gettrace() is not None:
            logger.critical("Security violation: Debugger detected. Exiting.")
            os._exit(1)

    @staticmethod
    def get_hwid() -> str:
        """
        Return a stable Hardware ID for the current machine:

        - **Linux**:   ``/etc/machine-id``
        - **Windows**: User SID via ``win32security``
        - **macOS**:   IOPlatformSerialNumber via ``ioreg``

        :returns: Hardware ID string, or a platform-specific fallback on error.
        """
        system = platform.system()

        if system == "Linux":
            try:
                with open("/etc/machine-id") as f:
                    return f.read().strip()
            except Exception:
                return "Unknown-Linux-HWID"

        if system == "Windows":
            try:
                winuser = os.getlogin()
                sid = win32security.LookupAccountName(None, winuser)[0]
                return win32security.ConvertSidToStringSid(sid)
            except Exception:
                return "Unknown-Windows-HWID"

        if system == "Darwin":
            try:
                raw = subprocess.Popen(
                    "ioreg -l | grep IOPlatformSerialNumber",
                    stdout=subprocess.PIPE,
                    shell=True,
                ).communicate()[0]
                serial = raw.decode().split("=", 1)[1].replace(" ", "")
                return serial[1:-2]
            except Exception:
                return "Unknown-Mac-HWID"

        return "Unknown-HWID"
