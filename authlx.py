"""
AuthLX Python SDK
=================
A production-ready client SDK for the AuthLX authentication platform.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  QUICK START
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  from authlx import api, others

  authlxapp = api(
      name          = "MyApp",
      ownerid       = "YOUR-APP-UUID",          # AuthLX Dashboard → App Info
      version       = "1.0",
      client_secret = "YOUR-CLIENT-SECRET",     # AuthLX Dashboard → App Info → Client Secret
  )

  if authlxapp.login("alice", "password123"):
      print("Logged in as", authlxapp.user_data.username)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ANTI-TAMPER: TWO MODES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  MODE 1 — SECURE  (client_secret provided — RECOMMENDED)
  ─────────────────────────────────────────────────────────
  • Every login/register automatically sends:
      hash           = SHA-256 of this .py or .exe
      hash_signature = HMAC-SHA256(hash:timestamp:nonce, client_secret)
      hash_timestamp = current Unix time (5-minute expiry window)
      hash_nonce     = random 32-hex string (single-use, 10-min block)
  • Backend verifies all three fields before allowing login.
  • The FIRST valid hash received is AUTO-WHITELISTED (Trust-On-First-Use).
  • All subsequent logins must match this hash. If you compile a NEW build, 
    you MUST click "Reset All Hashes" in your dashboard so it learns the new hash.
  • Network replay is impossible: nonce is consumed once; timestamp expires.
  • Attacker must EXTRACT the client_secret from your binary to forge
    a valid HMAC — protect it with PyArmor, Nuitka, or similar tools.

  authlxapp = api(
      name          = "MyApp",
      ownerid       = "YOUR-APP-UUID",
      version       = "1.0",
      client_secret = "YOUR-CLIENT-SECRET",  # from dashboard
  )

  MODE 2 — OFF  (no client_secret — developer opts out)
  ───────────────────────────────────────────────────────
  • The hash field is sent to the backend but the server ignores it
    entirely (because there is no HMAC to verify with).
  • No manual whitelisting required.
  • No hash protection. Auth relies on password, HWID, and sessions.
  • Use this when your language/environment cannot protect a secret.

  authlxapp = api(
      name    = "MyApp",
      ownerid = "YOUR-APP-UUID",
      version = "1.0",
      # client_secret omitted → OFF mode
  )

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WINDOWS SETUP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  pip install pywin32
  python -m pywin32_postinstall -install

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PRODUCTION HARDENING (hide client_secret from reverse engineers)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Step 1: Obfuscate source code
      pip install pyarmor
      pyarmor gen main.py            # outputs dist/main.py (encrypted)

  Step 2: Compile to executable
      pip install pyinstaller
      pyinstaller --onefile dist/main.py

  Step 3: Ship the .exe — client_secret is now inside encrypted bytecode.
  Step 4: Enable Hash Check in Dashboard. Run the app once to auto-whitelist it.
          When you release an update, click "Reset All Hashes" before running it.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import time
import hmac
import shutil
import hashlib
import logging
import platform
import secrets as _secrets
import subprocess
import threading
from urllib.parse import urlparse

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AuthLX: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("AuthLX")

# ─── Dependency bootstrap ─────────────────────────────────────────────────────
try:
    if os.name == "nt":
        import win32api       # type: ignore  # pip install pywin32
        import win32security  # type: ignore
        import win32con       # type: ignore
    import requests
except ModuleNotFoundError:
    print("AuthLX: Required modules not found. Installing...")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == "nt":
            os.system("pip install pywin32")
        os.system("pip install requests")
    print("AuthLX: Done. Please re-run the application.")
    time.sleep(1.5)
    os._exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   UpdateInfo  --  auto-updater data container
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class UpdateInfo:
    """Holds auto-updater metadata returned by check_for_updates()."""
    def __init__(self):
        self.update_available: bool = False
        self.current_version: str   = ""
        self.latest_version: str    = ""
        self.download_url: str      = ""
        self.file_name: str         = ""
        self.release_notes: str     = ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   api  --  main SDK class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class api:
    """
    AuthLX client SDK — see module docstring for full usage guide.

    Parameters
    ----------
    name : str
        Human-readable app name shown in the AuthLX Dashboard.

    ownerid : str
        Application UUID.  Find it in:
        Dashboard → Select App → App Info → App ID

    version : str
        Application version string (e.g. "1.0").
        Must match the version registered in your AuthLX Dashboard.
        If the backend returns a different version the process exits
        and prints the update/download link.

    client_secret : str, optional
        The Application Client Secret from your AuthLX Dashboard.
        Dashboard → Select App → App Info → Client Secret

        ► Provide this for SECURE MODE (recommended):
          • Every request is HMAC-signed with this secret.
          • The very first hash is auto-whitelisted (Trust On First Use).
          • For future updates, click "Reset All Hashes" in dashboard.
          • Network replay attacks are blocked via timestamp + nonce.

        ► Omit for OFF MODE (developer opt-out):
          • No hash-based protection. Hash field is sent but ignored by server.
          • Auth still protected by bcrypt password, HWID lock, and sessions.

    hash_to_check : str, optional
        Override the auto-computed SHA-256 hash.
        • Leave None (default) — SDK reads this file/exe and computes its own hash.
        • Pass "dev-skip" only during local testing to avoid hash-related errors
          while actively editing code. NEVER ship with a hardcoded string.

    api_url : str, optional
        Override the AuthLX API base URL.  Leave None to use the production
        endpoint.  Only change if you are self-hosting the backend.

    Examples
    --------
    SECURE MODE (recommended for all production apps)::

        authlxapp = api(
            name          = "MyApp",
            ownerid       = "YOUR-APP-UUID",
            version       = "1.0",
            client_secret = "YOUR-CLIENT-SECRET",
        )

    OFF MODE (no hash protection, developer opts out)::

        authlxapp = api(
            name    = "MyApp",
            ownerid = "YOUR-APP-UUID",
            version = "1.0",
        )

    Development / testing (skip hash check locally)::

        authlxapp = api(
            name          = "MyApp",
            ownerid       = "YOUR-APP-UUID",
            version       = "1.0",
            client_secret = "YOUR-CLIENT-SECRET",
            hash_to_check = "dev-skip",  # ← only for local dev; remove before release
        )
    """

    # ── Inner user data class ─────────────────────────────────────────────────
    class user_data_class:
        """Holds all user fields populated after a successful login."""
        def __init__(self):
            self.username: str           = ""
            self.hwid: str               = ""
            self.expires: str            = ""
            self.createdate: str         = ""
            self.lastlogin: str          = ""
            self.subscription: str       = ""
            self.subscriptions: list     = []
            self.is_authenticated: bool  = False
            self.auth_runtime_start: float = 0.0

    # ── Constructor ───────────────────────────────────────────────────────────
    def __init__(
        self,
        name: str,
        ownerid: str,
        version: str,
        client_secret: str  = None,
        hash_to_check: str  = None,
        api_url: str        = None,
    ):
        self.name    = name
        self.ownerid = ownerid
        self.version = version

        # SECURE MODE secret — developer's responsibility to protect in binary
        self._client_secret: str = client_secret

        # Hash of the running file — computed once at startup
        self.hash_to_check: str = (
            hash_to_check if hash_to_check is not None
            else others.get_checksum()
        )

        self.api_url: str = api_url or "https://authlx.com/api/v1/client"

        # Per-instance HTTP session — trust_env=False disables proxy auto-config
        self._session = requests.Session()
        self._session.trust_env = False   # Anti-MITM: ignore system proxy settings

        # Auth state
        self.session_token: str  = ""
        self.initialized: bool   = False
        self.hwid_method: str    = "windows_user"  # overridden by server on init()
        self.user_data           = self.user_data_class()

        # Ban info extraction
        self.ban_reason: str     = None
        self.ban_revoke_date: str = None

        # Rate limiting
        self._login_fails: int   = 0
        self._lockout_end: float = 0.0

        # Debug
        self._debug: bool = False

        # Security options
        self._allowed_hosts: list       = []
        self._pinned_public_keys: list  = []

        # Ban monitor
        self._ban_monitor_thread: threading.Thread = None
        self._ban_monitor_active: bool             = False

        # Auto-Updater
        self.auto_update_enabled: bool = True
        self.update_info: UpdateInfo   = UpdateInfo()

        # Auto-init on construction
        self.init()

    # ── Core lifecycle ────────────────────────────────────────────────────────

    def init(self):
        """
        Contact the AuthLX backend to verify the app is active and version
        matches.  Called automatically by ``__init__``.

        Also fetches server-side configuration (HWID method).
        Exits the process if the app is disabled, unreachable, or outdated.
        Anti-debug runs automatically inside this call.
        """
        # Intercept --authlx-update-finish stage before anything else
        self.handle_update_stage()

        # Cleanup previous .old backup if it exists
        current_exe = self.get_current_executable_path()
        if current_exe:
            old_backup = current_exe + ".old"
            if os.path.exists(old_backup):
                try:
                    os.remove(old_backup)
                except Exception:
                    pass

        others.anti_debug()

        payload = {
            "app_id": self.ownerid,
            "name": self.name,
            "version": self.version,
            "secret": self._client_secret or "NO_SECRET"
        }
        response = self._do_request("/init", payload)

        if response and response.get("status") == "success":
            app_info       = response.get("app_info", {})
            server_version = app_info.get("version", self.version)
            server_name    = app_info.get("name", self.name)

            if server_name != self.name:
                logger.critical(f"\n[SECURITY] Application name mismatch!")
                logger.critical(f"  Expected: {self.name}  |  Server reports: {server_name}")
                logger.critical("  Exiting to prevent unauthorized execution.")
                time.sleep(5)
                os._exit(1)

            if server_version != self.version:
                logger.critical("\n[UPDATE REQUIRED] Application version is outdated!")
                logger.critical(f"  Current: {self.version}  |  Required: {server_version}")
                
                if self.auto_update_enabled:
                    logger.info(f"[AUTO-UPDATE] Initiating auto-update to v{server_version}...")
                    info = self.check_for_updates()
                    if info.update_available:
                        self.perform_update(info)

                time.sleep(3)
                os._exit(1)

            self.initialized = True
            self.hwid_method = app_info.get("hwid_method", "windows_user")

            mode = "SECURE (HMAC + TOFU Hash)" if self._client_secret else "OFF (no hash protection)"
            if self._debug:
                logger.debug(f"Hash mode: {mode}")
        else:
            logger.error("Failed to initialise. Check ownerid and network connectivity.")
            os._exit(1)

    # ── HMAC helper ───────────────────────────────────────────────────────────

    def _compute_hash_signature(self) -> tuple:
        """
        Compute the HMAC-SHA256 signature for the current hash.

        Only called when ``client_secret`` is set (SECURE MODE).

        Returns
        -------
        tuple
            (signature_hex, timestamp_str, nonce_hex)

        Security properties:
          • signature   — HMAC proves requester knows the client_secret
          • timestamp   — backend rejects requests older than 5 minutes
          • nonce       — random 32-char hex string; backend blocks duplicates
                          within 10 minutes (single-use token)
        """
        timestamp = str(int(time.time()))
        nonce     = _secrets.token_hex(16)   # 32 hex chars = 128 bits of entropy
        signature = hmac.new(
            self._client_secret.encode("utf-8"),
            f"{self.hash_to_check}:{timestamp}:{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return signature, timestamp, nonce

    def _build_hash_payload(self) -> dict:
        """
        Build the hash-related fields to include in every login/register payload.

        SECURE MODE  — returns hash + hash_signature + hash_timestamp + hash_nonce
        OFF MODE     — returns hash only (backend ignores it)
        """
        payload = {"hash": self.hash_to_check}

        if self._client_secret:
            sig, ts, nonce = self._compute_hash_signature()
            payload["hash_signature"]  = sig
            payload["hash_timestamp"]  = ts
            payload["hash_nonce"]      = nonce

        return payload

    # ── Authentication ────────────────────────────────────────────────────────

    def login(self, user: str, password: str, hwid: str = None) -> bool:
        """
        Authenticate a user with username, password, and (optionally) HWID.

        In SECURE MODE (client_secret provided):
          • HMAC signature + timestamp + nonce are computed and sent automatically.
          • The backend verifies HMAC → rejects if secret doesn't match.
          • The nonce is consumed server-side → replay is impossible.
          • The first hash is auto-whitelisted (TOFU). If the hash doesn't match
            the whitelist, the request is blocked.

        In OFF MODE (no client_secret):
          • Only hash string is sent. Backend ignores it.
          • Auth protected by password bcrypt + HWID + session token.

        Parameters
        ----------
        user : str
            Username.
        password : str
            Plain-text password (hashed server-side with bcrypt).
        hwid : str, optional
            Hardware ID.  Auto-detected via ``others.get_hwid()`` if omitted.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()

        if hwid is None:
            hwid = others.get_hwid(method=self.hwid_method)

        payload = {
            "app_id":   self.ownerid,
            "username": user,
            "password": password,
            "hwid":     hwid,
            "version":  self.version,
        }
        payload.update(self._build_hash_payload())  # adds hash (+ signature fields if SECURE)

        if self._debug:
            mode = "SECURE" if self._client_secret else "OFF"
            logger.debug(f"login() hash mode: {mode}, hash: {self.hash_to_check[:16]}…")

        response = self._do_request("/login", payload)

        if response and response.get("status") == "success":
            data = response.get("data", {})
            self.session_token = data.get("token", "")
            self._load_user_data(data.get("user", {}))
            self.mark_authenticated()
            logger.info(f"Successfully logged in as '{self.user_data.username}'!")
            return True

        msg = (response.get("message", "Login failed.") if response else "No server response.")
        self._parse_ban_info(msg)
        logger.error(f"Login Failed: {msg}")
        self._login_hint(msg)
        return False

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

        Includes the same HMAC hash payload as ``login()``.

        Parameters
        ----------
        user : str
            Desired username.
        email : str
            User's email address.
        password : str
            Desired password.
        license_key : str
            A valid, unused license key for this application.
        hwid : str, optional
            Hardware ID.  Auto-detected if omitted.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()

        if hwid is None:
            hwid = others.get_hwid(method=self.hwid_method)

        payload = {
            "app_id":      self.ownerid,
            "username":    user,
            "email":       email,
            "password":    password,
            "license_key": license_key,
            "hwid":        hwid,
        }
        payload.update(self._build_hash_payload())

        response = self._do_request("/register", payload)

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Registration successful!"))
            return True

        msg = (response.get("message", "Registration failed.") if response else "No server response.")
        self._parse_ban_info(msg)
        logger.error(f"Registration Failed: {msg}")
        self._login_hint(msg)
        return False

    def web_login(self, user: str, password: str) -> bool:
        """
        Authenticate without HWID binding (for web panels or admin tools).

        Includes client-side brute-force lockout: 3 consecutive failures
        trigger a 5-minute lockout before another attempt is allowed.

        Parameters
        ----------
        user : str
            Username.
        password : str
            Plain-text password.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()

        if self.lockout_active():
            secs = self.lockout_remaining_ms() // 1000
            logger.error(f"Locked out due to multiple failed attempts. Try again in {secs}s.")
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
        msg = (response.get("message", "Web login failed.") if response else "No server response.")
        self._parse_ban_info(msg)
        logger.error(f"Web Login Failed: {msg}")
        return False

    def logout(self) -> bool:
        """
        Invalidate the current session on the backend and clear the local token.

        Returns
        -------
        bool
            ``True`` on success, ``False`` if not logged in or on error.
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
            logger.info(response.get("message", "Logged out."))
            self.session_token = ""
            self.user_data     = self.user_data_class()
            return True

        msg = (response.get("message", "Logout failed.") if response else "No server response.")
        logger.error(msg)
        return False

    def register_web(
        self, user: str, email: str, password: str, license_key: str
    ) -> bool:
        """Register without binding a HWID (web-flow registration)."""
        return self.register(user, email, password, license_key, hwid="WEB_REGISTRATION")

    # ── License operations ────────────────────────────────────────────────────

    def upgrade(self, user: str, license_key: str) -> bool:
        """
        Apply an unused license key to an existing account to extend its
        subscription or change its tier.

        Parameters
        ----------
        user : str
            Username of the account to upgrade.
        license_key : str
            Valid, unused license key.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        response = self._do_request(
            "/upgrade",
            {"app_id": self.ownerid, "username": user, "license_key": license_key},
        )
        if response and response.get("status") == "success":
            logger.info(response.get("message", "License successfully applied!"))
            return True

        msg = (response.get("message", "Upgrade failed.") if response else "No response.")
        self._parse_ban_info(msg)
        logger.error(f"Upgrade Failed: {msg}")
        return False

    # ── Session & token verification ──────────────────────────────────────────

    def check(self) -> bool:
        """
        Verify that the current session token is still valid on the backend.

        Call this at intervals (or use ``start_ban_monitor()``) to detect
        admin bans or session revocations at runtime.

        Returns
        -------
        bool
            ``True`` if session is active, ``False`` otherwise.
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
        Verify a standalone API token issued from the AuthLX Dashboard.

        Parameters
        ----------
        standalone_token : str
            The token string to validate.

        Returns
        -------
        bool
            ``True`` if valid and not banned, ``False`` otherwise.
        """
        self._checkinit()
        response = self._do_request(
            "/verify-token",
            {"app_id": self.ownerid, "token": standalone_token},
        )
        if response and response.get("status") == "success":
            logger.info("Token is valid!")
            return True
        msg = (response.get("message", "Invalid or banned token.") if response else "No response.")
        self._parse_ban_info(msg)
        logger.error(msg)
        return False

    # ── Account management ────────────────────────────────────────────────────

    def changeUsername(self, new_username: str) -> bool:
        """
        Change the username of the currently logged-in user.

        Requires an active session (``login()`` must have succeeded).

        Parameters
        ----------
        new_username : str
            The desired new username.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if not self.session_token:
            logger.error("Must be logged in to change username.")
            return False

        response = self._do_request(
            "/change-username",
            {
                "app_id":           self.ownerid,
                "session_token":    self.session_token,
                "new_username":     new_username,
            },
        )
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Username changed!"))
            self.user_data.username = new_username
            return True
        msg = (response.get("message", "Failed.") if response else "No response.")
        logger.error(f"changeUsername Failed: {msg}")
        return False

    def forgot(self, user: str, new_password: str, hwid: str = None) -> bool:
        """
        Reset a user's password by verifying their bound Hardware ID.

        The account must have a HWID bound (logged in at least once with
        HWID locking enabled on the app).

        Parameters
        ----------
        user : str
            Username of the account to reset.
        new_password : str
            The new plain-text password.
        hwid : str, optional
            The user's current Hardware ID.  Auto-detected if omitted.

        Returns
        -------
        bool
            ``True`` on success, ``False`` on failure.
        """
        self._checkinit()
        if hwid is None:
            hwid = others.get_hwid(method=self.hwid_method)

        response = self._do_request(
            "/forgot",
            {
                "app_id":       self.ownerid,
                "username":     user,
                "hwid":         hwid,
                "new_password": new_password,
            },
        )
        if response and response.get("status") == "success":
            logger.info(response.get("message", "Password reset!"))
            return True
        msg = (response.get("message", "Failed.") if response else "No response.")
        logger.error(f"forgot Failed: {msg}")
        return False

    # ── Subscription & expiry helpers ─────────────────────────────────────────

    def has_active_subscription(self) -> bool:
        """Return ``True`` if the logged-in user's subscription has not expired."""
        return self.expiry_remaining() > 0

    def expiry_remaining(self) -> float:
        """
        Return the number of seconds until the subscription expires.
        Returns ``0`` if expired or no expiry data is available.
        """
        if not self.user_data.expires:
            return 0
        from datetime import datetime
        try:
            s = self.user_data.expires.replace("Z", "+00:00")
            exp = datetime.fromisoformat(s)
            now = datetime.now(exp.tzinfo)
            return max(0.0, (exp - now).total_seconds())
        except Exception as e:
            if self._debug:
                logger.debug(f"expiry_remaining parse error: {e}")
            return 0

    # ── Auth runtime state ────────────────────────────────────────────────────

    def mark_authenticated(self):
        """Mark user as authenticated and record the runtime start time."""
        self.user_data.is_authenticated  = True
        self.user_data.auth_runtime_start = time.time()

    def refresh_auth_runtime(self):
        """Reset the authentication runtime clock to now."""
        self.user_data.auth_runtime_start = time.time()

    reset_auth_runtime = refresh_auth_runtime  # alias

    # ── Networking & security ─────────────────────────────────────────────────

    def set_allowed_hosts(self, hosts: list):
        """
        Restrict all SDK HTTP requests to the given list of hostnames.
        Any request to a hostname not in this list causes immediate exit.

        Example::

            authlxapp.set_allowed_hosts(["authlx.com"])
        """
        self._allowed_hosts = list(hosts)

    def add_allowed_host(self, host: str):
        """Add a single hostname to the allowed-hosts list."""
        if host not in self._allowed_hosts:
            self._allowed_hosts.append(host)

    def clear_allowed_hosts(self):
        """Remove all host-locking restrictions."""
        self._allowed_hosts = []

    def set_pinned_public_keys(self, keys: list):
        """Set TLS public-key pins (``sha256//BASE64==`` format)."""
        self._pinned_public_keys = list(keys)

    def add_pinned_public_key(self, key: str):
        """Add a single TLS public-key pin."""
        if key not in self._pinned_public_keys:
            self._pinned_public_keys.append(key)

    def clear_pinned_public_keys(self):
        """Remove all TLS public-key pins."""
        self._pinned_public_keys = []

    def req(self, url: str, method: str = "GET", **kwargs):
        """
        Hardened HTTP wrapper that enforces host-locking on arbitrary URLs.

        Parameters
        ----------
        url : str
            Target URL.
        method : str
            "GET" or "POST".
        **kwargs
            Additional arguments forwarded to ``requests``.

        Returns
        -------
        requests.Response or None
        """
        if self._allowed_hosts:
            domain = urlparse(url).hostname
            if domain not in self._allowed_hosts:
                logger.critical(f"Security violation: blocked connection to {domain}")
                time.sleep(self.close_delay() / 1000)
                os._exit(1)
        try:
            fn = self._session.get if method.upper() == "GET" else self._session.post
            return fn(url, **kwargs)
        except Exception as e:
            logger.error(f"req() failed: {e}")
            return None

    # ── Ban monitor ───────────────────────────────────────────────────────────

    def start_ban_monitor(self, interval_seconds: int = 60):
        """
        Start a background daemon thread that polls session validity.

        If the session is revoked (e.g. the user is banned by an admin
        while the app is running), the process is terminated immediately.

        Calling this when the monitor is already running is a no-op.

        Parameters
        ----------
        interval_seconds : int
            Polling interval in seconds (default: 60).

        Example::

            if authlxapp.login("alice", "password"):
                authlxapp.start_ban_monitor(interval_seconds=120)
                # Your app logic here...
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

    # ── Rate limiting & lockouts ──────────────────────────────────────────────

    def record_login_fail(self):
        """
        Increment the consecutive login-failure counter.
        After 3 failures a 5-minute client-side lockout is triggered.
        """
        self._login_fails += 1
        if self._login_fails >= 3:
            self._lockout_end = time.time() + 300

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

    # ── Delay helpers ─────────────────────────────────────────────────────────

    def init_fail_delay(self) -> int:
        """3-second delay used when initialisation fails."""
        time.sleep(3)
        return 3000

    def bad_input_delay(self) -> int:
        """2-second delay injected after a failed login to deter brute force."""
        time.sleep(2)
        return 2000

    def close_delay(self) -> int:
        """3-second delay used before a forced process exit."""
        return 3000

    # ── Debug helpers ─────────────────────────────────────────────────────────

    def setDebug(self, enable: bool):
        """Enable or disable verbose debug logging."""
        self._debug = enable

    def debugInfo(self) -> dict:
        """Return a snapshot of SDK state for debugging."""
        return {
            "debug_enabled":  self._debug,
            "hash_mode":      "SECURE" if self._client_secret else "OFF",
            "lockout_active": self.lockout_active(),
            "login_fails":    self._login_fails,
            "session":        self.session_token[:12] + "…" if self.session_token else "",
            "hash":           self.hash_to_check,
            "hwid_method":    self.hwid_method,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _checkinit(self):
        """Abort if ``init()`` has not completed successfully."""
        if not self.initialized:
            logger.warning("SDK not initialised. Call api() first.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _do_request(self, endpoint: str, post_data: dict):
        """
        Internal POST helper.  Enforces host-locking, sets SDK headers,
        handles connection/timeout errors with a graceful exit.
        """
        try:
            target_url = f"{self.api_url}{endpoint}"

            if self._allowed_hosts:
                domain = urlparse(target_url).hostname
                if domain not in self._allowed_hosts:
                    logger.critical(f"Security violation: blocked to {domain}")
                    time.sleep(self.close_delay() / 1000)
                    os._exit(1)

            headers = {
                "User-Agent":   f"AuthLX-SDK/1.0 ({self.name} v{self.version})",
                "Content-Type": "application/json",
            }

            if self._debug:
                safe = {k: v for k, v in post_data.items() if k != "password"}
                logger.debug(f"→ POST {endpoint}  {safe}")

            resp = self._session.post(
                target_url,
                json=post_data,
                headers=headers,
                timeout=10,
                verify=True,
            )

            if self._debug:
                logger.debug(f"← {resp.status_code}  {resp.text[:200]}")

            try:
                return resp.json()
            except ValueError:
                logger.error(f"Invalid JSON from server (HTTP {resp.status_code}).")
                time.sleep(self.close_delay() / 1000)
                os._exit(1)

        except requests.exceptions.Timeout:
            logger.error("Request timed out. Server may be down.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)
        except requests.exceptions.ConnectionError:
            logger.error("Connection error. Server is unreachable.")
            time.sleep(self.close_delay() / 1000)
            os._exit(1)

    def _load_user_data(self, data: dict):
        """Populate ``user_data`` from a server response dict."""
        self.user_data.username   = data.get("username", "")
        self.user_data.hwid       = data.get("hwid", "N/A")
        self.user_data.createdate = data.get("created_at", "")
        self.user_data.lastlogin  = data.get("last_login_at", "")
        subs = data.get("subscriptions", [])
        self.user_data.subscriptions = subs
        if subs:
            self.user_data.expires      = subs[0].get("expiry", "")
            self.user_data.subscription = subs[0].get("subscription", "")
        else:
            self.user_data.expires      = ""
            self.user_data.subscription = ""

    def _parse_ban_info(self, msg: str):
        """Parse ban reason and expiry from backend error messages."""
        self.ban_reason = None
        self.ban_revoke_date = None
        if not msg or ("Account is Banned" not in msg and "License is Banned" not in msg):
            return
            
        import re
        reason_match = re.search(r"Reason:\s*(.+?)(?=\s*\|\s*Expires:|$)", msg)
        expires_match = re.search(r"Expires:\s*(.+?)(?=$)", msg)
        
        if reason_match:
            self.ban_reason = reason_match.group(1).strip()
        if expires_match:
            self.ban_revoke_date = expires_match.group(1).strip()

    def _login_hint(self, msg: str):
        """Print developer-friendly hints based on the error message."""
        if "signature" in msg.lower() or "hmac" in msg.lower():
            logger.critical(
                "\n[ANTI-TAMPER] HMAC verification failed. Possible causes:\n"
                "  1. client_secret is wrong — copy it exactly from the dashboard.\n"
                "  2. System clock is more than 5 minutes off — sync your clock.\n"
            )
        elif "Application not found" in msg:
            logger.critical(
                "\n[SETUP ERROR] ownerid (App ID) is wrong.\n"
                "  Resolution: copy the exact App ID from AuthLX Dashboard → App Info.\n"
            )
        elif "Hardware ID mismatch" in msg:
            logger.critical(
                "\n[USER] HWID changed. Admin must reset HWID in the dashboard.\n"
            )
        elif "Subscription has expired" in msg:
            logger.critical("\n[USER] Subscription expired. Purchase a new license key.\n")
        elif "Application is currently disabled" in msg:
            logger.critical(
                "\n[SETUP ERROR] App is disabled in the dashboard.\n"
                "  Resolution: Dashboard → Select App → Enable.\n"
            )
        elif "Replay" in msg or "nonce" in msg.lower():
            logger.critical(
                "\n[SECURITY] Replay attack blocked. Each request must use a fresh nonce.\n"
                "  This error means someone is trying to re-use a captured packet.\n"
            )

    def _ban_monitor_loop(self, interval: int):
        """Background thread body for the ban monitor."""
        while self._ban_monitor_active:
            time.sleep(interval)
            if not self.session_token:
                continue
            if self._debug:
                logger.debug("Ban monitor: checking session…")
            if not self.check():
                logger.critical("\n[SECURITY] Session revoked or account banned at runtime.")
                time.sleep(1)
                os._exit(1)

    def _verify_pinned_key(self, url: str):
        """Hook point for TLS public-key pinning. Extend as needed."""
        if self._debug:
            logger.debug(f"[PIN] Key pinning check for {url}")

    # ── Auto-Updater ─────────────────────────────────────────────────────────

    @staticmethod
    def _is_frozen() -> bool:
        """Return True when running as a PyInstaller/Nuitka compiled binary."""
        return getattr(sys, 'frozen', False) or hasattr(sys, '_MEIPASS')

    @staticmethod
    def get_current_executable_path() -> str:
        """
        Return the absolute, resolved path of the running script or compiled binary.
        Works on Windows (.exe) and Linux (ELF binary or .py script).
        """
        try:
            # PyInstaller / Nuitka frozen binary
            if api._is_frozen():
                path = os.path.realpath(sys.executable)
                return os.path.abspath(path)
        except Exception:
            pass

        # Plain Python script: use argv[0] which the OS passed to us
        try:
            if sys.argv and sys.argv[0] and sys.argv[0] != "":
                path = os.path.realpath(sys.argv[0])
                return os.path.abspath(path)
        except Exception:
            pass

        return os.path.abspath(os.path.realpath(__file__))

    @staticmethod
    def _wait_file_unlocked(path: str, timeout_secs: float = 10.0):
        """
        Cross-platform wait until a file can be opened exclusively.
        On Linux, executables are never truly locked, so we just
        do a short sleep to let the old process exit gracefully.
        On Windows, we poll with open() until the lock releases.
        """
        if platform.system() == "Windows":
            deadline = time.time() + timeout_secs
            while time.time() < deadline:
                try:
                    # Try to open with exclusive access
                    fd = open(path, "r+b")
                    fd.close()
                    return  # Lock released — safe to rename
                except (IOError, OSError, PermissionError):
                    time.sleep(0.2)
        else:
            # On Linux, files are not locked by the OS even when running;
            # wait for the parent PID to disappear (heuristic: 1.5s sleep)
            time.sleep(1.5)

    @staticmethod
    def handle_update_stage():
        """
        Intercept Stage 2 process handoff (--authlx-update-finish <old_path>).
        Runs ONLY when the newly-downloaded binary is executed with that flag.
        Waits for original process exit, replaces the file, relaunches, then exits.
        Compatible with Windows and Linux for both .py scripts and compiled binaries.
        """
        try:
            if "--authlx-update-finish" not in sys.argv:
                return

            finish_idx = sys.argv.index("--authlx-update-finish")
            if finish_idx + 1 >= len(sys.argv):
                logger.error("[AUTO-UPDATE STAGE 2] Missing target path argument.")
                return

            target_path = os.path.abspath(os.path.realpath(sys.argv[finish_idx + 1]))
            if not target_path or not os.path.exists(target_path):
                logger.error(f"[AUTO-UPDATE STAGE 2] Target not found: {target_path}")
                # Target already gone (overwritten?) — try to just launch it
                if target_path and os.path.exists(target_path):
                    pass
                else:
                    os._exit(0)

            current_path = api.get_current_executable_path()
            if not current_path or not os.path.exists(current_path):
                logger.error("[AUTO-UPDATE STAGE 2] Could not resolve current binary path.")
                return

            logger.info(f"[AUTO-UPDATE STAGE 2] Waiting for original process to release: {target_path}")
            api._wait_file_unlocked(target_path)

            backup_path = target_path + ".old"
            # Clean up any pre-existing backup
            if os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except Exception:
                    pass

            # On Windows, os.rename to an existing path raises; shutil.move handles it.
            # Step 1: old_exe → old_exe.old
            shutil.move(target_path, backup_path)

            # Step 2: new_exe.new → old_exe  (current process IS new_exe.new)
            shutil.move(current_path, target_path)

            # Step 3: On Linux ensure the replacement binary is executable
            if platform.system() != "Windows":
                try:
                    os.chmod(target_path, 0o755)
                except Exception:
                    pass

            # Step 4: Relaunch the (now-replaced) original path
            logger.info(f"[AUTO-UPDATE STAGE 2] Launching updated binary: {target_path}")
            if target_path.lower().endswith(".py"):
                # Script mode — must run through Python interpreter
                subprocess.Popen([sys.executable, target_path],
                                 close_fds=True,
                                 start_new_session=True)
            else:
                # Compiled binary (PyInstaller .exe on Windows, ELF on Linux)
                subprocess.Popen([target_path],
                                 close_fds=True,
                                 start_new_session=True)

            os._exit(0)
        except Exception as e:
            logger.error(f"[AUTO-UPDATE STAGE 2 ERROR] {e}")

    def _download_file_http(self, url: str, target_path: str) -> bool:
        """Download file via requests with streaming, redirect handling, and progress display."""
        if not url or not target_path:
            return False
        try:
            headers = {"User-Agent": f"AuthLX-SDK-Python/1.0 ({self.name} v{self.version})"}
            with self._session.get(url, headers=headers, stream=True,
                                   timeout=30, allow_redirects=True) as r:
                r.raise_for_status()
                total_bytes = int(r.headers.get("Content-Length", 0))
                downloaded  = 0
                last_pct    = -1

                with open(target_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_bytes > 0:
                                pct = int(downloaded * 100 / total_bytes)
                                if pct != last_pct:
                                    bar_filled = pct // 5
                                    bar = "█" * bar_filled + "░" * (20 - bar_filled)
                                    mb_done  = downloaded / (1024 * 1024)
                                    mb_total = total_bytes / (1024 * 1024)
                                    print(f"\r  [{bar}] {pct:3d}%  {mb_done:.1f} / {mb_total:.1f} MB",
                                          end="", flush=True)
                                    last_pct = pct
                            else:
                                mb_done = downloaded / (1024 * 1024)
                                print(f"\r  Downloading... {mb_done:.1f} MB",
                                      end="", flush=True)

                print()  # newline after progress bar
            return os.path.exists(target_path) and os.path.getsize(target_path) > 0
        except Exception as e:
            print()  # newline if progress was mid-line
            logger.error(f"[DOWNLOAD ERROR] Failed to download update: {e}")
            return False

    def check_for_updates(self) -> "UpdateInfo":
        """Check AuthLX backend for available software updates."""
        info = UpdateInfo()
        info.current_version = self.version

        payload = {
            "app_id": self.ownerid,
            "name": self.name,
            "version": self.version,
            "secret": self._client_secret or "NO_SECRET"
        }

        latest_ver = ""
        dl_url = ""
        file_n = ""

        # 1. Query /init — may return auto_update_link and version
        response = self._do_request("/init", payload)
        if response and response.get("status") == "success":
            app_info   = response.get("app_info") or {}
            latest_ver = app_info.get("version", "")
            dl_url     = app_info.get("auto_update_link", "")

        # 2. Query /file/latest — authoritative release info
        file_res = self._do_request("/file/latest", payload)
        if file_res and file_res.get("status") == "success":
            data     = file_res.get("data") or {}
            file_obj = data.get("file") or {}
            if file_obj:
                if not latest_ver:
                    latest_ver = file_obj.get("version_tag", "")
                if not dl_url:
                    dl_url = file_obj.get("download_url", "")
                if not file_n:
                    file_n = file_obj.get("name", "")

        # Fallback: direct download endpoint
        if not dl_url:
            dl_url = f"{self.api_url}/file/latest/download?app_id={self.ownerid}"

        info.latest_version = latest_ver or self.version
        info.download_url   = dl_url
        info.file_name      = file_n

        if info.latest_version and info.latest_version != self.version:
            info.update_available = True

        self.update_info = info
        return info

    def perform_update(self, info: "UpdateInfo") -> bool:
        """
        Download the update binary to <current_exe>.new, then spawn it with
        --authlx-update-finish <current_exe> and exit, triggering Stage 2.
        Works for Windows .exe, Linux ELF binary, and Python scripts.
        """
        if not info or not info.update_available or not info.download_url:
            logger.error("[AUTO-UPDATE] No valid update download URL available.")
            return False

        current_exe = self.get_current_executable_path()
        if not current_exe:
            logger.error("[AUTO-UPDATE] Could not determine current binary path.")
            return False

        new_temp_path = current_exe + ".new"
        logger.info(f"[AUTO-UPDATE] Downloading update from: {info.download_url}")

        if not self._download_file_http(info.download_url, new_temp_path):
            logger.error("[AUTO-UPDATE] Download failed.")
            if os.path.exists(new_temp_path):
                try:
                    os.remove(new_temp_path)
                except Exception:
                    pass
            return False

        # On Linux, make the downloaded binary executable before spawning it
        if platform.system() != "Windows":
            try:
                os.chmod(new_temp_path, 0o755)
            except Exception:
                pass

        logger.info("[AUTO-UPDATE] Download complete. Spawning updater process...")

        try:
            if new_temp_path.lower().endswith(".py"):
                # Script: run through current Python interpreter
                cmd = [sys.executable, new_temp_path,
                       "--authlx-update-finish", current_exe]
            elif self._is_frozen():
                # Compiled binary (PyInstaller/Nuitka) — run directly
                cmd = [new_temp_path, "--authlx-update-finish", current_exe]
            else:
                # Plain Python running a non-.py path (unusual) — use interpreter
                cmd = [sys.executable, new_temp_path,
                       "--authlx-update-finish", current_exe]

            subprocess.Popen(cmd, close_fds=True, start_new_session=True)

            logger.info("[AUTO-UPDATE] Updater spawned. Exiting current process.")
            os._exit(0)
            return True
        except Exception as e:
            logger.error(f"[AUTO-UPDATE] Failed to spawn updater process: {e}")
            if os.path.exists(new_temp_path):
                try:
                    os.remove(new_temp_path)
                except Exception:
                    pass
            return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   others  —  static utility class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class others:
    """
    Static helpers for hardware fingerprinting, hash generation, and anti-debug.

    All methods are static — call them as: ``others.get_hwid()``
    """

    @staticmethod
    def get_checksum() -> str:
        """
        Compute the SHA-256 checksum of the currently running script or
        compiled executable.

        Used by the SDK as the Anti-Tamper hash. In SECURE MODE this hash
        is HMAC-signed with the client_secret and auto-whitelisted by the
        backend on every successful login — no manual dashboard work needed.

        In development the hash is the SHA-256 of the ``.py`` source file.
        In production (after PyInstaller compile) it is the SHA-256 of the ``.exe``.

        Returns
        -------
        str
            Lowercase hex SHA-256 digest, or ``"UNKNOWN_HASH"`` on error.
        """
        try:
            with open(sys.argv[0], "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "UNKNOWN_HASH"

    @staticmethod
    def anti_debug():
        """
        Terminate the process immediately if a Python debugger is attached.

        Checks ``sys.gettrace()`` — any non-``None`` value means a tracer
        (debugger, profiler) is installed.  Called automatically in ``api.init()``.

        For stronger protection combine with PyArmor and a compiled binary.
        """
        if sys.gettrace() is not None:
            logger.critical("Security violation: Debugger detected. Exiting.")
            os._exit(1)

    @staticmethod
    def get_hwid(method: str = "windows_user") -> str:
        """
        Return a stable Hardware ID for the current machine.

        Platform behaviour
        ------------------
        **Windows**
          - ``"windows_user"`` (default): Current user's Security Identifier (SID).
            Stable per Windows user account.  Requires pywin32.
          - Any other value: MachineGuid from Windows Registry (stable per install),
            falls back to ``wmic csproduct get uuid``.

        **Linux**
          Reads ``/etc/machine-id``.

        **macOS**
          Reads ``IOPlatformSerialNumber`` via ioreg.

        Parameters
        ----------
        method : str
            HWID strategy string.  Set by the AuthLX server during ``init()``
            based on what the developer chose in the dashboard.

        Returns
        -------
        str
            Hardware ID string.
        """
        system = platform.system()

        # ── Linux ──────────────────────────────────────────────────────────────
        if system == "Linux":
            try:
                with open("/etc/machine-id") as f:
                    mid = f.read().strip()
                    if mid:
                        return mid
            except Exception:
                pass
            return "Unknown-Linux-HWID"

        # ── Windows ────────────────────────────────────────────────────────────
        if system == "Windows":
            if method == "windows_user":
                # Use current user's SID — stable per Windows account
                try:
                    proc    = win32api.GetCurrentProcess()
                    token   = win32security.OpenProcessToken(proc, win32con.TOKEN_QUERY)
                    sid, _  = win32security.GetTokenInformation(token, win32security.TokenUser)
                    return win32security.ConvertSidToStringSid(sid)
                except Exception:
                    pass
                # Fallback: parse whoami /user output (no pywin32 needed)
                try:
                    out   = subprocess.check_output(
                        ["whoami", "/user", "/fo", "csv", "/nh"],
                        stderr=subprocess.DEVNULL,
                    ).decode(errors="replace").strip()
                    parts = out.replace('"', "").split(",")
                    if len(parts) >= 2:
                        sid = parts[-1].strip()
                        if sid.startswith("S-"):
                            return sid
                except Exception:
                    pass
                return "Unknown-Windows-User-HWID"

            else:
                # Use MachineGuid from Windows Registry — stable per installation
                try:
                    import winreg
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Cryptography",
                    ) as k:
                        guid, _ = winreg.QueryValueEx(k, "MachineGuid")
                        return guid
                except Exception:
                    pass
                # Fallback: wmic
                try:
                    out   = subprocess.check_output(
                        ["wmic", "csproduct", "get", "uuid"],
                        stderr=subprocess.DEVNULL,
                    ).decode(errors="replace")
                    lines = [l.strip() for l in out.splitlines() if l.strip()]
                    if len(lines) >= 2:
                        return lines[1]
                except Exception:
                    pass
                return "Unknown-Windows-Machine-HWID"

        # ── macOS ──────────────────────────────────────────────────────────────
        if system == "Darwin":
            try:
                raw = subprocess.Popen(
                    "ioreg -l | grep IOPlatformSerialNumber",
                    stdout=subprocess.PIPE,
                    shell=True,
                ).communicate()[0]
                return raw.decode(errors="replace").split("=", 1)[1].replace(" ", "").strip().strip('"')
            except Exception:
                pass
            return "Unknown-Mac-HWID"

        return "Unknown-HWID"
