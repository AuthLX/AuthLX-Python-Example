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
  • If signature is valid, the hash is AUTO-WHITELISTED — no manual
    dashboard work needed, even after every new build.
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
  Step 4: No manual hash whitelisting ever — the HMAC auto-registers it.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import time
import hmac
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
#   api  —  main SDK class
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
          • Hashes are auto-whitelisted — no dashboard work after each build.
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
                auto_update = app_info.get("auto_update_link")
                webloader   = app_info.get("webloader_link")
                if auto_update:
                    logger.critical(f"  Download: {auto_update}")
                if webloader:
                    logger.critical(f"  Webloader: {webloader}")
                time.sleep(5)
                os._exit(1)

            self.initialized = True
            self.hwid_method = app_info.get("hwid_method", "windows_user")

            mode = "SECURE (HMAC + auto-whitelist)" if self._client_secret else "OFF (no hash protection)"
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
          • The hash is auto-whitelisted → no manual dashboard work needed.

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
