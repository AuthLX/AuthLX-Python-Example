import os
import sys
import json
import time
import platform
import subprocess
import hashlib
import logging

# Set up SDK Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] AuthLX: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("AuthLX")

try:
    if os.name == 'nt':
        import win32security
    import requests
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        if os.name == 'nt':
            os.system("pip install pywin32")
        os.system("pip install requests")
    logger.info("Modules installed!")
    time.sleep(1.5)
    os._exit(1)


class api:
    name = ""
    ownerid = ""
    version = ""
    hash_to_check = ""
    api_url = ""
    session_token = ""
    
    session = requests.Session()
    # Anti-MITM: Prevents automatic proxy configuration via environment variables (like Fiddler/Charles)
    session.trust_env = False 
    
    initialized = False

    class user_data_class:
        username = ""
        hwid = ""
        expires = ""
        createdate = ""
        lastlogin = ""
        subscription = ""
        subscriptions = []

    user_data = user_data_class()

    def __init__(self, name, ownerid, version, hash_to_check=None, api_url=None):
        self.name = name
        self.ownerid = ownerid
        self.version = version
        self.hash_to_check = hash_to_check if hash_to_check else others.get_checksum()
        
        if api_url:
            self.api_url = api_url
        else:
            self.api_url = "http://127.0.0.1:3000/api/v1/client"
            
        self.init()

    def init(self):
        # Anti-Debug check during initialization
        others.anti_debug()
        self.initialized = True

    def register(self, user, email, password, license_key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "app_id": self.ownerid,
            "username": user,
            "email": email,
            "password": password,
            "license_key": license_key,
            "hwid": hwid
        }

        response = self.__do_request("/register", post_data)

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Successfully registered!"))
            return True
        else:
            msg = response.get("message", "Registration failed.")
            logger.error(f"Registration Failed: {msg}")
            
            if "Application not found" in msg:
                logger.critical(f"\n[SETUP ERROR] The ownerid (App ID) provided in the SDK is incorrect.")
                logger.critical(f"[RESOLUTION] Check your AuthLX Dashboard and copy the exact App ID.\n")
            
            return False

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        post_data = {
            "app_id": self.ownerid,
            "username": user,
            "password": password,
            "hwid": hwid,
            "hash": self.hash_to_check,
            "version": self.version
        }

        response = self.__do_request("/login", post_data)

        if response and response.get("status") == "success":
            data = response.get("data", {})
            self.session_token = data.get("token")
            self.__load_user_data(data.get("user", {}))
            logger.info("Successfully logged in!")
            return True
        else:
            msg = response.get("message", "Login failed.")
            logger.error(f"Login Failed: {msg}")
            
            # --- IMPORTANT SETUP ERROR RESOLUTIONS ---
            if "Application hash invalid or modified" in msg or "Application hash required" in msg:
                logger.critical(f"\n[SETUP ERROR] You enabled 'Hash Check' in AuthLX, but haven't whitelisted this script's hash!")
                logger.critical(f"[RESOLUTION] Go to AuthLX Dashboard -> Your App -> Security -> Add this hash: {self.hash_to_check}\n")
            elif "Application not found" in msg:
                logger.critical(f"\n[SETUP ERROR] The ownerid (App ID) provided in the SDK is incorrect.")
                logger.critical(f"[RESOLUTION] Check your AuthLX Dashboard and copy the exact App ID.\n")
            elif "Hardware ID mismatch" in msg:
                logger.critical(f"\n[USER ERROR] The user's hardware ID has changed.")
                logger.critical(f"[RESOLUTION] The user needs to request an HWID reset from the AuthLX Dashboard.\n")
            elif "Application is currently disabled" in msg:
                logger.critical(f"\n[SETUP ERROR] Your application is disabled.")
                logger.critical(f"[RESOLUTION] Go to AuthLX Dashboard and set your app to Active.\n")
                
            return False

    def check(self):
        """Verifies if the current session token is still valid"""
        self.checkinit()
        if not self.session_token:
            return False

        post_data = {
            "app_id": self.ownerid,
            "token": self.session_token
        }
        
        response = self.__do_request("/verify-session", post_data)

        if response and response.get("status") == "success":
            return True
        else:
            return False

    def verify_token(self, standalone_token):
        """Verifies a standalone API token"""
        self.checkinit()
        post_data = {
            "app_id": self.ownerid,
            "token": standalone_token
        }
        
        response = self.__do_request("/verify-token", post_data)
        
        if response and response.get("status") == "success":
            logger.info("Token is valid!")
            return True
        else:
            logger.error(response.get("message", "Invalid or banned token."))
            return False

    def logout(self):
        self.checkinit()
        if not self.session_token:
            logger.error("Not logged in.")
            return False

        post_data = {
            "app_id": self.ownerid,
            "session_token": self.session_token
        }

        response = self.__do_request("/logout", post_data)

        if response and response.get("status") == "success":
            logger.info(response.get("message", "Successfully logged out!"))
            self.session_token = ""
            return True
        else:
            logger.error(response.get("message", "Logout failed."))
            return False

    def checkinit(self):
        if not self.initialized:
            logger.warning("Initialize first, in order to use the functions")
            time.sleep(3)
            os._exit(1)

    def __do_request(self, endpoint, post_data):
        try:
            # Enforce TLS in production, disable proxy auto-config
            headers = {
                "User-Agent": f"AuthLX-ClientSDK/1.0 ({self.name} v{self.version})",
                "Content-Type": "application/json"
            }
            response = self.session.post(
                f"{self.api_url}{endpoint}", 
                json=post_data, 
                headers=headers, 
                timeout=10
            )
            
            try:
                return response.json()
            except ValueError:
                print(f"Invalid response from server. HTTP {response.status_code}")
                time.sleep(3)
                os._exit(1)

        except requests.exceptions.Timeout:
            print("Request timed out. Server is probably down/slow at the moment")
            time.sleep(3)
            os._exit(1)
        except requests.exceptions.ConnectionError as e:
            print(f"Connection error. Server is unreachable.")
            time.sleep(3)
            os._exit(1)

    def __load_user_data(self, data):
        self.user_data.username = data.get("username", "")
        self.user_data.hwid = data.get("hwid", "N/A")
        
        subscriptions = data.get("subscriptions", [])
        if subscriptions:
            self.user_data.expires = subscriptions[0].get("expiry", "")
            self.user_data.subscription = subscriptions[0].get("subscription", "")
        self.user_data.subscriptions = subscriptions
        self.user_data.createdate = data.get("created_at", "")
        self.user_data.lastlogin = data.get("last_login", "")


class others:
    @staticmethod
    def get_checksum():
        """Generates SHA256 checksum of the current running script/executable"""
        try:
            with open(sys.argv[0], "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return "UNKNOWN_HASH"

    @staticmethod
    def anti_debug():
        """Kills the process if a standard Python debugger is attached"""
        if sys.gettrace() is not None:
            logger.critical("Security violation: Debugger detected.")
            os._exit(1)

    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            try:
                with open("/etc/machine-id") as f:
                    return f.read().strip()
            except:
                return "Unknown-Linux-HWID"
        elif platform.system() == 'Windows':
            try:
                winuser = os.getlogin()
                sid = win32security.LookupAccountName(None, winuser)[0] 
                return win32security.ConvertSidToStringSid(sid)
            except:
                return "Unknown-Windows-HWID"
        elif platform.system() == 'Darwin':
            try:
                output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
                serial = output.decode().split('=', 1)[1].replace(' ', '')
                return serial[1:-2]
            except:
                return "Unknown-Mac-HWID"
        return "Unknown-HWID"
