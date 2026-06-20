# AuthLX-Python-Example

A production-ready, fully-featured Python SDK and Example Application for [AuthLX](https://authlx.com). 
This repository demonstrates how to securely integrate AuthLX authentication, license validation, and anti-tamper security into your Python desktop applications.

## 🌟 Features
- **Registration & Login**: Securely authenticate users via License Keys and Username/Passwords.
- **HWID Locking**: Automatically binds user accounts to their physical Hardware ID (Supports Windows, Mac, and Linux).
- **Session Management**: Verifies active sessions directly with the AuthLX backend.
- **Anti-Tamper (App Hash Verification)**: Generates a real-time SHA-256 checksum of the running application to prevent unauthorized modifications.
- **Anti-Debug**: Kills the application if debugging tools (like Python's `sys.gettrace()`) are detected.
- **Anti-MITM**: Disables proxy auto-configuration (bypassing local interception tools like Fiddler/Charles).

## 🚀 Quick Start

### 1. Requirements
Ensure you have the required modules installed:
```bash
pip install -r requirements.txt
```
*(Note: Windows users require `pywin32` for advanced HWID generation).*

### 2. Configuration
Open `main.py` and modify the SDK initialization block with your Application details from your AuthLX Dashboard:

```python
from authlx import api, others

authlxapp = api(
    name="YourAppName", 
    ownerid="YOUR-APP-UUID-HERE",
    version="1.0", 
    hash_to_check=others.get_checksum() # Automatically generates SHA256
)
```

### 3. Run the Example
```bash
python main.py
```
You will be greeted with an interactive console where you can test License Registration, Login, and API Token verification.

## 🛡️ Security Implementation
The `authlx.py` file is highly optimized for production security:
1. **`others.anti_debug()`**: Runs immediately upon initialization. If a debugger is attached, it exits with code 1.
2. **`session.trust_env = False`**: Forces the `requests` library to ignore local proxy environments, protecting against MitM packet sniffing.
3. **`others.get_checksum()`**: Reads `sys.argv[0]`, computes the hash, and sends it to your AuthLX backend during login. If the backend's `hash_check` security setting is enabled, altered apps will be rejected!

## 📜 License
This SDK is provided open-source under the MIT License. Feel free to modify and adapt it to your specific Python projects!
