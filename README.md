# AuthLX-Python-Example

A production-ready Python SDK and example application for [AuthLX](https://authlx.com) —
the authentication and license management platform for desktop software.

This repository shows how to securely integrate AuthLX into any Python application,
with a full suite of runtime security features built in.

---

## 🌟 Features

### Authentication
| Feature | Description |
|---|---|
| `register()` | Register a new user by activating a license key |
| `login()` | Authenticate with username, password, and HWID |
| `web_login()` | Authenticate without HWID (web/admin panels) |
| `logout()` | Invalidate the session on the backend |
| `check()` | Verify whether the current session is still active |
| `verify_token()` | Validate a standalone API token |

### Account Management
| Feature | Description |
|---|---|
| `changeUsername()` | Rename the currently logged-in user |
| `forgot()` | HWID-verified password reset |
| `upgrade()` | Apply a second license key to extend a subscription |

### Subscription Helpers
| Feature | Description |
|---|---|
| `has_active_subscription()` | Returns `True` if the subscription has not expired |
| `expiry_remaining()` | Seconds remaining until the subscription expires |
| `mark_authenticated()` | Flags the user as authenticated and records runtime start |
| `refresh_auth_runtime()` | Resets the authentication runtime timestamp |

### Security
| Feature | Description |
|---|---|
| **HWID Locking** | Binds accounts to a physical hardware ID (Windows, macOS, Linux) |
| **Anti-Tamper** | SHA-256 checksum of the running script sent to the backend on login |
| **Anti-Debug** | Kills the process if a Python debugger (`sys.gettrace()`) is detected |
| **Anti-MITM** | `session.trust_env = False` disables proxy auto-configuration |
| **Host Locking** | Blocks all HTTP requests to non-whitelisted domains |
| **Public-Key Pinning** | Hook point for TLS certificate pin verification |
| **Payload Cryptography** | HMAC-SHA256 seal + XOR field encryption helpers |
| **Hardened `req()`** | Custom HTTP wrapper that enforces host-locking and key-pinning |

### Rate Limiting & Lockouts
| Feature | Description |
|---|---|
| `record_login_fail()` | Increments the failure counter |
| `lockout_active()` | Returns `True` when a 5-minute lockout is in effect |
| `lockout_remaining_ms()` | Milliseconds left in the current lockout |
| `reset_lockout()` | Clears the failure counter and lockout |
| `bad_input_delay()` | 2-second delay injected after each failed login attempt |

### Ban Monitor
| Feature | Description |
|---|---|
| `start_ban_monitor()` | Starts a background thread that polls session validity |
| `stop_ban_monitor()` | Stops the ban monitor thread |
| `ban_monitor_running()` | Returns `True` if the monitor thread is alive |

---

## 🚀 Quick Start

### 1. Requirements

```bash
pip install -r requirements.txt
```

> **Windows users** also need `pywin32` for advanced HWID generation.

### 2. Configure

Open `main.py` and set your application details:

```python
APP_NAME    = "MyApp"
APP_ID      = "YOUR-APP-UUID-HERE"   # from your AuthLX Dashboard
APP_VERSION = "1.0"
APP_HASH    = others.get_checksum()  # auto-computed SHA-256
```

### 3. Run

```bash
python main.py
```

You will see an interactive console where you can test every SDK feature.

---

## 📁 Project Structure

```
AuthLX-Python-Example/
├── authlx.py          ← The SDK (import this in your own projects)
├── main.py            ← Interactive example demonstrating all features
├── requirements.txt   ← Python dependencies
└── other-examples/
    ├── merged_example.py  ← SDK + example in one standalone file
    ├── method1.py         ← Recommended: your code below the login gate
    ├── method2.py         ← Alternative: functions defined above main()
    └── README.md          ← Explanation of each integration pattern
```

---

## 🛡️ Security Notes

1. **Anti-Debug** (`others.anti_debug()`) — called automatically during `api.__init__()`. Exits immediately if a debugger is attached.

2. **Anti-MITM** (`session.trust_env = False`) — forces the `requests` library to ignore local proxy environments (Fiddler, Charles, Burp Suite, etc.).

3. **Anti-Tamper** (`others.get_checksum()`) — computes a real-time SHA-256 of `sys.argv[0]` and sends it to the backend on every `login()` call.  Enable *Hash Check* in your AuthLX Dashboard to reject modified executables automatically.

4. **HWID Locking** — each `login()` call sends the machine's Hardware ID. If it doesn't match the one on file, the backend rejects the request with a clear error message directing the user to request an HWID reset.

5. **Ban Monitor** — call `start_ban_monitor()` after login to run a background daemon that periodically calls `check()`.  If the session is revoked (e.g. by an admin ban), the process exits immediately via `os._exit(1)`.

6. **Host Locking** — call `set_allowed_hosts(["api.authlx.com"])` to restrict all HTTP requests made through the SDK to approved domains only.

---

## 📜 License

This SDK is provided open-source under the [MIT License](LICENSE).
Feel free to modify and adapt it for your own Python projects.
