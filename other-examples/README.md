# AuthLX Python SDK – Other Examples

These files show three different ways to integrate the AuthLX Python SDK into
your own application.  All three use the same `api` and `others` classes from
`authlx.py`; they differ only in *how* your application code is structured
relative to the authentication gate.

---

## Files

### `merged_example.py`

A single self-contained script that bundles the entire SDK and the example
application into **one file**.  Useful if you want zero file-management
overhead — just open this file, set your `APP_ID`, and add your code.

### `method1.py` ✅ Recommended

**Your code sits below the login call.**

The login gate is the very first thing that runs.  Your protected logic lives
inside `run_app()`, which is only called when `login()` returns `True`.
There is no way to reach your code without passing authentication.

```
main()
  └─ login()  ─── ✓ success ──→  run_app()   ← your code here
               └─ ✗ fail   ──→  "Login failed."
```

### `method2.py` ⚠ Use with caution

**Your functions are defined above `main()`, then called after login.**

Useful if you need to define functions at module scope before the `api`
object is created.  Since the functions are technically callable from anywhere,
**always call `authlxapp.check()` at the top of every protected function** to
re-verify the session.

```
def protected_feature(authlxapp):
    if not authlxapp.check():   # ← always include this guard
        return
    ...                         ← your code here

main()
  └─ login()  ─── ✓ success ──→  protected_feature(authlxapp)
               └─ ✗ fail   ──→  "Login failed."
```

---

## Which method should I use?

| Factor                          | Method 1       | Method 2           |
|---------------------------------|----------------|--------------------|
| Simplicity                      | ✅ Simpler      | Moderate           |
| Security (tamper resistance)    | ✅ Stronger     | Requires `check()` |
| Functions defined before `api`  | Not needed     | ✅ Supported        |
| Recommended for most projects   | ✅ Yes          | Special cases only |

---

*Docs / Source: https://github.com/AuthLX/AuthLX-Python-Example*
