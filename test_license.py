import os
import sys
from authlx import api, others

APP_NAME    = "Premium"
APP_ID      = "28ec87e8-ffec-404a-aad3-29ec468c765c"
APP_VERSION = "1.0"
APP_CLIENT_SECRET = "17f4fe6c84806638b455cb309e4ccd6bf5852b6951f6a6c2720d863203d9c53c"

def test():
    authlxapp = api(
        name          = APP_NAME,
        ownerid       = APP_ID,
        version       = APP_VERSION,
        client_secret = APP_CLIENT_SECRET
    )

    print("\\n--- Testing License ---")
    # We can try upgrading the existing test2 user with this license
    print("Testing UPGRADE on 'test2'...")
    if authlxapp.upgrade("test2", "J9ED-6FPE-ZPMP-ZKPK"):
        print("Success! License is valid and applied.")
    else:
        print("Failed to use license. (Might be invalid, expired, or already used)")

test()
