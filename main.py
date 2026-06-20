import os
import time
from authlx import api, others

# ========================================================
# AuthLX Python Example
# Author: Night Warden
# ========================================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    clear_screen()
    print("=" * 50)
    print("  Welcome to the AuthLX Example Application")
    print("=" * 50)
    print("Initializing Security Modules...")
    
    # 1. Initialize the API
    authlxapp = api(
        name="Premium", 
        ownerid="28ec87e8-ffec-404a-aad3-29ec468c765c",
        version="1.0", 
        hash_to_check=others.get_checksum()
    )
    
    print("[+] API Initialized.")
    print(f"[+] Security Hash: {authlxapp.hash_to_check}")
    print(f"[+] Hardware ID: {others.get_hwid()}")
    print("-" * 50)
    
    while True:
        print("\n[1] Login")
        print("[2] Register with License")
        print("[3] Verify Standalone Token")
        print("[4] Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            user = input("Username: ")
            password = input("Password: ")
            
            if authlxapp.login(user, password):
                print(f"\nWelcome back, {authlxapp.user_data.username}!")
                print(f"Subscription: {authlxapp.user_data.subscription}")
                print(f"Expires: {authlxapp.user_data.expires}")
                
                # Verify Session Test
                print("\n[+] Verifying Session token internally...")
                if authlxapp.check():
                    print("[+] Session is completely valid!")
                
                input("\nPress Enter to logout and return to menu...")
                authlxapp.logout()
                
        elif choice == "2":
            user = input("Username: ")
            email = input("Email: ")
            password = input("Password: ")
            license_key = input("License Key: ")
            
            authlxapp.register(user, email, password, license_key)
            
        elif choice == "3":
            token = input("Enter API Token: ")
            authlxapp.verify_token(token)
            
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
