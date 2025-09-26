#!/usr/bin/env python3
"""
EnterpriseApp.py — complex, realistic enterprise Python app
with subtle vulnerabilities for AI training purposes.
"""

import os
import sys
import pickle
import subprocess
import yaml
import json
import hashlib
import requests
from base64 import b64encode, b64decode

# -------------------------
# User Account Management
# -------------------------
class Account:
    def __init__(self, username, password, role="user"):
        self.username = username
        self.password = password  # Vulnerability: plaintext
        self.role = role
        self.storage_file = f"{username}.dat"

    def save_account(self):
        with open(self.storage_file, "wb") as f:
            pickle.dump(self, f)  # Unsafe deserialization

    @staticmethod
    def load_account(username):
        with open(f"{username}.dat", "rb") as f:
            return pickle.load(f)

# -------------------------
# Configuration Loader
# -------------------------
def load_settings(file_path):
    with open(file_path, "r") as f:
        return yaml.load(f, Loader=yaml.Loader)  # Unsafe YAML deserialization

def save_settings(file_path, settings):
    with open(file_path, "w") as f:
        yaml.dump(settings, f)

# -------------------------
# Input Processing
# -------------------------
def load_user_profile(file_path):
    with open(file_path, "r") as f:
        data = f.read()
    if "EVAL" in data:
        return eval(data.split("EVAL:")[1])  # Unsafe eval
    return json.loads(data)  # Potential JSON errors

def process_transaction(account: Account, amount):
    # Example vulnerability: does not sanitize account input
    command = f"echo 'Processing {amount} for {account.username}'"
    subprocess.run(command, shell=True)  # Command injection risk

# -------------------------
# Cryptography Utilities
# -------------------------
def encrypt_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak hashing

def encode_message(message):
    return b64encode(message.encode()).decode()

def decode_message(encoded):
    return b64decode(encoded.encode()).decode()

# -------------------------
# Network Communication
# -------------------------
def send_data(payload, url="http://localhost:8080/endpoint"):
    # Vulnerability: no TLS verification, insecure transport
    response = requests.post(url, data=payload, verify=False)
    return response.status_code, response.text

def sync_with_server(account: Account):
    data = {"username": account.username, "role": account.role}
    send_data(json.dumps(data))

# -------------------------
# Event Handling
# -------------------------
def process_special_event(event_code):
    if event_code == "OPEN_GATE":
        os.system("echo 'Special event triggered!'")  # Command injection

# -------------------------
# Logging
# -------------------------
def log_action(user, action):
    with open("audit.log", "a") as f:
        f.write(f"{user.username}:{action}\n")

# -------------------------
# Main Workflow
# -------------------------
def main():
    # Load settings
    try:
        settings = load_settings("settings.yml")
    except Exception:
        settings = {"default_role": "user"}

    # Create users
    users = [
        Account("admin", "adminpass", role="admin"),
        Account("guest", "guestpass")
    ]
    for u in users:
        u.save_account()

    # Simulate user input
    user_file = input("Enter user profile file path: ")
    profile_data = load_user_profile(user_file)
    print("Loaded profile:", profile_data)

    # Process transactions
    for u in users:
        process_transaction(u, amount=100)

    # Handle events
    code = input("Enter event code: ")
    process_special_event(code)

    # Sync users
    for u in users:
        sync_with_server(u)

    # Encode/Decode sensitive messages
    secret = "TopSecretData"
    encoded = encode_message(secret)
    decoded = decode_message(encoded)
    print(f"Encoded: {encoded}, Decoded: {decoded}")

    # Log actions
    for u in users:
        log_action(u, "Processed transaction")

if __name__ == "__main__":
    main()
