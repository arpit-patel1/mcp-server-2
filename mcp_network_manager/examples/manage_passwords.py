#!/usr/bin/env python3
"""Script to manage device passwords in the MCP Network Manager inventory."""

import os
import sys
import csv
import pandas as pd
from dotenv import load_dotenv

# Add the parent directory to the path so we can import the security_utils module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mcp_network_manager.security_utils import encrypt_password, decrypt_password, is_password_encrypted, get_master_key

# Load environment variables from .env file
load_dotenv()

def list_devices(inventory_file):
    """List all devices in the inventory.
    
    Args:
        inventory_file: Path to the inventory file.
        
    Returns:
        List of devices.
    """
    if not os.path.exists(inventory_file):
        print(f"Inventory file {inventory_file} does not exist.")
        return []
        
    try:
        df = pd.read_csv(inventory_file)
        devices = []
        
        for _, row in df.iterrows():
            device = {
                "device_name": row["device_name"],
                "device_type": row["device_type"],
                "ip_address": row["ip_address"],
                "username": row["username"],
                "password_encrypted": is_password_encrypted(row["password"]),
                "has_secret": not pd.isna(row["secret"]) and row["secret"] != "",
                "secret_encrypted": not pd.isna(row["secret"]) and row["secret"] != "" and is_password_encrypted(row["secret"])
            }
            devices.append(device)
            
        return devices
    except Exception as e:
        print(f"Error reading inventory file: {e}")
        return []

def encrypt_device_password(inventory_file, device_name, password=None, secret=None):
    """Encrypt the password for a device in the inventory.
    
    Args:
        inventory_file: Path to the inventory file.
        device_name: Name of the device.
        password: Password to encrypt. If None, the user will be prompted.
        secret: Secret to encrypt. If None, the user will be prompted if the device has a secret.
        
    Returns:
        True if successful, False otherwise.
    """
    if not os.path.exists(inventory_file):
        print(f"Inventory file {inventory_file} does not exist.")
        return False
        
    try:
        df = pd.read_csv(inventory_file)
        
        # Find the device
        device_row = df[df["device_name"] == device_name]
        if len(device_row) == 0:
            print(f"Device {device_name} not found in inventory.")
            return False
            
        # Get the current row index
        row_idx = device_row.index[0]
        
        # Check if password is already encrypted
        current_password = device_row.iloc[0]["password"]
        if is_password_encrypted(current_password):
            if not password:
                verify = input(f"Password for {device_name} is already encrypted. Do you want to replace it? (y/n): ")
                if verify.lower() != "y":
                    print("Password not changed.")
                else:
                    password = input(f"Enter new password for {device_name}: ")
                    df.at[row_idx, "password"] = encrypt_password(password)
                    print(f"Password for {device_name} has been encrypted.")
            else:
                df.at[row_idx, "password"] = encrypt_password(password)
                print(f"Password for {device_name} has been encrypted.")
        else:
            if not password:
                password = current_password
                verify = input(f"Do you want to encrypt the current password for {device_name}? (y/n): ")
                if verify.lower() != "y":
                    password = input(f"Enter new password for {device_name}: ")
            
            df.at[row_idx, "password"] = encrypt_password(password)
            print(f"Password for {device_name} has been encrypted.")
        
        # Check if device has a secret
        if not pd.isna(device_row.iloc[0]["secret"]) and device_row.iloc[0]["secret"] != "":
            current_secret = device_row.iloc[0]["secret"]
            if is_password_encrypted(current_secret):
                if not secret:
                    verify = input(f"Secret for {device_name} is already encrypted. Do you want to replace it? (y/n): ")
                    if verify.lower() != "y":
                        print("Secret not changed.")
                    else:
                        secret = input(f"Enter new secret for {device_name}: ")
                        df.at[row_idx, "secret"] = encrypt_password(secret)
                        print(f"Secret for {device_name} has been encrypted.")
                else:
                    df.at[row_idx, "secret"] = encrypt_password(secret)
                    print(f"Secret for {device_name} has been encrypted.")
            else:
                if not secret:
                    secret = current_secret
                    verify = input(f"Do you want to encrypt the current secret for {device_name}? (y/n): ")
                    if verify.lower() != "y":
                        secret = input(f"Enter new secret for {device_name}: ")
                
                df.at[row_idx, "secret"] = encrypt_password(secret)
                print(f"Secret for {device_name} has been encrypted.")
        
        # Save the inventory file
        df.to_csv(inventory_file, index=False)
        return True
    except Exception as e:
        print(f"Error encrypting password: {e}")
        return False

def decrypt_device_password(inventory_file, device_name):
    """Decrypt the password for a device in the inventory.
    
    Args:
        inventory_file: Path to the inventory file.
        device_name: Name of the device.
        
    Returns:
        True if successful, False otherwise.
    """
    if not os.path.exists(inventory_file):
        print(f"Inventory file {inventory_file} does not exist.")
        return False
        
    try:
        df = pd.read_csv(inventory_file)
        
        # Find the device
        device_row = df[df["device_name"] == device_name]
        if len(device_row) == 0:
            print(f"Device {device_name} not found in inventory.")
            return False
            
        # Check if password is encrypted
        current_password = device_row.iloc[0]["password"]
        if not is_password_encrypted(current_password):
            print(f"Password for {device_name} is not encrypted.")
            return False
            
        # Decrypt the password
        try:
            decrypted_password = decrypt_password(current_password)
            print(f"Decrypted password for {device_name}: {decrypted_password}")
        except Exception as e:
            print(f"Error decrypting password: {e}")
            return False
        
        # Check if device has a secret
        if not pd.isna(device_row.iloc[0]["secret"]) and device_row.iloc[0]["secret"] != "":
            current_secret = device_row.iloc[0]["secret"]
            if not is_password_encrypted(current_secret):
                print(f"Secret for {device_name} is not encrypted.")
                return True  # Continue since password was decrypted
                
            # Decrypt the secret
            verify = input(f"Do you want to decrypt the secret for {device_name}? (y/n): ")
            if verify.lower() != "y":
                return True  # Skip secret decryption
                
            try:
                decrypted_secret = decrypt_password(current_secret)
                print(f"Decrypted secret for {device_name}: {decrypted_secret}")
            except Exception as e:
                print(f"Error decrypting secret: {e}")
                return False
        
        return True
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return False

def main():
    """Run the password management script."""
    # Ensure the master key is initialized
    get_master_key()
    
    # Get the inventory file from the command line or use default
    inventory_file = sys.argv[1] if len(sys.argv) > 1 else "devices.csv"
    
    while True:
        print("\nMCP Network Manager Password Management")
        print("=======================================")
        print("1. List devices")
        print("2. Encrypt a device password")
        print("3. Decrypt a device password")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ")
        
        if choice == "1":
            devices = list_devices(inventory_file)
            if devices:
                print("\nDevices in inventory:")
                print("=====================")
                for device in devices:
                    password_status = "Encrypted" if device["password_encrypted"] else "Plain text"
                    secret_status = "None"
                    if device["has_secret"]:
                        secret_status = "Encrypted" if device["secret_encrypted"] else "Plain text"
                    
                    print(f"{device['device_name']} ({device['device_type']}) - {device['ip_address']} - Password: {password_status}, Secret: {secret_status}")
        elif choice == "2":
            device_name = input("Enter device name: ")
            encrypt_device_password(inventory_file, device_name)
        elif choice == "3":
            device_name = input("Enter device name: ")
            decrypt_device_password(inventory_file, device_name)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 