#!/usr/bin/env python3
"""Script to migrate hashed passwords to encrypted passwords in the MCP Network Manager inventory."""

import os
import sys
import pandas as pd
from dotenv import load_dotenv

# Add the parent directory to the path so we can import the security_utils module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mcp_network_manager.security_utils import encrypt_password, is_password_encrypted

# Load environment variables from .env file
load_dotenv()

def migrate_passwords(inventory_file):
    """Migrate hashed passwords to encrypted passwords in the inventory file.
    
    Args:
        inventory_file: Path to the inventory file.
        
    Returns:
        int: Number of passwords migrated.
    """
    if not os.path.exists(inventory_file):
        print(f"Inventory file {inventory_file} does not exist.")
        return 0
        
    try:
        df = pd.read_csv(inventory_file)
        migrated_count = 0
        
        # Check each row for passwords that start with "bcrypt:" but not with the encrypted prefix
        for idx, row in df.iterrows():
            # Check password
            if isinstance(row["password"], str) and row["password"].startswith("bcrypt:") and not is_password_encrypted(row["password"]):
                print(f"Cannot automatically migrate hashed password for {row['device_name']}. You need to provide the actual password.")
                password = input(f"Enter the actual password for {row['device_name']}: ")
                if password:
                    df.at[idx, "password"] = encrypt_password(password)
                    migrated_count += 1
                    print(f"Password for {row['device_name']} has been encrypted.")
                else:
                    print(f"No password provided. Skipping {row['device_name']}.")
            
            # Check secret if it exists
            if "secret" in row and isinstance(row["secret"], str) and row["secret"].startswith("bcrypt:") and not is_password_encrypted(row["secret"]):
                print(f"Cannot automatically migrate hashed secret for {row['device_name']}. You need to provide the actual secret.")
                secret = input(f"Enter the actual secret for {row['device_name']}: ")
                if secret:
                    df.at[idx, "secret"] = encrypt_password(secret)
                    migrated_count += 1
                    print(f"Secret for {row['device_name']} has been encrypted.")
                else:
                    print(f"No secret provided. Skipping secret for {row['device_name']}.")
        
        # Save the inventory file if any passwords were migrated
        if migrated_count > 0:
            df.to_csv(inventory_file, index=False)
            print(f"\nMigrated {migrated_count} passwords/secrets in {inventory_file}.")
        else:
            print(f"\nNo passwords or secrets needed migration in {inventory_file}.")
            
        return migrated_count
    except Exception as e:
        print(f"Error migrating passwords: {e}")
        return 0

def main():
    """Run the password migration script."""
    print("MCP Network Manager Password Migration Tool")
    print("==========================================")
    print("This tool will migrate hashed passwords (bcrypt) to encrypted passwords (Fernet).")
    print("You will need to provide the actual passwords for any hashed passwords found.")
    print()
    
    # Get the inventory file from the command line or use default
    inventory_file = sys.argv[1] if len(sys.argv) > 1 else "devices.csv"
    
    # Migrate passwords
    migrate_passwords(inventory_file)
    
    print("\nMigration complete. You can now use the encrypted passwords with the MCP Network Manager.")
    print("The encrypted passwords can be automatically decrypted when connecting to devices.")

if __name__ == "__main__":
    main() 