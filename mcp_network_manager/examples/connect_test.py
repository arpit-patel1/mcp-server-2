#!/usr/bin/env python3
"""Test script for connecting to a device with an encrypted password."""

import asyncio
import json
import sys
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main():
    """Run the test client."""
    # Get device name from command line or use default
    device_name = sys.argv[1] if len(sys.argv) > 1 else "ios_xe_latest"
    
    # Get password from command line or prompt (optional - only needed if you want to override the stored password)
    password = None
    if len(sys.argv) > 2 or input(f"Do you want to override the stored password for {device_name}? (y/n): ").lower() == 'y':
        password = sys.argv[2] if len(sys.argv) > 2 else input(f"Enter password for device {device_name}: ")
    
    # Get secret from command line or prompt (optional - only needed if you want to override the stored secret)
    secret = None
    if len(sys.argv) > 3 or (not password and input(f"Do you want to override the stored secret for {device_name}? (y/n): ").lower() == 'y'):
        secret = sys.argv[3] if len(sys.argv) > 3 else input(f"Enter secret for device {device_name}: ")
    
    print(f"Connecting to device {device_name}...")
    
    async with stdio_client(
        StdioServerParameters(command="python", args=["-m", "mcp_network_manager.server", "--transport", "stdio"])
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List devices to check if our device exists
            print("Listing devices...")
            result = await session.call_tool("mcp_device__list_devices", {})
            print(result[0].text)
            
            # Connect to the device (password will be automatically decrypted if encrypted)
            print(f"\nConnecting to {device_name}...")
            try:
                connect_params = {
                    "device_name": device_name
                }
                
                # Add password and secret if provided (to override stored values)
                if password:
                    connect_params["password"] = password
                if secret:
                    connect_params["secret"] = secret
                    
                result = await session.call_tool("mcp_device__connect", connect_params)
                print(result[0].text)
                
                if "Connected to" in result[0].text:
                    # If connected, try sending a simple command
                    print("\nSending 'show version' command...")
                    command_params = {
                        "device_name": device_name,
                        "command": "show version"
                    }
                    
                    # Add password and secret if provided (to override stored values)
                    if password:
                        command_params["password"] = password
                    if secret:
                        command_params["secret"] = secret
                        
                    result = await session.call_tool("mcp_device__send_command", command_params)
                    print(result[0].text)
                    
                    # Disconnect
                    print("\nDisconnecting...")
                    result = await session.call_tool("mcp_device__disconnect", {"device_name": device_name})
                    print(result[0].text)
            except Exception as e:
                print(f"Error: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 