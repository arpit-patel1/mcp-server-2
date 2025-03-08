"""Example client for the MCP Network Manager."""

import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client


async def main():
    """Run the example client."""
    # Connect to the server using stdio transport
    async with stdio_client(
        ["python", "-m", "mcp_network_manager.server", "--inventory", "devices.csv"]
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools:
                print(f"- {tool['name']}: {tool['description']}")
            print()

            # List devices
            print("Listing devices...")
            result = await session.call_tool("list_devices", {})
            print(result[0].text)
            print()

            # List device types
            print("Listing device types...")
            result = await session.call_tool("list_device_types", {})
            device_types = json.loads(result[0].text)
            print(device_types)
            print()

            # List prompts for a device type
            print("Listing prompts for cisco_ios...")
            result = await session.call_tool("list_prompts", {"device_type": "cisco_ios"})
            print(result[0].text)
            print()

            # Try to connect to a device (this might fail if the device is not reachable)
            print("Trying to connect to ios_xe1...")
            try:
                result = await session.call_tool("connect", {"device_name": "ios_xe1"})
                print(result[0].text)
                
                # If connection is successful, try sending a command
                if "Connected" in result[0].text:
                    print("\nSending command 'show version' to ios_xe1...")
                    try:
                        result = await session.call_tool(
                            "send_command", 
                            {"device_name": "ios_xe1", "command": "show version"}
                        )
                        print(result[0].text)
                    except Exception as e:
                        print(f"Error sending command: {e}")
                    
                    # Disconnect from the device
                    print("\nDisconnecting from ios_xe1...")
                    try:
                        result = await session.call_tool("disconnect", {"device_name": "ios_xe1"})
                        print(result[0].text)
                    except Exception as e:
                        print(f"Error disconnecting: {e}")
            except Exception as e:
                print(f"Error connecting: {e}")


if __name__ == "__main__":
    asyncio.run(main()) 