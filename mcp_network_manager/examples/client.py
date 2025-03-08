"""Example client for the MCP Network Manager."""

import asyncio
import json
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main():
    """Run the example client."""
    async with stdio_client(
        StdioServerParameters(command="mcp-network-manager", args=["--inventory", "devices.csv"])
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools:
                print(f"- {tool.name}: {tool.description}")
            print()

            # List devices
            print("Listing devices...")
            result = await session.call_tool("list_devices", {})
            print(result[0].text)
            print()

            # Add a device
            print("Adding a device...")
            try:
                result = await session.call_tool(
                    "add_device",
                    {
                        "device_type": "cisco_ios",
                        "device_name": "test_device",
                        "ip_address": "192.168.1.1",
                        "username": "admin",
                        "password": "password",
                        "ssh_port": 22,
                    },
                )
                print(result[0].text)
            except Exception as e:
                print(f"Error: {e}")
            print()

            # List devices again
            print("Listing devices again...")
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

            # Get a prompt
            print("Getting the show_version prompt for cisco_ios...")
            result = await session.call_tool(
                "get_prompt", {"device_type": "cisco_ios", "prompt_name": "show_version"}
            )
            print(result[0].text)
            print()

            # Connect to a device
            print("Connecting to test_device...")
            try:
                result = await session.call_tool("connect", {"device_name": "test_device"})
                print(result[0].text)
            except Exception as e:
                print(f"Error: {e}")
            print()

            # Check connection
            print("Checking connection to test_device...")
            try:
                result = await session.call_tool("check_connection", {"device_name": "test_device"})
                print(result[0].text)
            except Exception as e:
                print(f"Error: {e}")
            print()

            # Remove the device
            print("Removing test_device...")
            try:
                result = await session.call_tool("remove_device", {"device_name": "test_device"})
                print(result[0].text)
            except Exception as e:
                print(f"Error: {e}")
            print()

            # List devices one more time
            print("Listing devices one more time...")
            result = await session.call_tool("list_devices", {})
            print(result[0].text)
            print()


if __name__ == "__main__":
    asyncio.run(main()) 