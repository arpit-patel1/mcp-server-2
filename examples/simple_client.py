"""Simple client for the MCP Network Manager."""

import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client


async def main():
    """Run the simple client."""
    # Connect to the server using SSE transport
    async with sse_client(
        "http://localhost:8000/sse"
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print("Available tools:")
            for tool in tools:
                print(f"- {tool.name}: {tool.description}")


if __name__ == "__main__":
    asyncio.run(main()) 