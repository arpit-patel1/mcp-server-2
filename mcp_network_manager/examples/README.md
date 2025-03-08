# MCP Network Manager Examples

This directory contains examples of how to use the MCP Network Manager.

## Python Client

The `client.py` file demonstrates how to use the MCP Network Manager with the stdio transport:

```bash
# Make sure the MCP Network Manager is installed
cd ..
pip install -e .

# Run the example
python examples/client.py
```

## SSE Client

The `sse_client.py` file demonstrates how to use the MCP Network Manager with the SSE transport:

```bash
# Start the MCP Network Manager server with SSE transport
python -m mcp_network_manager.server --transport sse --port 8000 --inventory devices.csv

# In another terminal, run the example
python examples/sse_client.py
```

## Web Client

The `web_client.html` file demonstrates how to use the MCP Network Manager with a web interface:

```bash
# Start the MCP Network Manager server with SSE transport
python -m mcp_network_manager.server --transport sse --port 8000 --inventory devices.csv

# Open the web client in a browser
open examples/web_client.html
```

## Robust Client Example

The `robust_client.py` script demonstrates a robust client implementation that handles session initialization race conditions and other connection issues.

### Features

- **Connection Stabilization**: Adds a delay after connection to allow session initialization to complete
- **Retry Logic**: Automatically retries operations that fail due to session initialization issues
- **Error Handling**: Properly handles and logs various error conditions
- **Connection Verification**: Verifies that the connection is working before proceeding
- **Jittered Retries**: Uses randomized delays between retries to prevent thundering herd problems

### Usage

```bash
# Make sure the MCP Network Manager server is running
./mcp_network_manager/start_server.sh

# In another terminal, run the robust client
python mcp_network_manager/examples/robust_client.py
```

### Configuration Options

The `RobustMcpClient` class accepts several configuration options:

- `server_url`: URL of the MCP server (default: "http://localhost:8000")
- `max_retries`: Maximum number of retries for operations (default: 5)
- `retry_delay`: Base delay between retries in seconds (default: 0.5)
- `connection_stabilization_delay`: Delay after connection to allow session initialization (default: 0.2)
- `session_init_timeout`: Timeout for session initialization in seconds (default: 5.0)

### Handling Session Initialization Race Conditions

The client specifically handles the "Received request before initialization was complete" error by:

1. Adding a delay after connection to allow session initialization to complete
2. Implementing retry logic for operations that fail due to session initialization issues
3. Verifying the connection is ready before proceeding with operations

### Example Code

Here's a simple example of using the robust client:

```python
from mcp_network_manager.examples.robust_client import RobustMcpClient
import asyncio

async def main():
    client = RobustMcpClient()
    
    try:
        # Connect to the server
        await client.connect()
        
        # List devices
        devices = await client.list_devices()
        print(f"Found {len(devices)} devices")
        
        # Custom request with retry logic
        result = await client.send_request("custom.method", {"param": "value"})
        print(result)
        
    finally:
        # Always disconnect
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

## Kubernetes Connection Fix

The Kubernetes manager has been updated to properly handle the case when neither `kubeconfig_path` nor `api_server` is provided. It now correctly loads the default kubeconfig from `~/.kube/config` in this case.

This fixes the issue where the Kubernetes manager was trying to connect to `localhost:80` instead of the Kubernetes API server at the correct address.

## Notes

- The examples assume that the MCP Network Manager server is running on localhost:8000.
- The examples use the devices.csv file in the root directory of the project.
- The web client requires a modern browser with support for Server-Sent Events (SSE).
- The connections to real devices might fail if the devices are not reachable or if the credentials are incorrect. 