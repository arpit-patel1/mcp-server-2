# MCP Network Manager Examples

This directory contains example clients for the MCP Network Manager.

## Running the Examples

### Server

First, start the server with the SSE transport:

```bash
python -m mcp_network_manager.server --transport sse --inventory devices.csv
```

This will start the server on port 8000 by default.

### Clients

#### Simple Client

The `simple_client.py` file demonstrates a minimal client that connects to the server and lists the available tools:

```bash
python examples/simple_client.py
```

#### SSE Client

The `sse_client.py` file demonstrates how to use the MCP Network Manager with the SSE transport:

```bash
python examples/sse_client.py
```

#### Regular Client

The `client.py` file demonstrates how to use the MCP Network Manager with the stdio transport:

```bash
python examples/client.py
```

## Connecting from External Clients

When connecting from external clients like Langflow, make sure to use the correct endpoint URL:

```
http://your-server-ip:8000/sse
```

For example, if your server is running on the local machine, use:

```
http://localhost:8000/sse
```

Or if connecting from another machine, use the IP address:

```
http://192.168.1.182:8000/sse
```

## Troubleshooting

If you encounter connection errors, check the following:

1. Make sure the server is running with the `--transport sse` option
2. Make sure you're using the correct endpoint URL with `/sse` at the end
3. Check that there are no firewalls blocking the connection
4. Verify that the server IP address is correct and accessible from the client
