# MCP Network Manager Server

This directory contains the MCP Network Manager server, which provides tools for managing network devices using Netmiko.

## Starting the Server

The `start_server.sh` script is provided to easily start the server. It will:

1. Check if the specified port is in use (for SSE transport)
2. If it is, attempt to kill the process using it
3. Start the MCP Network Manager server

### Basic Usage

```bash
# Start the server with default settings (SSE transport on port 8000)
./start_server.sh

# Start the server with stdio transport
./start_server.sh --transport stdio

# Start the server on a different port
./start_server.sh --port 8080

# Start the server with a different inventory file
./start_server.sh --inventory my_devices.csv

# Start the server with a different conda environment
./start_server.sh --env my_conda_env
```

### Command-Line Options

The script supports the following command-line options:

- `-p, --port PORT`: Port to use (default: 8000)
- `-i, --inventory FILE`: Inventory file to use (default: devices.csv)
- `-t, --transport TYPE`: Transport type (stdio or sse, default: sse)
- `-e, --env NAME`: Conda environment name (default: mcp-dev-py311)
- `-h, --help`: Display help message

### Examples

Start the server with SSE transport on port 8000:
```bash
./start_server.sh
```

Start the server with stdio transport:
```bash
./start_server.sh --transport stdio
```

Start the server on port 8080:
```bash
./start_server.sh --port 8080
```

Start the server with a custom inventory file:
```bash
./start_server.sh --inventory custom_devices.csv
```

## Stopping the Server

To stop the server, you can press `Ctrl+C` in the terminal where it's running.

Alternatively, you can use the following command to kill the process using the port:
```bash
lsof -i :8000 -t | xargs kill
```

Or for a more forceful termination:
```bash
lsof -i :8000 -t | xargs kill -9
```

## Troubleshooting

If you encounter issues with the server, here are some common solutions:

### Port Already in Use

If you see an error like "Address already in use", it means another process is already using the port. The script will attempt to kill this process, but if it fails, you can manually free up the port:

```bash
# Find the process using port 8000
lsof -i :8000

# Kill the process
kill -9 <PID>
```

### Conda Environment Issues

If you see an error related to the conda environment, make sure the specified environment exists and has all the required packages installed:

```bash
# Create the conda environment
conda create -n mcp-dev-py311 python=3.11

# Activate the environment
conda activate mcp-dev-py311

# Install the required packages
cd mcp_network_manager && pip install -e .
``` 