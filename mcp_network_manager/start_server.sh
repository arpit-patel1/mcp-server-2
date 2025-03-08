#!/bin/bash

# start_server.sh - Script to free up port and start the MCP Network Manager server
# 
# This script:
# 1. Checks if the specified port is in use
# 2. If it is, attempts to kill the process using it
# 3. Starts the MCP Network Manager server with SSE transport
#
# Note: The MCP Network Manager uses a strict tool naming convention with domain-specific prefixes:
# - mcp_device__* for network device management tools
# - mcp_kube__* for Kubernetes management tools
# Old tool names without prefixes or with the generic mcp__ prefix are not supported.

# Default values
PORT=8000
INVENTORY_FILE="devices.csv"
TRANSPORT="sse"
CONDA_ENV="mcp-dev-py311"
LOG_LEVEL="INFO"

# Function to display usage information
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT          Port to use (default: 8000)"
    echo "  -i, --inventory FILE     Inventory file to use (default: devices.csv)"
    echo "  -t, --transport TYPE     Transport type (stdio or sse, default: sse)"
    echo "  -e, --env NAME           Conda environment name (default: mcp-dev-py311)"
    echo "  -l, --log-level LEVEL    Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL, default: INFO)"
    echo "  -h, --help               Display this help message"
    echo ""
    exit 1
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -i|--inventory)
            INVENTORY_FILE="$2"
            shift 2
            ;;
        -t|--transport)
            TRANSPORT="$2"
            shift 2
            ;;
        -e|--env)
            CONDA_ENV="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Validate transport type
if [[ "$TRANSPORT" != "sse" && "$TRANSPORT" != "stdio" ]]; then
    echo "Error: Transport type must be 'sse' or 'stdio'"
    usage
fi

# Validate log level
if [[ "$LOG_LEVEL" != "DEBUG" && "$LOG_LEVEL" != "INFO" && "$LOG_LEVEL" != "WARNING" && "$LOG_LEVEL" != "ERROR" && "$LOG_LEVEL" != "CRITICAL" ]]; then
    echo "Error: Log level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    usage
fi

# Function to check if a port is in use
check_port() {
    lsof -i :$PORT > /dev/null 2>&1
    return $?
}

# Function to kill process using a port
kill_process_on_port() {
    echo "Port $PORT is in use. Attempting to free it up..."
    
    # Get the PID of the process using the port
    PID=$(lsof -i :$PORT -t)
    
    if [ -z "$PID" ]; then
        echo "Could not find PID for process using port $PORT"
        return 1
    fi
    
    echo "Found process with PID $PID using port $PORT"
    
    # Try to kill the process gracefully first
    echo "Attempting to terminate process gracefully..."
    kill $PID
    
    # Wait a moment to see if it worked
    sleep 2
    
    # Check if the port is still in use
    if check_port; then
        echo "Process still running. Attempting to force kill..."
        kill -9 $PID
        sleep 1
    fi
    
    # Final check
    if check_port; then
        echo "Failed to free up port $PORT"
        return 1
    else
        echo "Successfully freed up port $PORT"
        return 0
    fi
}

# Check if conda is available
if ! command -v conda &> /dev/null; then
    echo "Error: conda is not installed or not in PATH"
    exit 1
fi

# Check if conda environment is active
if [[ "$CONDA_DEFAULT_ENV" != "$CONDA_ENV" ]]; then
    echo "Activating conda environment: $CONDA_ENV"
    # Source the conda.sh script to enable conda command in the script
    source "$(conda info --base)/etc/profile.d/conda.sh"
    conda activate $CONDA_ENV
    
    # Check if activation was successful
    if [[ $? -ne 0 || "$CONDA_DEFAULT_ENV" != "$CONDA_ENV" ]]; then
        echo "Error: Failed to activate conda environment $CONDA_ENV"
        echo "Please activate it manually with: conda activate $CONDA_ENV"
        exit 1
    fi
fi

echo "Using conda environment: $CONDA_DEFAULT_ENV"

# Check if inventory file exists
if [[ ! -f "$INVENTORY_FILE" ]]; then
    echo "Warning: Inventory file '$INVENTORY_FILE' not found"
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Exiting..."
        exit 1
    fi
fi

# Only check port if using SSE transport
if [[ "$TRANSPORT" == "sse" ]]; then
    # Check if port is in use
    if check_port; then
        # Try to kill the process
        if ! kill_process_on_port; then
            echo "Could not free up port $PORT. Please check manually."
            exit 1
        fi
    fi
    
    echo "Port $PORT is free. Starting MCP Network Manager server with SSE transport..."
    
    # Start the server with SSE transport
    python -m mcp_network_manager.server --transport $TRANSPORT --port $PORT --inventory $INVENTORY_FILE --log-level $LOG_LEVEL
else
    echo "Starting MCP Network Manager server with stdio transport..."
    
    # Start the server with stdio transport
    python -m mcp_network_manager.server --transport $TRANSPORT --inventory $INVENTORY_FILE --log-level $LOG_LEVEL
fi

# Exit with the same status as the server
exit $? 